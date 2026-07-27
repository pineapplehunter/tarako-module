// tarako-app — userspace client for the tarako kernel module.
//
// Opens /dev/tarako and issues three ioctls in sequence:
//   1. TARAKO_HELLO       — sanity check
//   2. TARAKO_GET_PUBKEY  — retrieve the raw ECDSA P-256 public key (65 bytes)
//   3. TARAKO_SIGN_DATA   — signs SHA256(fsverity_digest || user_data)
//
// Up to 1024 bits of opaque user data can be provided as a hex command-line
// argument. Shorter values (such as a 32-byte nonce) are zero-padded to 1024
// bits. Without an argument, a hardcoded 32-byte nonce is used (for testing).
//
// This binary must reside on an fs-verity-protected filesystem; the kernel
// module rejects signing requests from non-verity processes.
use der::asn1::{BitString, ObjectIdentifier, UintRef};
use der::{Encode, SliceWriter, Tag};
use std::fmt::Write;
use std::io;
use std::os::fd::{AsRawFd, RawFd};

const TARAKO_HELLO: u32 = 0x0000_5300;
const TARAKO_GET_PUBKEY: u32 = 0x8041_5301;
const TARAKO_SIGN_DATA: u32 = 0xC121_5302;
const USER_DATA_BYTES: usize = 1024 / 8;

#[repr(C)]
struct SignDataReq {
    user_data: [u8; USER_DATA_BYTES],
    hash: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pubkey: [u8; 65],
}

impl Default for SignDataReq {
    fn default() -> Self {
        Self {
            user_data: [0; USER_DATA_BYTES],
            hash: [0; 32],
            sig_r: [0; 32],
            sig_s: [0; 32],
            pubkey: [0; 65],
        }
    }
}

const _: () = assert!(std::mem::size_of::<SignDataReq>() == 289);

fn hex(buf: &[u8]) -> String {
    let mut output = String::with_capacity(buf.len() * 2);
    for byte in buf {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn pubkey_der(pubkey: &[u8; 65]) -> Vec<u8> {
    let algo_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let curve_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let algo_inner_len =
        (algo_oid.encoded_len().unwrap() + curve_oid.encoded_len().unwrap()).unwrap();
    let algo_outer_len = algo_inner_len.for_tlv(Tag::Sequence).unwrap();

    let pk_bitstring = BitString::from_bytes(pubkey).unwrap();
    let pk_len = pk_bitstring.encoded_len().unwrap();

    let content_len = (algo_outer_len + pk_len).unwrap();
    let total_len = usize::try_from(content_len.for_tlv(Tag::Sequence).unwrap()).unwrap();

    let mut buf = vec![0u8; total_len];
    let mut writer = SliceWriter::new(&mut buf);
    writer
        .sequence(content_len, |w| {
            w.sequence(algo_inner_len, |w| {
                algo_oid.encode(w)?;
                curve_oid.encode(w)
            })?;
            pk_bitstring.encode(w)
        })
        .unwrap();
    buf
}

fn sig_der(sig_r: &[u8; 32], sig_s: &[u8; 32]) -> Vec<u8> {
    let r = UintRef::new(sig_r).unwrap();
    let s = UintRef::new(sig_s).unwrap();

    let content_len = (r.encoded_len().unwrap() + s.encoded_len().unwrap()).unwrap();
    let total_len = usize::try_from(content_len.for_tlv(Tag::Sequence).unwrap()).unwrap();

    let mut buf = vec![0u8; total_len];
    let mut writer = SliceWriter::new(&mut buf);
    writer
        .sequence(content_len, |w| {
            r.encode(w)?;
            s.encode(w)
        })
        .unwrap();
    buf
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_user_data(value: &str) -> Option<[u8; USER_DATA_BYTES]> {
    let input = value.as_bytes();
    if input.is_empty() || input.len() > USER_DATA_BYTES * 2 || !input.len().is_multiple_of(2) {
        return None;
    }

    let mut output = [0u8; USER_DATA_BYTES];
    for (byte, pair) in output.iter_mut().zip(input.chunks_exact(2)) {
        *byte = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn ioctl(fd: RawFd, request: u32) -> io::Result<libc::c_int> {
    let result = unsafe { libc::ioctl(fd, request as _) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn ioctl_mut<T>(fd: RawFd, request: u32, value: &mut T) -> io::Result<libc::c_int> {
    let result = unsafe { libc::ioctl(fd, request as _, value as *mut T) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn usage_error(program: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("usage: {program} [hex-user-data (up to 256 hex chars)]"),
    )
}

fn default_user_data() -> [u8; USER_DATA_BYTES] {
    let mut data = [0u8; USER_DATA_BYTES];
    for (index, byte) in data[..32].iter_mut().enumerate() {
        *byte = (index + 1) as u8;
    }
    data
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let program = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tarako-app".into());
    let user_data = match (args.next(), args.next()) {
        (None, None) => default_user_data(),
        (Some(value), None) => value
            .to_str()
            .and_then(parse_hex_user_data)
            .ok_or_else(|| usage_error(&program))?,
        _ => return Err(usage_error(&program).into()),
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tarako")?;
    let fd = file.as_raw_fd();

    // 1. Hello — verify the device is responsive.
    println!("=== TARAKO_HELLO ===");
    let result = ioctl(fd, TARAKO_HELLO)?;
    if result != 0 {
        return Err(
            io::Error::other(format!("TARAKO_HELLO returned unexpected value {result}")).into(),
        );
    }
    println!("ioctl return: {result}\n");

    // 2. Get public key — retrieve the raw ECDSA P-256 public key.
    println!("=== TARAKO_GET_PUBKEY ===");
    let mut pubkey = [0u8; 65];
    let result = ioctl_mut(fd, TARAKO_GET_PUBKEY, &mut pubkey)?;
    if result as usize != pubkey.len() {
        return Err(io::Error::other(format!(
            "TARAKO_GET_PUBKEY returned {result}, expected {}",
            pubkey.len()
        ))
        .into());
    }
    let der = pubkey_der(&pubkey);
    println!("ioctl return: {result}");
    println!("public key ({} bytes) DER:", pubkey.len());
    println!("{}", hex(&der));

    // 3. Sign — kernel computes ECDSA-SHA256(fsverity_digest || user_data).
    println!("=== TARAKO_SIGN_DATA ===");
    let mut request = SignDataReq {
        user_data,
        ..Default::default()
    };
    let result = ioctl_mut(fd, TARAKO_SIGN_DATA, &mut request)?;
    if result != 0 {
        return Err(io::Error::other(format!(
            "TARAKO_SIGN_DATA returned unexpected value {result}"
        ))
        .into());
    }
    if request.pubkey != pubkey {
        return Err(io::Error::other("public key changed between ioctls").into());
    }

    println!("ioctl return: {result}");
    println!("user data: {}", hex(&request.user_data));
    println!("hash: {}", hex(&request.hash));
    println!("sig_r: {}", hex(&request.sig_r));
    println!("sig_s: {}", hex(&request.sig_s));
    println!("signature DER:");
    println!("{}", hex(&sig_der(&request.sig_r, &request.sig_s)));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tarako-app: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_pads_hex_user_data() {
        let parsed = parse_hex_user_data("01aBff").unwrap();
        assert_eq!(&parsed[..3], &[0x01, 0xab, 0xff]);
        assert!(parsed[3..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_invalid_hex_user_data() {
        assert!(parse_hex_user_data("").is_none());
        assert!(parse_hex_user_data("0").is_none());
        assert!(parse_hex_user_data("xx").is_none());
        assert!(parse_hex_user_data("é").is_none());
        assert!(parse_hex_user_data(&"00".repeat(USER_DATA_BYTES + 1)).is_none());
    }
}
