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
use std::os::unix::io::AsRawFd;

const TARAKO_HELLO: libc::c_ulong = 0x0000_5300;
const TARAKO_GET_PUBKEY: libc::c_ulong = 0x8041_5301;
const TARAKO_SIGN_DATA: libc::c_ulong = 0xC121_5302;
const USER_DATA_BYTES: usize = 1024 / 8;

#[repr(C)]
struct SignDataReq {
    user_data: [u8; USER_DATA_BYTES],
    hash: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pubkey: [u8; 65],
}

fn hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for &b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
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

fn parse_hex_user_data(s: &str) -> Option<[u8; USER_DATA_BYTES]> {
    if s.is_empty() || s.len() > USER_DATA_BYTES * 2 || s.len() % 2 != 0 {
        return None;
    }
    let mut out = [0u8; USER_DATA_BYTES];
    for (i, byte) in out.iter_mut().take(s.len() / 2).enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Use the provided opaque data, or a hardcoded nonce padded with zeroes.
    let user_data = if args.len() > 1 {
        parse_hex_user_data(&args[1]).unwrap_or_else(|| {
            eprintln!("usage: {} [hex-user-data (up to 256 hex chars)]", args[0]);
            std::process::exit(1);
        })
    } else {
        let mut data = [0u8; USER_DATA_BYTES];
        data[..32].copy_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        data
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tarako")
        .expect("failed to open /dev/tarako");
    let fd = file.as_raw_fd();

    // 1. Hello — verify the device is responsive
    println!("=== TARAKO_HELLO ===");
    let ret = unsafe { libc::ioctl(fd, TARAKO_HELLO as _) };
    if ret < 0 {
        eprintln!("TARAKO_HELLO failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    println!("ioctl return: {ret}\n");

    // 2. Get public key — retrieve the raw ECDSA P-256 public key
    println!("=== TARAKO_GET_PUBKEY ===");
    let mut pubkey = [0u8; 65];
    let ret = unsafe {
        libc::ioctl(
            fd,
            TARAKO_GET_PUBKEY as _,
            pubkey.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret < 0 {
        eprintln!(
            "TARAKO_GET_PUBKEY failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    let pubkey_len = ret as usize;
    let der = pubkey_der(&pubkey);
    println!("ioctl return: {ret}");
    println!("public key ({pubkey_len} bytes) DER:");
    println!("{}", hex(&der));

    // 3. Sign — kernel computes ECDSA(sk, SHA256(fsverity_digest || user_data))
    println!("=== TARAKO_SIGN_DATA ===");
    let mut req = SignDataReq {
        user_data,
        hash: [0u8; 32],
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
        pubkey: [0u8; 65],
    };
    let ret = unsafe {
        libc::ioctl(
            fd,
            TARAKO_SIGN_DATA as _,
            &mut req as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        eprintln!(
            "TARAKO_SIGN_DATA failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    println!("ioctl return: {ret}");
    println!("user data: {}", hex(&req.user_data));
    println!("hash: {}", hex(&req.hash));
    // Kernel returns raw LE-limb bytes; convert to big-endian hex for display
    println!("sig_r: {}", hex(&req.sig_r));
    println!("sig_s: {}", hex(&req.sig_s));
    println!("signature DER:");
    println!("{}", hex(&sig_der(&req.sig_r, &req.sig_s)));
}
