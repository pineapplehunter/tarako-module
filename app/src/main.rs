// signer-app — userspace client for the signer kernel module.
//
// Opens /dev/signer and issues three ioctls in sequence:
//   1. SIGNER_HELLO       — sanity check
//   2. SIGNER_GET_PUBKEY  — retrieve the raw ECDSA P-256 public key (65 bytes)
//   3. SIGNER_SIGN_DATA   — remote attestation: signs SHA256(fsverity_digest || nonce)
//
// The nonce can be provided as a 64-hex-char command-line argument.
// Without an argument, a hardcoded nonce is used (for testing).
//
// This binary must reside on an fs-verity-protected filesystem; the kernel
// module rejects ioctls from non-verity processes.
use der::asn1::{BitString, ObjectIdentifier, UintRef};
use der::{Encode, SliceWriter, Tag};
use std::os::unix::io::AsRawFd;

const SIGNER_HELLO: libc::c_ulong = 0x0000_5300;
const SIGNER_GET_PUBKEY: libc::c_ulong = 0x8041_5301;
const SIGNER_SIGN_DATA: libc::c_ulong = 0xC0C1_5302;

#[repr(C)]
struct SignDataReq {
    nonce: [u8; 32],
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

fn parse_hex_nonce(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Use the provided hex nonce, or fall back to a hardcoded one
    let nonce: [u8; 32] = if args.len() > 1 {
        parse_hex_nonce(&args[1]).unwrap_or_else(|| {
            eprintln!("usage: {} [64-hex-nonce]", args[0]);
            std::process::exit(1);
        })
    } else {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/signer")
        .expect("failed to open /dev/signer");
    let fd = file.as_raw_fd();

    // 1. Hello — verify the device is responsive
    println!("=== SIGNER_HELLO ===");
    let ret = unsafe { libc::ioctl(fd, SIGNER_HELLO as _) };
    if ret < 0 {
        eprintln!("SIGNER_HELLO failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    println!("ioctl return: {ret}\n");

    // 2. Get public key — retrieve the raw ECDSA P-256 public key
    println!("=== SIGNER_GET_PUBKEY ===");
    let mut pubkey = [0u8; 65];
    let ret = unsafe {
        libc::ioctl(
            fd,
            SIGNER_GET_PUBKEY as _,
            pubkey.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret < 0 {
        eprintln!(
            "SIGNER_GET_PUBKEY failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    let pubkey_len = ret as usize;
    let der = pubkey_der(&pubkey);
    println!("ioctl return: {ret}");
    println!("public key ({pubkey_len} bytes) DER:");
    println!("{}", hex(&der));

    // 3. Sign — kernel computes ECDSA(sk, SHA256(fsverity_digest || nonce))
    println!("=== SIGNER_SIGN_DATA ===");
    let mut req = SignDataReq {
        nonce,
        hash: [0u8; 32],
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
        pubkey: [0u8; 65],
    };
    let ret = unsafe {
        libc::ioctl(
            fd,
            SIGNER_SIGN_DATA as _,
            &mut req as *mut _ as *mut libc::c_void,
        )
    };
    if ret < 0 {
        eprintln!(
            "SIGNER_SIGN_DATA failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    println!("ioctl return: {ret}");
    println!("nonce: {}", hex(&req.nonce));
    println!("hash: {}", hex(&req.hash));
    // Kernel returns raw LE-limb bytes; convert to big-endian hex for display
    println!("sig_r: {}", hex(&req.sig_r));
    println!("sig_s: {}", hex(&req.sig_s));
    println!("signature DER:");
    println!("{}", hex(&sig_der(&req.sig_r, &req.sig_s)));
}
