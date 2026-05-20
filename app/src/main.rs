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

// The kernel returns signature r, s as raw LE-limb u64 bytes.
// Convert to big-endian hex for human-readable display.
fn le_limbs_to_be_hex(raw: &[u8; 32]) -> String {
    let mut be = [0u8; 32];
    for i in 0..4 {
        let limb = u64::from_le_bytes(raw[(3 - i) * 8..(4 - i) * 8].try_into().unwrap());
        be[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    hex(&be)
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
    let ret = unsafe { libc::ioctl(fd, SIGNER_HELLO) };
    println!("ioctl return: {ret}\n");

    // 2. Get public key — retrieve the raw ECDSA P-256 public key
    println!("=== SIGNER_GET_PUBKEY ===");
    let mut pubkey = [0u8; 65];
    let ret = unsafe {
        libc::ioctl(
            fd,
            SIGNER_GET_PUBKEY,
            pubkey.as_mut_ptr() as *mut libc::c_void,
        )
    };
    let pubkey_len = if ret > 0 { ret as usize } else { 0 };
    println!("ioctl return: {ret}");
    println!("public key ({pubkey_len} bytes):");
    println!("  hex: {}", hex(&pubkey[..pubkey_len]));
    println!();

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
            SIGNER_SIGN_DATA,
            &mut req as *mut _ as *mut libc::c_void,
        )
    };
    println!("ioctl return: {ret}");
    println!("nonce: {}", hex(&req.nonce));
    println!("hash: {}", hex(&req.hash));
    // Kernel returns raw LE-limb bytes; convert to big-endian hex for display
    println!("sig_r: {}", le_limbs_to_be_hex(&req.sig_r));
    println!("sig_s: {}", le_limbs_to_be_hex(&req.sig_s));
    println!("pubkey: {}", hex(&req.pubkey));
}
