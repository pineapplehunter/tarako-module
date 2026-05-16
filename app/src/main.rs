use std::os::unix::io::AsRawFd;

const SIGNER_HELLO: libc::c_ulong = 0x0000_5300;
const SIGNER_GET_CERT: libc::c_ulong = 0x8800_5301;
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

fn main() {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/signer")
        .expect("failed to open /dev/signer");
    let fd = file.as_raw_fd();

    // 1. Hello
    println!("=== SIGNER_HELLO ===");
    let ret = unsafe { libc::ioctl(fd, SIGNER_HELLO) };
    println!("ioctl return: {ret}\n");

    // 2. Get certificate
    println!("=== SIGNER_GET_CERT ===");
    let mut cert = [0u8; 2048];
    let ret = unsafe { libc::ioctl(fd, SIGNER_GET_CERT, cert.as_mut_ptr() as *mut libc::c_void) };
    let cert_len = if ret > 0 { ret as usize } else { 0 };
    println!("ioctl return: {ret}");
    println!("certificate ({cert_len} bytes):");
    println!("  hex: {}", hex(&cert[..cert_len]));
    if cert_len > 0 {
        std::fs::write("/tmp/signer_cert.der", &cert[..cert_len]).ok();
    }
    println!();

    // 3. Sign — kernel computes ECDSA(sk, SHA256(fsverity_digest || nonce))
    println!("=== SIGNER_SIGN_DATA ===");
    let nonce: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let mut req = SignDataReq {
        nonce,
        hash: [0u8; 32],
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
        pubkey: [0u8; 65],
    };
    let ret = unsafe { libc::ioctl(fd, SIGNER_SIGN_DATA, &mut req as *mut _ as *mut libc::c_void) };
    println!("ioctl return: {ret}");
    println!("nonce: {}", hex(&req.nonce));
    println!("hash: {}", hex(&req.hash));
    println!("sig_r: {}", hex(&req.sig_r));
    println!("sig_s: {}", hex(&req.sig_s));
    println!("pubkey: {}", hex(&req.pubkey));
}
