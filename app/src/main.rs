use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

const SIGNER_HELLO: libc::c_ulong = 0x0000_5300;
const SIGNER_GET_CERT: libc::c_ulong = 0x8800_5301;
const SIGNER_SIGN_DATA: libc::c_ulong = 0xC144_5302;

#[repr(C)]
struct SignDataReq {
    data_len: u32,
    data: [u8; 256],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
}

fn hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for &b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    let file = OpenOptions::new()
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
    println!();

    // 3. Sign data
    println!("=== SIGNER_SIGN_DATA ===");
    let msg = b"Hello, kernel!";
    let mut req = SignDataReq {
        data_len: msg.len() as u32,
        data: [0u8; 256],
        sig_r: [0u8; 32],
        sig_s: [0u8; 32],
    };
    req.data[..msg.len()].copy_from_slice(msg);

    let ret = unsafe { libc::ioctl(fd, SIGNER_SIGN_DATA, &mut req as *mut _ as *mut libc::c_void) };
    println!("ioctl return: {ret}");
    println!("message: '{}'", String::from_utf8_lossy(msg));
    println!("signature R: {}", hex(&req.sig_r));
    println!("signature S: {}", hex(&req.sig_s));
}
