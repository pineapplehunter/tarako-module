// SPDX-License-Identifier: GPL-2.0

// Self-signed X.509 certificate builder.
//
// Uses a minimal DER encoder (DerBuf) to construct a self-signed
// ECDSA P-256 certificate, then signs it with the generated private key.

use crate::convert;
use crate::ioctl;
use kernel::alloc::{flags::GFP_KERNEL, KBox};
use kernel::prelude::*;

// OID 1.2.840.10045.2.1 - id-ecPublicKey (ANSI X9.62, RFC 5480 sec 2.1.1)
const OID_EC_PUBKEY: [u32; 6] = [1, 2, 840, 10045, 2, 1];
// OID 1.2.840.10045.3.1.7 - secp256r1 / prime256v1 (ANSI X9.62, SEC 2)
const OID_SECP256R1: [u32; 7] = [1, 2, 840, 10045, 3, 1, 7];
// OID 1.2.840.10045.4.3.2 - ecdsa-with-SHA256 (ANSI X9.62, RFC 5758)
const OID_ECDSA_WITH_SHA256: [u32; 7] = [1, 2, 840, 10045, 4, 3, 2];
// OID 2.5.4.3 - commonName (ITU-T X.520 / RFC 4519 sec 2.3)
const OID_CN: [u32; 4] = [2, 5, 4, 3];

// Arbitrary validity period for the self-signed cert (UTC, format YYMMDDHHMMSSZ)
const CURR_TIME: &[u8] = b"250101000000Z";
const EXPIRE_TIME: &[u8] = b"350101000000Z";
// X.509 subject commonName
const SUBJECT: &[u8] = b"signer";

struct DerBuf {
    buf: KBox<[u8; 2048]>,
    pos: usize,
}

impl DerBuf {
    fn new() -> Result<Self> {
        let buf = KBox::new([0u8; 2048], GFP_KERNEL).map_err(|_| ENOMEM)?;
        Ok(DerBuf { buf, pos: 0 })
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    fn push(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn extend(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    fn encode_length(&mut self, len: usize) {
        if len <= 0x7f {
            self.push(len as u8);
        } else if len <= 0xff {
            self.push(0x81);
            self.push(len as u8);
        } else if len <= 0xffff {
            self.push(0x82);
            self.push((len >> 8) as u8);
            self.push((len & 0xff) as u8);
        }
    }

    fn tag(&mut self, class: u8, constructed: bool, tag: u8, contents: &[u8]) {
        self.push((class << 6) | ((constructed as u8) << 5) | tag);
        self.encode_length(contents.len());
        self.extend(contents);
    }

    fn sequence(&mut self, contents: &[u8]) {
        self.tag(0, true, 0x10, contents);
    }

    fn set(&mut self, contents: &[u8]) {
        self.tag(0, true, 0x11, contents);
    }

    fn integer(&mut self, val: i64) {
        if val == 0 {
            self.buf[self.pos..self.pos + 3].copy_from_slice(&[0x02, 0x01, 0x00]);
            self.pos += 3;
            return;
        }
        let mut tmp = [0u8; 9];
        let mut n = 0usize;
        let mut v = val;
        while v != 0 {
            tmp[8 - n] = (v & 0xff) as u8;
            v >>= 8;
            n += 1;
        }
        let bytes = &tmp[9 - n..9];
        let (start, extra) = if bytes[0] & 0x80 != 0 {
            (0usize, 1usize)
        } else {
            (0usize, 0usize)
        };
        let data = &bytes[start..];
        self.push(0x02);
        self.encode_length(data.len() + extra);
        if extra > 0 {
            self.push(0x00);
        }
        self.extend(data);
    }

    fn integer_bytes(&mut self, val: &[u8]) {
        let start = val.iter().position(|&b| b != 0).unwrap_or(0);
        let data = &val[start..];
        self.push(0x02);
        if data.is_empty() || data[0] & 0x80 != 0 {
            self.encode_length(data.len() + 1);
            self.push(0x00);
        } else {
            self.encode_length(data.len());
        }
        self.extend(data);
    }

    fn oid(&mut self, oid: &[u32]) {
        let mut enc = [0u8; 64];
        let mut epos = 0usize;
        if oid.len() >= 2 {
            enc[epos] = (oid[0] * 40 + oid[1]) as u8;
            epos += 1;
        }
        for &val in &oid[2..] {
            if val < 128 {
                enc[epos] = val as u8;
                epos += 1;
            } else {
                let mut v = val;
                let mut tmp = [0u8; 5];
                let mut tn = 0usize;
                tmp[tn] = (v & 0x7f) as u8;
                tn += 1;
                v >>= 7;
                while v > 0 {
                    tmp[tn] = ((v & 0x7f) | 0x80) as u8;
                    tn += 1;
                    v >>= 7;
                }
                for j in (0..tn).rev() {
                    enc[epos] = tmp[j];
                    epos += 1;
                }
            }
        }
        self.push(0x06);
        self.encode_length(epos);
        self.extend(&enc[..epos]);
    }

    fn bit_string(&mut self, unused: u8, contents: &[u8]) {
        self.push(0x03);
        self.encode_length(1 + contents.len());
        self.push(unused);
        self.extend(contents);
    }

    fn utf8_string(&mut self, s: &[u8]) {
        self.push(0x0c);
        self.encode_length(s.len());
        self.extend(s);
    }

    fn utctime(&mut self, s: &[u8]) {
        self.push(0x17);
        self.encode_length(s.len());
        self.extend(s);
    }

    fn tagged_explicit(&mut self, tag: u8, contents: &[u8]) {
        self.tag(2, true, tag, contents);
    }
}

pub(crate) fn build_certificate(
    privkey: &[u64; 4],
    pub_x: &[u64; 4],
    pub_y: &[u64; 4],
) -> Result<([u8; 2048], usize)> {
    let pubkey_bytes = convert::uncompressed_pubkey_bytes(pub_x, pub_y);

    let mut spki = DerBuf::new()?;
    {
        let mut algo = DerBuf::new()?;
        algo.oid(&OID_EC_PUBKEY);
        algo.oid(&OID_SECP256R1);

        spki.sequence(algo.as_slice());
        spki.bit_string(0, &pubkey_bytes);
    }
    let spki_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(spki.as_slice());
        s
    };

    let mut sig_algo = DerBuf::new()?;
    sig_algo.oid(&OID_ECDSA_WITH_SHA256);
    let sig_algo_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(sig_algo.as_slice());
        s
    };

    let mut validity = DerBuf::new()?;
    validity.utctime(CURR_TIME);
    validity.utctime(EXPIRE_TIME);
    let validity_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(validity.as_slice());
        s
    };

    let mut name = DerBuf::new()?;
    {
        let mut attr = DerBuf::new()?;
        attr.oid(&OID_CN);
        attr.utf8_string(SUBJECT);
        let mut attr_seq = DerBuf::new()?;
        attr_seq.sequence(attr.as_slice());
        let mut set = DerBuf::new()?;
        set.set(attr_seq.as_slice());
        name.sequence(set.as_slice());
    }

    let mut version = DerBuf::new()?;
    version.integer(2);
    let mut version_tagged = DerBuf::new()?;
    version_tagged.tagged_explicit(0, version.as_slice());

    let mut tbs = DerBuf::new()?;
    tbs.extend(version_tagged.as_slice());
    tbs.integer(1);
    tbs.extend(sig_algo_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(validity_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(spki_seq.as_slice());

    let tbs_cert = {
        let mut s = DerBuf::new()?;
        s.sequence(tbs.as_slice());
        let mut out = [0u8; 2048];
        let len = s.pos;
        if len > 2048 {
            return Err(ENOSPC);
        }
        out[..len].copy_from_slice(&s.buf[..len]);
        (out, len)
    };
    let tbs_bytes = &tbs_cert.0[..tbs_cert.1];
    let (sig_r_limbs, sig_s_limbs) = ioctl::ecdsa_sign(tbs_bytes, privkey)?;
    let sig_r = convert::le_limbs_to_be_bytes(&sig_r_limbs);
    let sig_s = convert::le_limbs_to_be_bytes(&sig_s_limbs);

    let mut sig_der = DerBuf::new()?;
    sig_der.integer_bytes(&sig_r);
    sig_der.integer_bytes(&sig_s);
    let sig_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(sig_der.as_slice());
        s
    };

    let mut cert = DerBuf::new()?;
    cert.extend(tbs_bytes);
    cert.extend(sig_algo_seq.as_slice());
    cert.bit_string(0, sig_seq.as_slice());

    let mut out = [0u8; 2048];
    let cert_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(cert.as_slice());
        s
    };
    let len = cert_seq.pos;
    if len > 2048 {
        return Err(ENOSPC);
    }
    out[..len].copy_from_slice(&cert_seq.buf[..len]);
    Ok((out, len))
}
