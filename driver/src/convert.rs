// SPDX-License-Identifier: GPL-2.0

// Byte-order conversion helpers for ECC limbs.
//
// Kernel crypto helpers work with little-endian u64 arrays ("limbs").
// Wire formats (certificate, signature R/S, ioctl buffers) are big-endian
// byte strings.  These routines bridge the two worlds.

use crate::ecc;

/// SEC 1 uncompressed EC point (`0x04 || X || Y`, 65 bytes).
pub(crate) struct UncompressedPubkey(pub(crate) [u8; ecc::P256_PUBKEY_BYTES]);

impl UncompressedPubkey {
    pub(crate) fn as_bytes(&self) -> &[u8; ecc::P256_PUBKEY_BYTES] {
        &self.0
    }
}
