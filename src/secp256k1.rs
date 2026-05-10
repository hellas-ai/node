//! Real ECDSA verifier over secp256k1.
//!
//! Production callers can use [`Secp256k1Verifier`] to verify resolve
//! signatures with the canonical Bitcoin curve. The kernel itself remains
//! crypto-agnostic — this module is gated behind the `secp256k1` feature, and
//! the kernel never references it directly.
//!
//! Compact-form ECDSA signatures are 64 bytes (`r ‖ s`), matching the
//! kernel's [`Sig`] shape. Compressed public keys are 33 bytes, matching
//! [`Key`]. The 32-byte [`ResolveHash`] is interpreted as the pre-hashed
//! message — the verifier does not hash again.
//!
//! # Seals
//!
//! Dispute seals are protocol-specific: they may carry a TEE attestation, a
//! ZK proof, or a fraud-game commitment. There is no universal seal
//! verifier, and `Secp256k1Verifier` rejects every seal it sees. Production
//! users that resolve disputes must compose this verifier with a seal-aware
//! one — or wire the entire `Verifier` trait themselves.

use secp256k1::{Message, PublicKey, Secp256k1, VerifyOnly, ecdsa::Signature};

use crate::op::{ResolveKind, Seal};
use crate::primitive::{Key, ResolveHash, Sig};
use crate::verifier::Verifier;

/// Verifier that accepts compact-form secp256k1 ECDSA signatures from
/// compressed public keys, with the resolve hash interpreted as the
/// pre-hashed message.
#[derive(Debug)]
pub struct Secp256k1Verifier {
    secp: Secp256k1<VerifyOnly>,
}

impl Secp256k1Verifier {
    /// Creates a new verifier over a fresh verify-only context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::verification_only(),
        }
    }
}

impl Default for Secp256k1Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for Secp256k1Verifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: ResolveHash) -> bool {
        let Ok(pk) = PublicKey::from_slice(key.as_bytes()) else {
            return false;
        };
        let Ok(signature) = Signature::from_compact(sig.as_bytes()) else {
            return false;
        };
        let message = Message::from_digest(hash.to_bytes());
        self.secp.verify_ecdsa(message, &signature, &pk).is_ok()
    }

    fn verify_seal(
        &self,
        _seal: Seal,
        _protocol: crate::primitive::ProtocolCode,
        _kind: ResolveKind,
        _hash: ResolveHash,
    ) -> bool {
        // Seals are protocol-specific; this verifier has no seal policy and
        // rejects every seal. Compose with a seal verifier in production.
        false
    }
}
