//! Real ECDSA verifier over secp256k1.
//!
//! Production callers can use [`Secp256k1Verifier`] to verify close
//! signatures with the canonical Bitcoin curve. The kernel itself remains
//! crypto-agnostic — this module is gated behind the `secp256k1` feature, and
//! the kernel never references it directly.
//!
//! Compact-form ECDSA signatures are 64 bytes (`r ‖ s`), matching the
//! kernel's [`Sig`] shape. Compressed public keys are 33 bytes, matching
//! [`Key`]. The 32-byte [`CloseHash`] is interpreted as the pre-hashed
//! message — the verifier does not hash again.
//!
//! # Scope
//!
//! This verifier covers the [`SigVerifier`] half only:
//! signature-shaped witnesses used by [`crate::Proof::Mutual`]. The seal
//! half — [`crate::Proof::Violation`] — is protocol-specific (TEE
//! attestation, ZK proof commitment, fraud-game seal) and has no
//! universal admissibility policy, so production deployments compose
//! `Secp256k1Verifier` with a separate [`crate::SealVerifier`]
//! implementation that knows their protocol's seal shape.

use secp256k1::{Message, PublicKey, Secp256k1, VerifyOnly, ecdsa::Signature};

use crate::primitive::{CloseHash, Key, Sig};
use crate::verifier::SigVerifier;

/// Verifier that accepts compact-form secp256k1 ECDSA signatures from
/// compressed public keys, with the close hash interpreted as the
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

impl SigVerifier for Secp256k1Verifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: CloseHash) -> bool {
        let Ok(pk) = PublicKey::from_slice(key.as_bytes()) else {
            return false;
        };
        let Ok(signature) = Signature::from_compact(sig.as_bytes()) else {
            return false;
        };
        let message = Message::from_digest(hash.to_bytes());
        self.secp.verify_ecdsa(message, &signature, &pk).is_ok()
    }
}
