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
//! # Coverage and seals
//!
//! This verifier handles only the cooperative path: [`Proof::Mutual`] is
//! checked by verifying both signatures against the canonical close
//! payload hash. [`Proof::Timeout`] enforces the terms-hash binding,
//! the height guard, and the committed timeout-payout shape. The
//! [`Proof::Violation`] path is **rejected**: dispute seals are protocol-
//! specific (TEE attestation, ZK proof commitment, fraud-game
//! commitment), and there is no universal seal verifier. Production
//! users that need to admit violation closes must compose this verifier
//! with a seal-aware one — or wire the entire [`Verifier`] trait
//! themselves.

use secp256k1::{Message, PublicKey, Secp256k1, VerifyOnly, ecdsa::Signature};

use crate::consts::MAX_EDGE_OUTPUTS;
use crate::context::Context;
use crate::error::InvalidProofReason;
use crate::list::List;
use crate::object::Edge;
use crate::primitive::{CloseHash, EdgeId, Key, Sig};
use crate::tx::{CloseKind, Payout, Proof, Tx};
use crate::verifier::Verifier;

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

impl Default for Secp256k1Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for Secp256k1Verifier {
    fn verify_close(
        &self,
        edge_id: EdgeId,
        edge: &Edge,
        payouts: &List<Payout, MAX_EDGE_OUTPUTS>,
        proof: &Proof,
        context: &Context,
    ) -> Result<(), InvalidProofReason> {
        match proof {
            Proof::Mutual { maker, taker } => {
                let hash = Tx::payload_hash(edge_id, CloseKind::Mutual, edge.terms(), payouts);
                let parties = edge.parties();
                if self.verify_sig(*maker, parties.maker(), hash)
                    && self.verify_sig(*taker, parties.taker(), hash)
                {
                    Ok(())
                } else {
                    Err(InvalidProofReason::BadSignature)
                }
            }
            Proof::Timeout { terms } => {
                if terms.hash() != edge.terms() {
                    return Err(InvalidProofReason::TermsMismatch);
                }
                if context.block_height() < terms.timeout() {
                    return Err(InvalidProofReason::TimeoutNotReached);
                }
                if payouts != terms.timeout_outputs() {
                    return Err(InvalidProofReason::PayoutMismatch);
                }
                Ok(())
            }
            Proof::Violation { .. } => {
                // Seals are protocol-specific; this verifier has no seal
                // policy and rejects every violation close. Compose with a
                // seal verifier in production.
                Err(InvalidProofReason::BadSeal)
            }
        }
    }
}
