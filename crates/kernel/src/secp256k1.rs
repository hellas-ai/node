//! Real ECDSA verifier over secp256k1.
//!
//! Production callers can use [`Secp256k1Verifier`] to verify close
//! signatures with the canonical Bitcoin curve. The kernel itself remains
//! crypto-agnostic — this module is gated behind the `secp256k1` feature, and
//! the kernel never references it directly.
//!
//! Compact-form ECDSA signatures are 64 bytes (`r ‖ s`), matching the
//! kernel's [`Sig`] shape. Compressed public keys are 33 bytes, matching
//! [`Key`]. The 32-byte [`PayloadHash`] is interpreted as the pre-hashed
//! message — the verifier does not hash again.
//!
//! # Scope
//!
//! Real ECDSA covers [`SigVerifier`] cleanly: cooperative-close
//! signatures used by [`crate::Proof::Mutual`]. The seal half —
//! [`crate::Proof::Violation`] — is protocol-specific (TEE attestation,
//! ZK proof commitment, fraud-game seal) with no universal admissibility
//! policy, so [`Secp256k1Verifier`] also implements [`SealVerifier`] as
//! a hard-reject: every seal is rejected, every violation close fails.
//! Deployments that support violation closes wrap or replace the seal
//! impl with one that knows their protocol's seal shape.

use core::fmt;

use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, VerifyOnly, ecdsa::Signature};

use crate::primitive::{Key, PayloadHash, Sig};
use crate::tx::{Auth, Seal};
use crate::verifier::{SealPublicInputs, SealVerifier, SigVerifier};

/// Failure while constructing an in-memory native signer.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Secp256k1SignerError {
    /// The supplied bytes are not a valid non-zero secp256k1 secret scalar.
    InvalidSecretScalar,
}

/// In-memory secp256k1 signer for native kernel authorizations.
#[derive(Clone)]
#[allow(
    missing_copy_implementations,
    reason = "secret-bearing signers must not be implicitly copied"
)]
pub struct Secp256k1Signer {
    secret_key: SecretKey,
    party_key: Key,
}

impl fmt::Debug for Secp256k1Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secp256k1Signer")
            .field("party_key", &self.party_key)
            .finish_non_exhaustive()
    }
}

impl Secp256k1Signer {
    /// Derives a native signer from one canonical 32-byte secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`Secp256k1SignerError::InvalidSecretScalar`] for zero or
    /// out-of-range scalars.
    pub fn from_secret_scalar(secret_scalar: [u8; 32]) -> Result<Self, Secp256k1SignerError> {
        let secret_key = SecretKey::from_byte_array(secret_scalar)
            .map_err(|_| Secp256k1SignerError::InvalidSecretScalar)?;
        let party_key = Key::from_bytes(secret_key.public_key(&Secp256k1::new()).serialize());
        Ok(Self {
            secret_key,
            party_key,
        })
    }

    /// Returns the compressed secp256k1 party key controlled by this signer.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Signs one canonical kernel payload hash into compact `r || s` form.
    #[must_use]
    pub fn sign(&self, hash: PayloadHash) -> Sig {
        let signature = Secp256k1::new()
            .sign_ecdsa(Message::from_digest(hash.to_bytes()), &self.secret_key)
            .serialize_compact();
        Sig::from_bytes(signature)
    }
}

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
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool {
        let Ok(pk) = PublicKey::from_slice(party_key.as_bytes()) else {
            return false;
        };
        let Ok(signature) = Signature::from_compact(sig.as_bytes()) else {
            return false;
        };
        let message = Message::from_digest(hash.to_bytes());
        self.secp.verify_ecdsa(message, &signature, &pk).is_ok()
    }

    fn verify_auth(&self, auth: &Auth, party_key: Key, hash: PayloadHash) -> bool {
        match auth {
            Auth::Native(sig) => self.verify_sig(*sig, party_key, hash),
            #[cfg(feature = "webauthn")]
            Auth::WebAuthn(assertion) => {
                crate::webauthn::verify_webauthn_assertion(assertion, party_key, hash).is_ok()
            }
            #[cfg(not(feature = "webauthn"))]
            Auth::WebAuthn(_) => false,
        }
    }
}

impl SealVerifier for Secp256k1Verifier {
    /// Rejects every seal. Dispute seals are protocol-specific (TEE
    /// attestation, ZK proof commitment, fraud-game seal); this verifier
    /// owns no such policy. Deployments that admit violation closes wrap
    /// or replace this impl with one that knows their protocol's seal.
    fn verify_seal(&self, _seal: Seal, _public: &SealPublicInputs<'_>) -> bool {
        false
    }
}
