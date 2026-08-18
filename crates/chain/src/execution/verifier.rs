//! Consensus-fixed verifier wiring.
//!
//! [`ChainVerifier`] is the one place where the chain decides which
//! cryptography consensus execution applies kernel transactions with.
//! Party authorizations are real secp256k1 / WebAuthn; dispute seals are
//! hard-rejected until a real protocol seal verifier exists. Changing the
//! seal policy happens here and nowhere else — `execute_all` and
//! `execute_proposal` take the verifier as a parameter and never construct
//! one.

use hellas_kernel::{
    Auth, Key, PayloadHash, Seal, SealPublicInputs, SealVerifier, Secp256k1Verifier, Sig,
    SigVerifier,
};

/// The verifier every consensus execution path runs with.
#[derive(Debug, Default)]
pub struct ChainVerifier {
    inner: Secp256k1Verifier,
}

impl ChainVerifier {
    /// Creates the consensus verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Secp256k1Verifier::new(),
        }
    }
}

impl SigVerifier for ChainVerifier {
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool {
        self.inner.verify_sig(sig, party_key, hash)
    }

    fn verify_auth(&self, auth: &Auth, party_key: Key, hash: PayloadHash) -> bool {
        self.inner.verify_auth(auth, party_key, hash)
    }
}

impl SealVerifier for ChainVerifier {
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool {
        self.inner.verify_seal(seal, public)
    }
}
