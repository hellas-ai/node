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

/// Whether the wired verifier can actually verify some protocol's
/// dispute seals.
///
/// Consensus execution rejects every staked-terms `Open` unless the
/// verifier admits them: a bond whose `Violation` path can never verify
/// is not a bond, just locked funds with a dead dispute game. The gate
/// lifts exactly when a seal-capable verifier is wired — it cannot
/// desync from the verification capability, because it *is* the
/// verification capability.
pub trait StakedOpenPolicy {
    /// Returns true when staked-terms opens are admissible under this
    /// verifier.
    #[must_use]
    fn admits_staked_opens(&self) -> bool;
}

/// The verifier every consensus execution path runs with.
///
/// With the `preverified-seals` feature (dev chains only), violation
/// seals verify against a shared [`crate::staked::PreverifiedSeals`]
/// cache and staked opens are admitted; otherwise every seal is
/// rejected and staked opens are gated off.
#[derive(Debug, Default)]
pub struct ChainVerifier {
    inner: Secp256k1Verifier,
    #[cfg(feature = "preverified-seals")]
    seals: crate::staked::PreverifiedSeals,
}

impl ChainVerifier {
    /// Creates the consensus verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Secp256k1Verifier::new(),
            #[cfg(feature = "preverified-seals")]
            seals: crate::staked::PreverifiedSeals::new(),
        }
    }

    /// The preverified fraud-artifact cache this verifier consults.
    /// Handles are cheap clones sharing one cache.
    #[cfg(feature = "preverified-seals")]
    #[must_use]
    pub fn preverified_seals(&self) -> crate::staked::PreverifiedSeals {
        self.seals.clone()
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
    #[cfg(not(feature = "preverified-seals"))]
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool {
        self.inner.verify_seal(seal, public)
    }

    #[cfg(feature = "preverified-seals")]
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool {
        self.seals.verify(seal, public)
    }
}

impl StakedOpenPolicy for ChainVerifier {
    /// Without a seal-capable verifier every seal is rejected
    /// (`Secp256k1Verifier`'s hard-reject), so staked opens are
    /// meaningless and refused. The dev preverified cache makes them
    /// meaningful.
    fn admits_staked_opens(&self) -> bool {
        cfg!(feature = "preverified-seals")
    }
}
