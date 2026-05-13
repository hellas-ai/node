//! Open authorization witnesses.
//!
//! Close proofs deliberately keep using compact native [`Sig`] values because
//! cooperative closes are settlement-key signatures over a close payload hash.
//! Opens need a wider envelope: a party may authorize an edge with the same
//! native signature shape, or with a `WebAuthn` assertion whose challenge binds
//! to the canonical open hash.

use crate::{
    consts::MAX_WEBAUTHN_DATA_LENGTH,
    list::List,
    primitive::{PayloadHash, Sig},
};

/// Bounded `authenticatorData || clientDataJSON` bytes from a `WebAuthn`
/// assertion.
pub type WebAuthnData = List<u8, MAX_WEBAUTHN_DATA_LENGTH>;

/// `WebAuthn` assertion used to authorize one edge open.
///
/// The assertion carries the P-256 signature components, the P-256 public key
/// coordinates, and the raw `WebAuthn` bytes signed by the authenticator. The
/// kernel verifier expects `clientDataJSON.challenge` to equal the base64url
/// encoding of the canonical open hash.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WebAuthnAssertion {
    r: [u8; PayloadHash::LENGTH],
    s: [u8; PayloadHash::LENGTH],
    pub_key_x: [u8; PayloadHash::LENGTH],
    pub_key_y: [u8; PayloadHash::LENGTH],
    webauthn_data: WebAuthnData,
}

impl WebAuthnAssertion {
    /// Creates a `WebAuthn` open assertion from canonical components.
    #[must_use]
    pub const fn new(
        r: [u8; PayloadHash::LENGTH],
        s: [u8; PayloadHash::LENGTH],
        pub_key_x: [u8; PayloadHash::LENGTH],
        pub_key_y: [u8; PayloadHash::LENGTH],
        webauthn_data: WebAuthnData,
    ) -> Self {
        Self {
            r,
            s,
            pub_key_x,
            pub_key_y,
            webauthn_data,
        }
    }

    /// Returns the P-256 signature `r` scalar bytes.
    #[must_use]
    pub const fn r(&self) -> &[u8; PayloadHash::LENGTH] {
        &self.r
    }

    /// Returns the P-256 signature `s` scalar bytes.
    #[must_use]
    pub const fn s(&self) -> &[u8; PayloadHash::LENGTH] {
        &self.s
    }

    /// Returns the P-256 public key x-coordinate.
    #[must_use]
    pub const fn pub_key_x(&self) -> &[u8; PayloadHash::LENGTH] {
        &self.pub_key_x
    }

    /// Returns the P-256 public key y-coordinate.
    #[must_use]
    pub const fn pub_key_y(&self) -> &[u8; PayloadHash::LENGTH] {
        &self.pub_key_y
    }

    /// Returns the bounded `authenticatorData || clientDataJSON` bytes.
    #[must_use]
    pub const fn webauthn_data(&self) -> &WebAuthnData {
        &self.webauthn_data
    }
}

/// Party authorization for an edge open.
#[allow(
    clippy::large_enum_variant,
    reason = "Open auth is stored inline so the no-alloc kernel can verify WebAuthn bytes directly"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum OpenAuth {
    /// Compact native settlement signature over [`crate::Tx::open_hash`].
    Native(Sig),
    /// `WebAuthn` assertion whose challenge is [`crate::Tx::open_hash`].
    WebAuthn(WebAuthnAssertion),
}

impl OpenAuth {
    /// Wraps a compact native settlement signature.
    #[must_use]
    pub const fn native(sig: Sig) -> Self {
        Self::Native(sig)
    }

    /// Wraps a `WebAuthn` assertion.
    #[must_use]
    pub const fn webauthn(assertion: WebAuthnAssertion) -> Self {
        Self::WebAuthn(assertion)
    }
}

impl From<Sig> for OpenAuth {
    fn from(sig: Sig) -> Self {
        Self::Native(sig)
    }
}
