//! Party-key authorization witnesses.
//!
//! [`Auth`] is the kernel's one consent envelope: it proves that a party
//! key authorized a canonical payload hash — the open hash when opening an
//! edge, the close payload hash for a cooperative close. `Native` carries a
//! compact settlement signature; `WebAuthn` carries an assertion whose
//! challenge is that same hash. Both prove consent from the same kernel
//! party key used for funding ownership, terms, and payouts.

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

/// Party-key authorization over a canonical payload hash.
///
/// This is a witness envelope, not a separate identity. The verifier checks
/// each variant against the maker/taker key committed in [`crate::Terms`],
/// for both edge opens ([`crate::Tx::open_hash`]) and cooperative closes
/// ([`crate::Tx::payload_hash`]).
#[allow(
    clippy::large_enum_variant,
    reason = "Auth is stored inline so the no-alloc kernel can verify WebAuthn bytes directly"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Auth {
    /// Compact native settlement signature over the payload hash.
    Native(Sig),
    /// `WebAuthn` assertion whose challenge is the payload hash.
    WebAuthn(WebAuthnAssertion),
}

impl Auth {
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

impl From<Sig> for Auth {
    fn from(sig: Sig) -> Self {
        Self::Native(sig)
    }
}
