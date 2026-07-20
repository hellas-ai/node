//! Party-key authorization witnesses.
//!
//! [`Auth`] is the kernel's one consent envelope: it proves that a party
//! key authorized a canonical payload hash — the open hash when opening an
//! edge, the close payload hash for a cooperative close. `Native` carries a
//! compact settlement signature; `WebAuthn` carries an assertion whose
//! challenge is that same hash. Both prove consent from the same kernel
//! party key used for funding ownership, terms, and payouts.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::MAX_WEBAUTHN_DATA_LENGTH,
    list::List,
    primitive::Sig,
};

/// Bounded `authenticatorData || clientDataJSON` bytes from a `WebAuthn`
/// assertion.
pub type WebAuthnData = List<u8, MAX_WEBAUTHN_DATA_LENGTH>;

const NATIVE_TAG: u8 = 0;
const WEBAUTHN_TAG: u8 = 1;
const P256_COORDINATE_LENGTH: usize = 32;

/// `WebAuthn` assertion used to authorize one edge open.
///
/// The assertion carries the P-256 signature components, the P-256 public key
/// coordinates, and the raw `WebAuthn` bytes signed by the authenticator. The
/// kernel verifier expects `clientDataJSON.challenge` to equal the base64url
/// encoding of the canonical open hash.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WebAuthnAssertion {
    r: [u8; P256_COORDINATE_LENGTH],
    s: [u8; P256_COORDINATE_LENGTH],
    pub_key_x: [u8; P256_COORDINATE_LENGTH],
    pub_key_y: [u8; P256_COORDINATE_LENGTH],
    webauthn_data: WebAuthnData,
}

impl WebAuthnAssertion {
    /// Creates a `WebAuthn` open assertion from canonical components.
    #[must_use]
    pub const fn new(
        r: [u8; P256_COORDINATE_LENGTH],
        s: [u8; P256_COORDINATE_LENGTH],
        pub_key_x: [u8; P256_COORDINATE_LENGTH],
        pub_key_y: [u8; P256_COORDINATE_LENGTH],
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
    pub const fn r(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.r
    }

    /// Returns the P-256 signature `s` scalar bytes.
    #[must_use]
    pub const fn s(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.s
    }

    /// Returns the P-256 public key x-coordinate.
    #[must_use]
    pub const fn pub_key_x(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_x
    }

    /// Returns the P-256 public key y-coordinate.
    #[must_use]
    pub const fn pub_key_y(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_y
    }

    /// Returns the bounded `authenticatorData || clientDataJSON` bytes.
    #[must_use]
    pub const fn webauthn_data(&self) -> &WebAuthnData {
        &self.webauthn_data
    }
}

impl Encode for WebAuthnAssertion {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + 4 * <[u8; P256_COORDINATE_LENGTH] as Encode>::MAX_ENCODED_SIZE
        + <WebAuthnData as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + self.r.encoded_size()
            + self.s.encoded_size()
            + self.pub_key_x.encoded_size()
            + self.pub_key_y.encoded_size()
            + self.webauthn_data.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::WEBAUTHN_ASSERTION);
        self.r.encode_to(writer);
        self.s.encode_to(writer);
        self.pub_key_x.encode_to(writer);
        self.pub_key_y.encode_to(writer);
        self.webauthn_data.encode_to(writer);
    }
}

impl Decode for WebAuthnAssertion {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::WEBAUTHN_ASSERTION)?;
        let r = decode_field(buf, &mut consumed)?;
        let s = decode_field(buf, &mut consumed)?;
        let pub_key_x = decode_field(buf, &mut consumed)?;
        let pub_key_y = decode_field(buf, &mut consumed)?;
        let webauthn_data = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(r, s, pub_key_x, pub_key_y, webauthn_data),
            consumed,
        ))
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

impl Encode for Auth {
    const MAX_ENCODED_SIZE: usize =
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + WebAuthnAssertion::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Native(sig) => sig.encoded_size(),
                Self::WebAuthn(assertion) => assertion.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::AUTH);
        match self {
            Self::Native(sig) => {
                NATIVE_TAG.encode_to(writer);
                sig.encode_to(writer);
            }
            Self::WebAuthn(assertion) => {
                WEBAUTHN_TAG.encode_to(writer);
                assertion.encode_to(writer);
            }
        }
    }
}

impl Decode for Auth {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::AUTH)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            NATIVE_TAG => {
                let sig = decode_field(buf, &mut consumed)?;
                Ok((Self::native(sig), consumed))
            }
            WEBAUTHN_TAG => {
                let assertion = decode_field(buf, &mut consumed)?;
                Ok((Self::webauthn(assertion), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

impl From<Sig> for Auth {
    fn from(sig: Sig) -> Self {
        Self::Native(sig)
    }
}
