//! Deterministic helpers and fixtures for the kernel WebAuthn v1 wire format.
//!
//! Everything in this module is gated by the crate's `test-support` feature.
//! It is suitable for integration tests and examples, not production key
//! custody: [`SoftPasskey`] stores its secret scalar in process memory.

use core::fmt;

use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

use super::{AT, ED, MIN_AUTH_DATA_LEN, UP, WebAuthnError, base64url_32, p256_key};
use crate::{
    CloseKind, CoinId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    MAX_WEBAUTHN_DATA_LENGTH, Parties, PayloadHash, Payout, ProtocolCode, Terms, Tx,
    WebAuthnAssertion, consts::P256_COORDINATE_LENGTH, context::BlockHeight,
};

const FIXTURE_ORIGIN: &[u8] = b"https://wallet.example.invalid";
const FIXTURE_RP_ID_HASH: [u8; P256_COORDINATE_LENGTH] = [0xaa; P256_COORDINATE_LENGTH];

/// Number of named invalid fixtures returned by [`negative_assertions`].
pub const WEBAUTHN_NEGATIVE_FIXTURE_COUNT: usize = 9;

/// Failure while constructing a deterministic software-passkey fixture.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum SoftPasskeyError {
    /// The supplied bytes are not a valid non-zero P-256 secret scalar.
    InvalidSecretScalar,
    /// P-256 did not expose or accept the derived affine coordinates.
    InvalidPublicKey,
    /// Deterministic P-256 prehash signing failed.
    SigningFailed,
    /// The assertion exceeded [`MAX_WEBAUTHN_DATA_LENGTH`].
    AssertionTooLarge,
}

/// In-memory deterministic P-256 signer for tests and shared fixtures.
#[derive(Clone)]
pub struct SoftPasskey {
    signing_key: SigningKey,
    party_key: Key,
    pub_key_x: [u8; P256_COORDINATE_LENGTH],
    pub_key_y: [u8; P256_COORDINATE_LENGTH],
}

impl fmt::Debug for SoftPasskey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftPasskey")
            .field("party_key", &self.party_key)
            .finish_non_exhaustive()
    }
}

impl SoftPasskey {
    /// Derives a software passkey from one canonical 32-byte secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`SoftPasskeyError::InvalidSecretScalar`] for zero or
    /// out-of-range scalars, or [`SoftPasskeyError::InvalidPublicKey`] if the
    /// derived coordinates cannot be represented as a kernel party key.
    pub fn from_secret_scalar(
        secret_scalar: [u8; P256_COORDINATE_LENGTH],
    ) -> Result<Self, SoftPasskeyError> {
        let signing_key = SigningKey::from_slice(&secret_scalar)
            .map_err(|_| SoftPasskeyError::InvalidSecretScalar)?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = point.x().ok_or(SoftPasskeyError::InvalidPublicKey)?;
        let y = point.y().ok_or(SoftPasskeyError::InvalidPublicKey)?;
        let mut pub_key_x = [0_u8; P256_COORDINATE_LENGTH];
        let mut pub_key_y = [0_u8; P256_COORDINATE_LENGTH];
        pub_key_x.copy_from_slice(x);
        pub_key_y.copy_from_slice(y);
        let party_key =
            p256_key(&pub_key_x, &pub_key_y).map_err(|_| SoftPasskeyError::InvalidPublicKey)?;

        Ok(Self {
            signing_key,
            party_key,
            pub_key_x,
            pub_key_y,
        })
    }

    /// Returns the compressed SEC1 party key controlled by this passkey.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the P-256 public x-coordinate.
    #[must_use]
    pub const fn pub_key_x(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_x
    }

    /// Returns the P-256 public y-coordinate.
    #[must_use]
    pub const fn pub_key_y(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_y
    }

    /// Signs `hash` into the canonical v1 assertion envelope.
    ///
    /// The generated authenticator data uses a deterministic ignored
    /// `rpIdHash`, sets `UP`, clears `UV`, `AT`, and `ED`, and uses a zero
    /// signature counter. The client data includes the fixture origin and a
    /// `false` `crossOrigin` member; neither affects verifier policy.
    ///
    /// # Errors
    ///
    /// Returns [`SoftPasskeyError`] if signing fails or the bounded assertion
    /// cannot be assembled.
    pub fn sign(&self, hash: PayloadHash) -> Result<WebAuthnAssertion, SoftPasskeyError> {
        build_assertion(self, hash, UP, ClientDataKind::Valid, false)
    }
}

/// Named valid WebAuthn v1 fixture.
#[derive(Debug, Clone)]
pub struct WebAuthnFixture {
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
}

impl WebAuthnFixture {
    /// Returns the stable vector name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the assertion under test.
    #[must_use]
    pub const fn assertion(&self) -> &WebAuthnAssertion {
        &self.assertion
    }

    /// Returns the expected compressed SEC1 signer key.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the canonical payload hash embedded as the challenge.
    #[must_use]
    pub const fn payload_hash(&self) -> PayloadHash {
        self.payload_hash
    }
}

/// Named invalid WebAuthn v1 fixture with its pinned verifier error.
#[derive(Debug, Clone)]
pub struct InvalidWebAuthnFixture {
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
    expected_error: WebAuthnError,
}

impl InvalidWebAuthnFixture {
    /// Returns the stable vector name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the assertion under test.
    #[must_use]
    pub const fn assertion(&self) -> &WebAuthnAssertion {
        &self.assertion
    }

    /// Returns the party key supplied to the verifier.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the payload hash supplied to the verifier.
    #[must_use]
    pub const fn payload_hash(&self) -> PayloadHash {
        self.payload_hash
    }

    /// Returns the exact verifier error this vector must produce.
    #[must_use]
    pub const fn expected_error(&self) -> WebAuthnError {
        self.expected_error
    }
}

/// Builds the named valid assertion over [`Tx::open_hash`].
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if the deterministic fixture cannot be built.
pub fn valid_open_assertion() -> Result<WebAuthnFixture, SoftPasskeyError> {
    let context = fixture_context()?;
    let assertion = context.passkey.sign(context.open_hash)?;
    Ok(WebAuthnFixture {
        name: "valid_open_assertion",
        assertion,
        party_key: context.passkey.party_key(),
        payload_hash: context.open_hash,
    })
}

/// Builds the named valid assertion over a mutual-close [`Tx::payload_hash`].
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if the deterministic fixture cannot be built.
pub fn valid_mutual_close_assertion() -> Result<WebAuthnFixture, SoftPasskeyError> {
    let context = fixture_context()?;
    let assertion = context.passkey.sign(context.mutual_close_hash)?;
    Ok(WebAuthnFixture {
        name: "valid_mutual_close_assertion",
        assertion,
        party_key: context.passkey.party_key(),
        payload_hash: context.mutual_close_hash,
    })
}

/// Builds all named invalid v1 assertions and their exact expected errors.
///
/// # Errors
///
/// Returns [`SoftPasskeyError`] if deterministic signing or bounded fixture
/// assembly fails.
pub fn negative_assertions()
-> Result<[InvalidWebAuthnFixture; WEBAUTHN_NEGATIVE_FIXTURE_COUNT], SoftPasskeyError> {
    let context = fixture_context()?;
    let wrong_challenge = PayloadHash::from_bytes([0x5a; PayloadHash::LENGTH]);
    let wrong_signer = SoftPasskey::from_secret_scalar([9; P256_COORDINATE_LENGTH])?;
    let party_key = context.passkey.party_key();
    let hash = context.open_hash;

    Ok([
        invalid_fixture(
            "wrong_challenge",
            build_assertion(
                &context.passkey,
                wrong_challenge,
                UP,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::InvalidChallenge,
        ),
        invalid_fixture(
            "high_s",
            build_assertion(&context.passkey, hash, UP, ClientDataKind::Valid, true)?,
            party_key,
            hash,
            WebAuthnError::HighS,
        ),
        invalid_fixture(
            "wrong_signer_key",
            wrong_signer.sign(hash)?,
            party_key,
            hash,
            WebAuthnError::SignerMismatch,
        ),
        invalid_fixture(
            "attested_credential_data",
            build_assertion(
                &context.passkey,
                hash,
                UP | AT,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::AttestedCredentialDataUnsupported,
        ),
        invalid_fixture(
            "extension_data",
            build_assertion(
                &context.passkey,
                hash,
                UP | ED,
                ClientDataKind::Valid,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::ExtensionsUnsupported,
        ),
        invalid_fixture(
            "missing_user_presence_and_verification",
            build_assertion(&context.passkey, hash, 0, ClientDataKind::Valid, false)?,
            party_key,
            hash,
            WebAuthnError::MissingUserPresence,
        ),
        invalid_fixture(
            "nested_json_injection",
            build_assertion(
                &context.passkey,
                hash,
                UP,
                ClientDataKind::NestedInjection,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::InvalidClientDataJson,
        ),
        invalid_fixture(
            "duplicate_required_field",
            build_assertion(
                &context.passkey,
                hash,
                UP,
                ClientDataKind::DuplicateChallenge,
                false,
            )?,
            party_key,
            hash,
            WebAuthnError::DuplicateClientDataField,
        ),
        invalid_fixture(
            "wrong_client_data_type",
            build_assertion(&context.passkey, hash, UP, ClientDataKind::WrongType, false)?,
            party_key,
            hash,
            WebAuthnError::InvalidClientDataType,
        ),
    ])
}

fn invalid_fixture(
    name: &'static str,
    assertion: WebAuthnAssertion,
    party_key: Key,
    payload_hash: PayloadHash,
    expected_error: WebAuthnError,
) -> InvalidWebAuthnFixture {
    InvalidWebAuthnFixture {
        name,
        assertion,
        party_key,
        payload_hash,
        expected_error,
    }
}

struct FixtureContext {
    passkey: SoftPasskey,
    open_hash: PayloadHash,
    mutual_close_hash: PayloadHash,
}

fn fixture_context() -> Result<FixtureContext, SoftPasskeyError> {
    let passkey = SoftPasskey::from_secret_scalar([7; P256_COORDINATE_LENGTH])?;
    let other = SoftPasskey::from_secret_scalar([8; P256_COORDINATE_LENGTH])?;
    let maker = List::take(
        [CoinId::from_bytes([0x11; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        1,
    );
    let taker = List::take(
        [CoinId::from_bytes([0x22; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        1,
    );
    let funding = Funding::new(maker, taker);
    let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
    if let Some(maker_payout) = payout_values.first_mut() {
        *maker_payout = Payout::new(passkey.party_key(), 40);
    }
    if let Some(taker_payout) = payout_values.get_mut(1) {
        *taker_payout = Payout::new(other.party_key(), 60);
    }
    let outputs = List::take(payout_values, 2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(passkey.party_key(), other.party_key()),
        BlockHeight::new(100),
        outputs.clone(),
    );
    let open_hash = Tx::open_hash(&funding, &terms);
    let edge = Tx::edge_id_of(&funding, &terms);
    let mutual_close_hash = Tx::payload_hash(edge, CloseKind::Mutual, terms.hash(), &outputs);

    Ok(FixtureContext {
        passkey,
        open_hash,
        mutual_close_hash,
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ClientDataKind {
    Valid,
    NestedInjection,
    DuplicateChallenge,
    WrongType,
}

fn build_assertion(
    passkey: &SoftPasskey,
    challenge_hash: PayloadHash,
    flags: u8,
    client_data_kind: ClientDataKind,
    force_high_s: bool,
) -> Result<WebAuthnAssertion, SoftPasskeyError> {
    let mut data = [0_u8; MAX_WEBAUTHN_DATA_LENGTH];
    let mut len = 0;
    append(&mut data, &mut len, &FIXTURE_RP_ID_HASH)?;
    append(&mut data, &mut len, &[flags])?;
    append(&mut data, &mut len, &[0; 4])?;
    if len != MIN_AUTH_DATA_LEN {
        return Err(SoftPasskeyError::AssertionTooLarge);
    }

    write_client_data(&mut data, &mut len, challenge_hash, client_data_kind)?;
    let auth_data = data
        .get(..MIN_AUTH_DATA_LEN)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let client_data_json = data
        .get(MIN_AUTH_DATA_LEN..len)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let client_data_hash = Sha256::digest(client_data_json);
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    let message_hash = hasher.finalize();
    let signature: P256Signature = passkey
        .signing_key
        .sign_prehash(&message_hash)
        .map_err(|_| SoftPasskeyError::SigningFailed)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature_bytes = signature.to_bytes();
    let (r_bytes, s_bytes) = signature_bytes.split_at(P256_COORDINATE_LENGTH);
    let mut r = [0_u8; P256_COORDINATE_LENGTH];
    let mut s = [0_u8; P256_COORDINATE_LENGTH];
    r.copy_from_slice(r_bytes);
    s.copy_from_slice(s_bytes);
    if force_high_s {
        s.fill(0xff);
    }

    let webauthn_data = List::new(data, len).ok_or(SoftPasskeyError::AssertionTooLarge)?;
    Ok(WebAuthnAssertion::new(
        r,
        s,
        passkey.pub_key_x,
        passkey.pub_key_y,
        webauthn_data,
    ))
}

fn write_client_data(
    data: &mut [u8; MAX_WEBAUTHN_DATA_LENGTH],
    len: &mut usize,
    challenge_hash: PayloadHash,
    kind: ClientDataKind,
) -> Result<(), SoftPasskeyError> {
    append(data, len, b"{\"type\":\"")?;
    match kind {
        ClientDataKind::WrongType => append(data, len, b"webauthn.create")?,
        _ => append(data, len, b"webauthn.get")?,
    }
    append(data, len, b"\",\"challenge\":\"")?;
    let challenge = base64url_32(challenge_hash.as_bytes());
    append(data, len, &challenge)?;
    append(data, len, b"\"")?;
    append(data, len, b",\"origin\":\"")?;
    append(data, len, FIXTURE_ORIGIN)?;
    append(data, len, b"\",\"crossOrigin\":false")?;

    match kind {
        ClientDataKind::DuplicateChallenge => {
            append(data, len, b",\"challenge\":\"")?;
            append(data, len, &challenge)?;
            append(data, len, b"\"")?;
        }
        ClientDataKind::NestedInjection => {
            append(data, len, b",\"extra\":{\"challenge\":\"")?;
            append(data, len, &challenge)?;
            append(data, len, b"\"}")?;
        }
        ClientDataKind::Valid | ClientDataKind::WrongType => {}
    }

    append(data, len, b"}")
}

fn append(buf: &mut [u8], len: &mut usize, bytes: &[u8]) -> Result<(), SoftPasskeyError> {
    let end = len
        .checked_add(bytes.len())
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let destination = buf
        .get_mut(*len..end)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    destination.copy_from_slice(bytes);
    *len = end;
    Ok(())
}
