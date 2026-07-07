//! Domain types used by the Hellas chain and light-client API.
//!
//! # `WebAuthn` policy divergence
//!
//! [`Transaction::verify_signature`] enforces a browser-shaped policy:
//! UP *and* UV flags, an HTTPS origin allowlist, and `rpIdHash` binding.
//! The kernel's open-authorization verifier (`hellas-kernel`, feature
//! `webauthn`) is deliberately looser — UP *or* UV, origin ignored — and
//! treats `WebAuthn` as a portable P-256 transaction-signing envelope.
//! They are different products; do not wire one where the other is
//! expected.

/// Digest used by chain-facing APIs.
pub use commonware_cryptography::sha256::Digest;

/// Decoding helper for domain types.
pub use commonware_codec::DecodeExt;
/// Encoding helper for domain types.
pub use commonware_codec::Encode;

use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::BytesMut;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
/// Signing helper for domain key types.
pub use commonware_cryptography::Signer;
use commonware_cryptography::{Hasher, Sha256, ed25519, secp256r1};
use p256::ecdsa::signature::Verifier as _;
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256 as Sha2};
use url::Url;

/// Validator public key.
pub type PublicKey = ed25519::PublicKey;
/// Validator private key.
pub type PrivateKey = ed25519::PrivateKey;
/// User public key.
pub type UserPublicKey = secp256r1::standard::PublicKey;
/// User signature.
pub type UserSignature = secp256r1::standard::Signature;
/// Object identifier in the chain state.
pub type ObjectId = Digest;

/// User address derived from a secp256r1 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(UserPublicKey);

impl Address {
    /// Returns the public key encoded by this address.
    #[must_use]
    pub const fn public_key(&self) -> &UserPublicKey {
        &self.0
    }

    /// Consumes the address and returns its public key.
    #[must_use]
    pub const fn into_public_key(self) -> UserPublicKey {
        self.0
    }
}

impl From<UserPublicKey> for Address {
    fn from(pk: UserPublicKey) -> Self {
        Self(pk)
    }
}

impl AsRef<UserPublicKey> for Address {
    fn as_ref(&self) -> &UserPublicKey {
        &self.0
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use commonware_codec::Encode;
        f.write_str(&bs58::encode(self.0.encode()).into_string())
    }
}

impl core::str::FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(AddressError::Base58)?;
        let pk = UserPublicKey::decode(bytes.as_slice()).map_err(|_| AddressError::InvalidKey)?;
        Ok(Self(pk))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
/// Address parsing error.
pub enum AddressError {
    /// Invalid base58 encoding.
    #[error("invalid base58: {0}")]
    Base58(bs58::decode::Error),
    /// Invalid secp256r1 public key bytes.
    #[error("invalid secp256r1 public key")]
    InvalidKey,
}

impl FixedSize for Address {
    const SIZE: usize = UserPublicKey::SIZE;
}

impl Write for Address {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl Read for Address {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(UserPublicKey::read(buf)?))
    }
}

/// Bounded array-backed list for chain wire payloads.
///
/// Local to this crate so the commonware codec impls below can live
/// beside the type (orphan rule); the chain wire format is independent
/// of the kernel's canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounded<T, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T, const N: usize> Bounded<T, N> {
    /// Creates a bounded list from a backing array and live length.
    #[must_use]
    pub fn new(items: [T; N], len: usize) -> Option<Self> {
        (len <= N).then_some(Self { items, len })
    }

    /// Borrows the live entries.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.items.get(..self.len).unwrap_or(&self.items)
    }

    /// Returns the number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the list has no live entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over the live entries.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Bounded<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Write, const N: usize> Write for Bounded<T, N> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.as_slice().write(buf);
    }
}

impl<T: EncodeSize, const N: usize> EncodeSize for Bounded<T, N> {
    fn encode_size(&self) -> usize {
        self.as_slice().encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.as_slice().encode_inline_size()
    }
}

impl<const N: usize> Read for Bounded<u8, N> {
    type Cfg = (RangeCfg<usize>, ());

    fn read_cfg(buf: &mut impl bytes::Buf, (range, _cfg): &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, range)?;
        let mut items = [0_u8; N];
        for slot in items.iter_mut().take(len) {
            *slot = u8::read(buf)?;
        }
        Ok(Self { items, len })
    }
}

impl<const N: usize> Read for Bounded<ObjectId, N> {
    type Cfg = (RangeCfg<usize>, ());

    fn read_cfg(buf: &mut impl bytes::Buf, (range, _cfg): &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, range)?;
        let mut items = [ObjectId::from([0; 32]); N];
        for slot in items.iter_mut().take(len) {
            *slot = ObjectId::read(buf)?;
        }
        Ok(Self { items, len })
    }
}

/// Threshold signature variant used by consensus.
#[cfg(feature = "domain-consensus")]
pub type ThresholdVariant = commonware_cryptography::bls12381::primitives::variant::MinPk;
/// Threshold signature share.
#[cfg(feature = "domain-consensus")]
pub type ThresholdShare = commonware_cryptography::bls12381::primitives::group::Share;
/// Threshold sharing polynomial.
#[cfg(feature = "domain-consensus")]
pub type ThresholdPolynomial =
    commonware_cryptography::bls12381::primitives::sharing::Sharing<ThresholdVariant>;
/// Consensus signing scheme.
#[cfg(feature = "domain-consensus")]
pub type Scheme = commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme<
    PublicKey,
    ThresholdVariant,
>;
/// Consensus context.
#[cfg(feature = "domain-consensus")]
pub type Context = commonware_consensus::simplex::types::Context<Digest, PublicKey>;
/// Consensus activity event.
#[cfg(feature = "domain-consensus")]
pub type Activity = commonware_consensus::simplex::types::Activity<Scheme, Digest>;

/// The epoch number used in consensus.
///
/// No reconfiguration - the network always starts in epoch 0.
#[cfg(feature = "domain-consensus")]
pub const EPOCH: commonware_consensus::types::Epoch = commonware_consensus::types::Epoch::zero();

/// `WebAuthn` policy version.
pub const WEBAUTHN_POLICY_VERSION: u8 = 1;
/// Chain identifier committed into `WebAuthn` challenges.
pub const WEBAUTHN_CHAIN_ID: &[u8] = b"hellas-devnet-1";
/// Whether `WebAuthn` user presence is required.
pub const WEBAUTHN_REQUIRE_UP: bool = true;
/// Whether `WebAuthn` user verification is required.
pub const WEBAUTHN_REQUIRE_UV: bool = true;
/// Whether cross-origin assertions are rejected.
pub const WEBAUTHN_REQUIRE_CROSS_ORIGIN_FALSE: bool = true;
/// Whether HTTPS origins are required.
pub const WEBAUTHN_REQUIRE_HTTPS_ORIGIN: bool = true;
/// Whether HTTP localhost origins are allowed.
pub const WEBAUTHN_ALLOW_HTTP_LOCALHOST_ORIGIN: bool = true;
/// Whether attested credential data is allowed.
pub const WEBAUTHN_ALLOW_ATTESTED_CREDENTIAL_DATA: bool = false;
/// Whether `WebAuthn` extensions are allowed.
pub const WEBAUTHN_ALLOW_EXTENSIONS: bool = false;
/// Required `WebAuthn` client data type.
pub const WEBAUTHN_TYPE_GET: &str = "webauthn.get";

/// Domain separator for `WebAuthn` challenges.
pub const CHALLENGE_DOMAIN: &[u8] = b"hellas-webauthn-challenge-v1";
/// Transfer transaction tag.
pub const TRANSFER_TAG: u8 = 0x01;
/// Merge transaction tag.
pub const MERGE_TAG: u8 = 0x02;
/// Maximum merge input count.
pub const MAX_MERGE_INPUTS: usize = 32;
/// Maximum transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 256;
/// Default genesis allocation balance.
pub const GENESIS_BALANCE: u64 = 100_000_000;
/// Minimum `WebAuthn` authenticator data length.
pub const MIN_AUTHENTICATOR_DATA_LEN: usize = 37;
/// Maximum `WebAuthn` authenticator data length.
pub const MAX_AUTHENTICATOR_DATA_LEN: usize = 256;
/// Maximum `WebAuthn` client data JSON length.
pub const MAX_CLIENT_DATA_JSON_LEN: usize = 1024;

/// Bounded authenticator data carried by a `WebAuthn` signature.
pub type AuthenticatorData = Bounded<u8, MAX_AUTHENTICATOR_DATA_LEN>;
/// Bounded client data JSON carried by a `WebAuthn` signature.
pub type ClientDataJson = Bounded<u8, MAX_CLIENT_DATA_JSON_LEN>;
/// Bounded merge input list.
pub type MergeInputs = Bounded<ObjectId, MAX_MERGE_INPUTS>;

/// Returns the deterministic object id for a genesis allocation.
#[must_use]
pub fn genesis_object_id(validator_index: u16) -> ObjectId {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"hellas-genesis");
    validator_index.write(&mut buf);
    Sha256::hash(&buf)
}

/// Returns the deterministic object id for a transaction output.
#[must_use]
pub fn output_object_id(tx_digest: &Digest, output_index: u8) -> ObjectId {
    let mut buf = BytesMut::new();
    tx_digest.write(&mut buf);
    output_index.write(&mut buf);
    Sha256::hash(&buf)
}

fn challenge_prefix(buf: &mut BytesMut, tag: u8) {
    const WEBAUTHN_CHAIN_ID_LEN: u8 = 14;

    buf.extend_from_slice(CHALLENGE_DOMAIN);
    WEBAUTHN_POLICY_VERSION.write(buf);
    WEBAUTHN_CHAIN_ID_LEN.write(buf);
    buf.extend_from_slice(WEBAUTHN_CHAIN_ID);
    tag.write(buf);
}

/// Returns the `WebAuthn` challenge for a transfer transaction.
#[must_use]
pub fn transfer_challenge(input: &ObjectId, recipient: &Address, amount: u64) -> Digest {
    let mut buf = BytesMut::new();
    challenge_prefix(&mut buf, TRANSFER_TAG);
    input.write(&mut buf);
    recipient.write(&mut buf);
    amount.write(&mut buf);
    Sha256::hash(&buf)
}

/// Returns the `WebAuthn` challenge for a merge transaction.
#[must_use]
pub fn merge_challenge(sorted_inputs: &[ObjectId]) -> Digest {
    let mut buf = BytesMut::new();
    challenge_prefix(&mut buf, MERGE_TAG);
    sorted_inputs.write(&mut buf);
    Sha256::hash(&buf)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha2::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
fn secp256r1_key_from_material(material: &[u8]) -> p256::ecdsa::SigningKey {
    let mut salt = 0u8;
    loop {
        let mut hasher = Sha2::new();
        hasher.update(b"hellas-secp256r1-material-v1");
        hasher.update(material);
        hasher.update([salt]);
        let raw: [u8; 32] = hasher.finalize().into();
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&raw) {
            return key;
        }
        salt = salt.wrapping_add(1);
    }
}

fn localhost_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn origin_is_allowed(url: &Url) -> bool {
    let scheme = url.scheme();
    (scheme == "https")
        || (WEBAUTHN_ALLOW_HTTP_LOCALHOST_ORIGIN
            && scheme == "http"
            && url.host_str().is_some_and(localhost_host))
}

fn lower_host_hash(host: &str) -> Option<[u8; 32]> {
    const MAX_RP_ID_LEN: usize = 253;

    if host.is_empty() || host.len() > MAX_RP_ID_LEN {
        return None;
    }
    let mut lower = [0_u8; MAX_RP_ID_LEN];
    for (dst, src) in lower.iter_mut().zip(host.bytes()) {
        *dst = src.to_ascii_lowercase();
    }
    Some(sha256_bytes(&lower[..host.len()]))
}

/// Returns the SHA-256 RP ID hash for a permitted `WebAuthn` origin.
#[must_use]
pub fn rp_id_hash_from_origin(origin: &str) -> Option<[u8; 32]> {
    let url = Url::parse(origin).ok()?;
    if WEBAUTHN_REQUIRE_HTTPS_ORIGIN && !origin_is_allowed(&url) {
        return None;
    }
    lower_host_hash(url.host_str()?)
}

// --- Coin (gated) ---

#[derive(Clone, Debug, PartialEq, Eq)]
/// Chain coin object.
pub struct Coin {
    /// Coin owner.
    pub owner: Address,
    /// Coin value.
    pub value: u64,
}

impl FixedSize for Coin {
    const SIZE: usize = Address::SIZE + u64::SIZE;
}

impl Write for Coin {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.owner.write(buf);
        self.value.write(buf);
    }
}

impl Read for Coin {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            owner: Address::read(buf)?,
            value: u64::read(buf)?,
        })
    }
}

// --- WebAuthnSignature (gated) ---

#[derive(Clone, Debug, PartialEq, Eq)]
/// `WebAuthn` signature payload committed by a transaction.
pub struct WebAuthnSignature {
    /// Raw secp256r1 ECDSA signature.
    pub signature: UserSignature,
    /// `WebAuthn` authenticator data.
    pub authenticator_data: AuthenticatorData,
    /// `WebAuthn` client data JSON.
    pub client_data_json: ClientDataJson,
}

fn byte_list_from_slice<const N: usize>(bytes: &[u8]) -> Option<Bounded<u8, N>> {
    if bytes.len() > N {
        return None;
    }
    let mut items = [0_u8; N];
    items[..bytes.len()].copy_from_slice(bytes);
    Bounded::new(items, bytes.len())
}

impl WebAuthnSignature {
    /// Builds a bounded `WebAuthn` signature payload.
    #[must_use]
    pub fn new(
        signature: UserSignature,
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> Option<Self> {
        if authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN || client_data_json.is_empty() {
            return None;
        }
        Some(Self {
            signature,
            authenticator_data: byte_list_from_slice(authenticator_data)?,
            client_data_json: byte_list_from_slice(client_data_json)?,
        })
    }
}

impl EncodeSize for WebAuthnSignature {
    fn encode_size(&self) -> usize {
        self.signature.encode_size()
            + self.authenticator_data.encode_size()
            + self.client_data_json.encode_size()
    }
}

impl Write for WebAuthnSignature {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signature.write(buf);
        self.authenticator_data.write(buf);
        self.client_data_json.write(buf);
    }
}

impl Read for WebAuthnSignature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            signature: UserSignature::read(buf)?,
            authenticator_data: AuthenticatorData::read_cfg(
                buf,
                &(
                    RangeCfg::new(MIN_AUTHENTICATOR_DATA_LEN..=MAX_AUTHENTICATOR_DATA_LEN),
                    (),
                ),
            )?,
            client_data_json: ClientDataJson::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_CLIENT_DATA_JSON_LEN), ()),
            )?,
        })
    }
}

// --- Transaction (gated) ---

// Keep transactions inline/stack-allocated to avoid per-transaction heap churn in hot paths.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
/// Chain transaction.
pub enum Transaction {
    /// Transfer part or all of one input coin to a recipient.
    Transfer {
        /// Input coin object id.
        input: ObjectId,
        /// Recipient address.
        recipient: Address,
        /// Amount transferred to the recipient.
        amount: u64,
        /// Owner signature over the transfer challenge.
        signature: WebAuthnSignature,
    },
    /// Merge multiple input coins owned by the same address.
    MergeCoin {
        /// Sorted input coin object ids.
        inputs: MergeInputs,
        /// Owner signature over the merge challenge.
        signature: WebAuthnSignature,
    },
}

fn merge_inputs_are_strictly_sorted(inputs: &[ObjectId]) -> bool {
    inputs.windows(2).all(|pair| pair[0] < pair[1])
}

fn client_data_rp_hash(bytes: &[u8], expected_challenge: &[u8]) -> Option<[u8; 32]> {
    let json: JsonValue = serde_json::from_slice(bytes).ok()?;
    let obj = json.as_object()?;
    let ty = obj.get("type")?.as_str()?;
    let challenge = obj.get("challenge")?.as_str()?;
    let origin = obj.get("origin")?.as_str()?;
    let cross_origin = obj
        .get("crossOrigin")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    if ty != WEBAUTHN_TYPE_GET {
        return None;
    }
    if WEBAUTHN_REQUIRE_CROSS_ORIGIN_FALSE && cross_origin {
        return None;
    }
    let mut decoded_challenge = [0_u8; 32];
    let Ok(decoded_challenge) = Base64UrlUnpadded::decode(challenge, &mut decoded_challenge) else {
        return None;
    };
    if decoded_challenge != expected_challenge {
        return None;
    }
    rp_id_hash_from_origin(origin)
}

fn verify_webauthn_signature(
    expected_challenge: &[u8],
    signature: &WebAuthnSignature,
    owner: &UserPublicKey,
) -> bool {
    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;
    const FLAG_AT: u8 = 0x40;
    const FLAG_ED: u8 = 0x80;

    let authenticator_data = signature.authenticator_data.as_slice();
    let client_data_json = signature.client_data_json.as_slice();
    if authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN || client_data_json.is_empty() {
        return false;
    }

    let Some(rp_hash) = client_data_rp_hash(client_data_json, expected_challenge) else {
        return false;
    };
    if authenticator_data[..32] != rp_hash {
        return false;
    }

    let flags = authenticator_data[32];
    if WEBAUTHN_REQUIRE_UP && (flags & FLAG_UP) == 0 {
        return false;
    }
    if WEBAUTHN_REQUIRE_UV && (flags & FLAG_UV) == 0 {
        return false;
    }
    if !WEBAUTHN_ALLOW_ATTESTED_CREDENTIAL_DATA && (flags & FLAG_AT) != 0 {
        return false;
    }
    if !WEBAUTHN_ALLOW_EXTENSIONS && (flags & FLAG_ED) != 0 {
        return false;
    }

    let client_hash = sha256_bytes(client_data_json);
    let mut msg = [0_u8; MAX_AUTHENTICATOR_DATA_LEN + 32];
    let msg_len = authenticator_data.len() + client_hash.len();
    msg[..authenticator_data.len()].copy_from_slice(authenticator_data);
    msg[authenticator_data.len()..msg_len].copy_from_slice(&client_hash);

    let Ok(verifying_key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(owner.as_ref()) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature.signature.as_ref()) else {
        return false;
    };
    verifying_key.verify(&msg[..msg_len], &sig).is_ok()
}

impl Transaction {
    /// Verifies the transaction `WebAuthn` signature against `owner`.
    #[must_use]
    pub fn verify_signature(&self, owner: &Address) -> bool {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                let expected = transfer_challenge(input, recipient, *amount);
                verify_webauthn_signature(expected.as_ref(), signature, owner.public_key())
            }
            Self::MergeCoin { inputs, signature } => {
                let expected = merge_challenge(inputs.as_slice());
                verify_webauthn_signature(expected.as_ref(), signature, owner.public_key())
            }
        }
    }

    /// Returns whether merge transaction inputs use canonical ordering.
    #[must_use]
    pub fn merge_is_canonical(&self) -> bool {
        match self {
            Self::Transfer { .. } => true,
            Self::MergeCoin { inputs, .. } => merge_inputs_are_strictly_sorted(inputs.as_slice()),
        }
    }
}

#[cfg(test)]
impl From<ed25519::PublicKey> for Address {
    fn from(pk: ed25519::PublicKey) -> Self {
        let key = secp256r1_key_from_material(pk.as_ref());
        addr_from_signing_key(&key)
    }
}

#[cfg(test)]
impl Transaction {
    /// Builds a signed transfer transaction for tests.
    #[must_use]
    pub fn transfer(
        key: &PrivateKey,
        input: ObjectId,
        recipient: Address,
        amount: u64,
    ) -> Option<Self> {
        let secp_key = secp256r1_key_from_material(key.public_key().as_ref());
        let challenge = transfer_challenge(&input, &recipient, amount);
        Some(Self::Transfer {
            input,
            recipient,
            amount,
            signature: mock_webauthn_sign(&secp_key, &challenge)?,
        })
    }

    /// Builds a signed merge transaction for tests.
    #[must_use]
    pub fn merge(key: &PrivateKey, inputs: &[ObjectId]) -> Option<Self> {
        let mut items = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
        if inputs.len() > items.len() {
            return None;
        }
        items[..inputs.len()].copy_from_slice(inputs);
        items[..inputs.len()].sort();
        let inputs = MergeInputs::new(items, inputs.len())?;
        let secp_key = secp256r1_key_from_material(key.public_key().as_ref());
        let challenge = merge_challenge(inputs.as_slice());
        Some(Self::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&secp_key, &challenge)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                u8::SIZE
                    + input.encode_size()
                    + recipient.encode_size()
                    + amount.encode_size()
                    + signature.encode_size()
            }
            Self::MergeCoin { inputs, signature } => {
                u8::SIZE + inputs.encode_size() + signature.encode_size()
            }
        }
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Transfer {
                input,
                recipient,
                amount,
                signature,
            } => {
                0u8.write(buf);
                input.write(buf);
                recipient.write(buf);
                amount.write(buf);
                signature.write(buf);
            }
            Self::MergeCoin { inputs, signature } => {
                1u8.write(buf);
                inputs.write(buf);
                signature.write(buf);
            }
        }
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Transfer {
                input: ObjectId::read(buf)?,
                recipient: Address::read(buf)?,
                amount: u64::read(buf)?,
                signature: WebAuthnSignature::read(buf)?,
            }),
            1 => Ok(Self::MergeCoin {
                inputs: MergeInputs::read_cfg(buf, &(RangeCfg::new(2..=MAX_MERGE_INPUTS), ()))?,
                signature: WebAuthnSignature::read(buf)?,
            }),
            _ => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
/// Derives a deterministic secp256r1 signing key from `seed`.
#[must_use]
pub fn secp256r1_key_from_seed(seed: u64) -> p256::ecdsa::SigningKey {
    secp256r1_key_from_material(&seed.to_le_bytes())
}

#[cfg(test)]
/// Derives a chain address from a secp256r1 signing key.
#[must_use]
pub fn addr_from_signing_key(key: &p256::ecdsa::SigningKey) -> Address {
    Address::from(UserPublicKey::from(key.verifying_key().to_owned()))
}

#[cfg(test)]
const MOCK_WEBAUTHN_ORIGIN: &str = "https://wallet.hellas.ai";

#[cfg(test)]
fn push_bytes(dst: &mut [u8], len: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = len.checked_add(bytes.len())?;
    if end > dst.len() {
        return None;
    }
    dst[*len..end].copy_from_slice(bytes);
    *len = end;
    Some(())
}

#[cfg(test)]
fn client_data_json_for_origin(challenge: &Digest, origin: &str) -> Option<ClientDataJson> {
    let mut challenge_buf = [0_u8; 43];
    let challenge_b64 = Base64UrlUnpadded::encode(challenge.as_ref(), &mut challenge_buf).ok()?;
    let mut json = [0_u8; MAX_CLIENT_DATA_JSON_LEN];
    let mut len = 0;
    push_bytes(&mut json, &mut len, br#"{"type":""#)?;
    push_bytes(&mut json, &mut len, WEBAUTHN_TYPE_GET.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","challenge":""#)?;
    push_bytes(&mut json, &mut len, challenge_b64.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","origin":""#)?;
    push_bytes(&mut json, &mut len, origin.as_bytes())?;
    push_bytes(&mut json, &mut len, br#"","crossOrigin":false}"#)?;
    byte_list_from_slice(&json[..len])
}

#[cfg(test)]
/// Creates a deterministic `WebAuthn` signature for tests using `origin`.
#[must_use]
pub fn mock_webauthn_sign_with_origin(
    key: &p256::ecdsa::SigningKey,
    challenge: &Digest,
    origin: &str,
) -> Option<WebAuthnSignature> {
    use p256::ecdsa::signature::Signer as _;

    let rp_id_hash = rp_id_hash_from_origin(origin)?;
    let client_data_json = client_data_json_for_origin(challenge, origin)?;

    let mut authenticator_data = [0_u8; MIN_AUTHENTICATOR_DATA_LEN];
    authenticator_data[..32].copy_from_slice(&rp_id_hash);
    authenticator_data[32] = 0x05; // UP | UV

    let client_hash = sha256_bytes(client_data_json.as_slice());
    let mut msg = [0_u8; MIN_AUTHENTICATOR_DATA_LEN + 32];
    msg[..authenticator_data.len()].copy_from_slice(&authenticator_data);
    msg[authenticator_data.len()..].copy_from_slice(&client_hash);

    let signed: p256::ecdsa::Signature = key.sign(&msg);
    let normalized = signed.normalize_s().unwrap_or(signed);
    let Ok(signature) = UserSignature::decode(normalized.to_bytes().as_ref()) else {
        return None;
    };

    Some(WebAuthnSignature {
        signature,
        authenticator_data: byte_list_from_slice(&authenticator_data)?,
        client_data_json,
    })
}

#[cfg(test)]
/// Creates a deterministic `WebAuthn` signature for tests.
#[must_use]
pub fn mock_webauthn_sign(
    key: &p256::ecdsa::SigningKey,
    challenge: &Digest,
) -> Option<WebAuthnSignature> {
    mock_webauthn_sign_with_origin(key, challenge, MOCK_WEBAUTHN_ORIGIN)
}

#[cfg(test)]
#[allow(clippy::disallowed_types, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    fn test_merge_inputs(values: &[ObjectId]) -> MergeInputs {
        let mut items = [ObjectId::from([0; 32]); MAX_MERGE_INPUTS];
        items[..values.len()].copy_from_slice(values);
        MergeInputs::new(items, values.len()).expect("test merge inputs fit")
    }

    fn sample_transfer(key: &p256::ecdsa::SigningKey) -> (Address, Transaction) {
        let sender_addr = addr_from_signing_key(key);
        let recipient = addr_from_signing_key(&secp256r1_key_from_seed(2));
        let input = Digest::from([7; 32]);
        let challenge = transfer_challenge(&input, &recipient, 5);
        let signature = mock_webauthn_sign(key, &challenge).expect("mock signature");
        (
            sender_addr,
            Transaction::Transfer {
                input,
                recipient,
                amount: 5,
                signature,
            },
        )
    }

    #[test]
    fn coin_codec_roundtrip() {
        let owner = addr_from_signing_key(&secp256r1_key_from_seed(1));
        let coin = Coin { owner, value: 123 };
        let encoded = coin.encode();
        let decoded = Coin::decode(encoded).expect("coin decode");
        assert_eq!(decoded, coin);
    }

    #[test]
    fn transfer_codec_roundtrip() {
        let key = secp256r1_key_from_seed(1);
        let (_, tx) = sample_transfer(&key);
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn merge_codec_roundtrip() {
        let key = secp256r1_key_from_seed(1);
        let mut values = [
            Digest::from([3; 32]),
            Digest::from([1; 32]),
            Digest::from([2; 32]),
        ];
        values.sort();
        let inputs = test_merge_inputs(&values);
        let challenge = merge_challenge(inputs.as_slice());
        let tx = Transaction::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&key, &challenge).expect("mock signature"),
        };
        let encoded = tx.encode();
        let decoded = Transaction::decode(encoded).expect("tx decode");
        assert_eq!(decoded.encode(), tx.encode());
    }

    #[test]
    fn signature_verification_succeeds_with_correct_key() {
        let key = secp256r1_key_from_seed(1);
        let (sender, tx) = sample_transfer(&key);
        assert!(tx.verify_signature(&sender));
    }

    #[test]
    fn signature_verification_fails_with_wrong_key() {
        let key = secp256r1_key_from_seed(1);
        let wrong = addr_from_signing_key(&secp256r1_key_from_seed(2));
        let (_, tx) = sample_transfer(&key);
        assert!(!tx.verify_signature(&wrong));
    }

    #[test]
    fn signature_verification_fails_with_wrong_origin() {
        let key = secp256r1_key_from_seed(1);
        let (sender, mut tx) = sample_transfer(&key);
        let Transaction::Transfer {
            input,
            recipient,
            amount,
            signature,
        } = &mut tx
        else {
            panic!("expected transfer")
        };
        let challenge = transfer_challenge(input, recipient, *amount);
        signature.client_data_json =
            client_data_json_for_origin(&challenge, "https://evil.example").expect("client data");
        assert!(!tx.verify_signature(&sender));
    }

    #[test]
    fn address_base58_roundtrip() {
        let addr = addr_from_signing_key(&secp256r1_key_from_seed(42));
        let encoded = addr.to_string();
        let decoded: Address = encoded.parse().expect("base58 decode");
        assert_eq!(addr, decoded);
    }

    #[test]
    fn merge_inputs_canonical_check() {
        let key = secp256r1_key_from_seed(1);
        let inputs = test_merge_inputs(&[Digest::from([3; 32]), Digest::from([1; 32])]);
        let challenge = merge_challenge(inputs.as_slice());
        let tx = Transaction::MergeCoin {
            inputs,
            signature: mock_webauthn_sign(&key, &challenge).expect("mock signature"),
        };
        assert!(!tx.merge_is_canonical());
    }
}
