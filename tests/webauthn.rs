//! Kernel-level `WebAuthn` open authorization tests.

#![cfg(feature = "webauthn")]
#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

mod support;

use hellas_kernel::{
    ApplyError, BlockHash, BlockHeight, CoinId, Context, Funding, Genesis, InvalidOpenReason, Key,
    List, MAX_EDGE_OUTPUTS, MAX_WEBAUTHN_DATA_LENGTH, OpenAuth, Parties, PayloadHash, Payout,
    ProtocolCode, Seal, SealPublicInputs, SealVerifier, Sig, SigVerifier, Terms, Tx,
    WebAuthnAssertion, WebAuthnData, p256_key, verify_webauthn_assertion,
};
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use support::{FixedStore, coin_id, party_one, payouts_two, state};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const MAKER_COIN: CoinId = coin_id(1);
const TAKER_COIN: CoinId = coin_id(2);
const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct MixedVerifier;

impl SigVerifier for MixedVerifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool {
        sig == Sig::placeholder(key, hash)
    }

    fn verify_open_auth(&self, auth: &OpenAuth, key: Key, hash: PayloadHash) -> bool {
        match auth {
            OpenAuth::Native(sig) => self.verify_sig(*sig, key, hash),
            OpenAuth::WebAuthn(assertion) => {
                verify_webauthn_assertion(assertion, key, hash).is_ok()
            }
        }
    }
}

impl SealVerifier for MixedVerifier {
    fn verify_seal(&self, _seal: Seal, _public: &SealPublicInputs<'_>) -> bool {
        false
    }
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("seed is a valid P-256 scalar")
}

fn make_terms(maker: Key, protocol: u8) -> Terms {
    let parties = Parties::new(maker, TAKER);
    let outputs: List<Payout, MAX_EDGE_OUTPUTS> = payouts_two(maker, 7, TAKER, 8);
    Terms::basic(ProtocolCode::new(protocol), parties, TIMEOUT, outputs)
}

const fn funding() -> Funding {
    Funding::new(party_one(MAKER_COIN), party_one(TAKER_COIN))
}

fn sign_webauthn(
    signing_key: &SigningKey,
    hash: PayloadHash,
    origin: &str,
) -> (WebAuthnAssertion, Key) {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let mut pub_key_x = [0_u8; PayloadHash::LENGTH];
    let mut pub_key_y = [0_u8; PayloadHash::LENGTH];
    pub_key_x.copy_from_slice(point.x().expect("P-256 point has x-coordinate"));
    pub_key_y.copy_from_slice(point.y().expect("P-256 point has y-coordinate"));
    let key = p256_key(&pub_key_x, &pub_key_y).expect("valid P-256 key");

    let mut authenticator_data = [0_u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xaa; 32]);
    authenticator_data[32] = 0x01;

    let challenge = base64url_32(hash.as_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    );

    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(authenticator_data);
    hasher.update(client_data_hash);
    let message_hash = hasher.finalize();

    let signature: P256Signature = signing_key
        .sign_prehash(&message_hash)
        .expect("P-256 prehash signing succeeds");
    let signature = signature.normalize_s().unwrap_or(signature);
    let sig_bytes = signature.to_bytes();
    let mut r = [0_u8; PayloadHash::LENGTH];
    let mut s = [0_u8; PayloadHash::LENGTH];
    r.copy_from_slice(&sig_bytes[..PayloadHash::LENGTH]);
    s.copy_from_slice(&sig_bytes[PayloadHash::LENGTH..]);

    let mut data = [0_u8; MAX_WEBAUTHN_DATA_LENGTH];
    data[..authenticator_data.len()].copy_from_slice(&authenticator_data);
    let client_data = client_data_json.as_bytes();
    let len = authenticator_data.len() + client_data.len();
    data[authenticator_data.len()..len].copy_from_slice(client_data);
    let webauthn_data: WebAuthnData =
        List::new(data, len).expect("test WebAuthn payload fits kernel bound");

    (
        WebAuthnAssertion::new(r, s, pub_key_x, pub_key_y, webauthn_data),
        key,
    )
}

#[test]
fn webauthn_open_auth_is_checked_in_kernel() {
    let maker_sk = keypair(1);
    let maker_key = p256_key_from_signing_key(&maker_sk);
    let funding = funding();
    let terms = make_terms(maker_key, 1);
    let hash = Tx::open_hash(&funding, &terms);
    let (maker_assertion, _) = sign_webauthn(&maker_sk, hash, "https://not-hellas.invalid");
    let taker_sig = Sig::placeholder(TAKER, hash);
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = Tx::open_with_auth(
        funding,
        terms,
        OpenAuth::webauthn(maker_assertion),
        OpenAuth::native(taker_sig),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );

    let event = state
        .apply(CONTEXT, &MixedVerifier, &open)
        .expect("WebAuthn maker + native taker opens edge");
    assert_eq!(
        state.store().edge(edge).map(hellas_kernel::Edge::value),
        Some(15)
    );
    let _ = event;
}

#[test]
fn webauthn_open_rejects_wrong_challenge() {
    let maker_sk = keypair(1);
    let maker_key = p256_key_from_signing_key(&maker_sk);
    let funding = funding();
    let terms = make_terms(maker_key, 1);
    let wrong_terms = make_terms(maker_key, 2);
    let hash = Tx::open_hash(&funding, &terms);
    let wrong_hash = Tx::open_hash(&funding, &wrong_terms);
    let (maker_assertion, _) = sign_webauthn(&maker_sk, wrong_hash, "https://example.invalid");
    let taker_sig = Sig::placeholder(TAKER, hash);
    let edge = Tx::edge_id_of(&funding, &terms);
    let open = Tx::open_with_auth(
        funding,
        terms,
        OpenAuth::webauthn(maker_assertion),
        OpenAuth::native(taker_sig),
    );
    let mut state = state(
        FixedStore::empty([MAKER_COIN, TAKER_COIN], [edge]),
        [
            Genesis::coin(MAKER_COIN, maker_key, 10),
            Genesis::coin(TAKER_COIN, TAKER, 5),
        ],
    );

    assert_eq!(
        state.apply(CONTEXT, &MixedVerifier, &open),
        Err(ApplyError::InvalidOpen {
            output: edge,
            reason: InvalidOpenReason::BadSignature,
        }),
    );
}

fn p256_key_from_signing_key(signing_key: &SigningKey) -> Key {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let mut pub_key_x = [0_u8; PayloadHash::LENGTH];
    let mut pub_key_y = [0_u8; PayloadHash::LENGTH];
    pub_key_x.copy_from_slice(point.x().expect("P-256 point has x-coordinate"));
    pub_key_y.copy_from_slice(point.y().expect("P-256 point has y-coordinate"));
    p256_key(&pub_key_x, &pub_key_y).expect("valid P-256 key")
}

fn base64url_32(input: &[u8; PayloadHash::LENGTH]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(43);
    let mut i = 0;
    while i + 3 <= input.len() {
        let bits =
            (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8) | u32::from(input[i + 2]);
        out.push(char::from(TABLE[((bits >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((bits >> 12) & 0x3f) as usize]));
        out.push(char::from(TABLE[((bits >> 6) & 0x3f) as usize]));
        out.push(char::from(TABLE[(bits & 0x3f) as usize]));
        i += 3;
    }
    let bits = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
    out.push(char::from(TABLE[((bits >> 18) & 0x3f) as usize]));
    out.push(char::from(TABLE[((bits >> 12) & 0x3f) as usize]));
    out.push(char::from(TABLE[((bits >> 6) & 0x3f) as usize]));
    out
}
