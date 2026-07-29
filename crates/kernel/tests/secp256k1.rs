//! Real-crypto smoke test for the [`Secp256k1Verifier`].
//!
//! Constructs a real keypair, signs the kernel's canonical close hash with
//! ECDSA, and asserts that the kernel accepts the resulting Mutual close
//! through the production verifier. Mutating any of (sig, key, hash) or
//! swapping the kernel for a `RejectVerifier` causes rejection.

#![cfg(feature = "secp256k1")]
#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    ApplyError, Auth, BlockHash, BlockHeight, CloseKind, CoinId, Context, EdgeId, Funding, Genesis,
    InvalidProofReason, Key, List, MAX_EDGE_OUTPUTS, Parties, Payout, Proof, ProtocolCode, Seal,
    SealPublicInputs, SealVerifier, Secp256k1Verifier, Sig, State, Terms, Tx,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use support::{FixedStore, list};

const TIMEOUT: BlockHeight = BlockHeight::new(2);
const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

fn keypair(seed: u8) -> (SecretKey, Key) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([seed; 32]).expect("non-zero seed");
    let public = secret.public_key(&secp);
    (secret, Key::from_bytes(public.serialize()))
}

/// Real ECDSA authorization from `secret` over `hash`.
fn sign(secret: &SecretKey, hash: hellas_kernel::PayloadHash) -> Auth {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash.to_bytes());
    let signature = secp.sign_ecdsa(message, secret);
    Auth::native(Sig::from_bytes(signature.serialize_compact()))
}

fn payouts(maker: Key, taker: Key) -> List<Payout, MAX_EDGE_OUTPUTS> {
    support::payouts(&[(maker, 7), (taker, 8)])
}

#[test]
fn mutual_with_real_ecdsa_signatures_closes_under_production_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let timeout_outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, timeout_outputs);
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(&funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        sign(&maker_sk, open_hash),
        sign(&taker_sk, open_hash),
    );
    let close_hash = Tx::payload_hash(edge, CloseKind::Mutual, terms_hash, &outputs);
    let proof = Proof::mutual(sign(&maker_sk, close_hash), sign(&taker_sk, close_hash));
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let close = Tx::close(edge, proof, outputs);
    let store = FixedStore::empty([maker_coin, taker_coin, maker_out, taker_out], [edge]);
    let mut state = State::genesis(
        store,
        &[
            Genesis::coin(maker_coin, maker_pk, 10),
            Genesis::coin(taker_coin, taker_pk, 5),
        ],
    )
    .expect("genesis seeds the store");
    let verifier = Secp256k1Verifier::new();

    state
        .apply(CONTEXT, &verifier, &open)
        .expect("open accepted");
    let event = state
        .apply(CONTEXT, &verifier, &close)
        .expect("mutual with valid ECDSA accepted");
    assert_eq!(state.store().edge(edge), None);
    let _ = event;
}

#[test]
fn forged_signature_is_rejected_by_real_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs.clone());
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(list(&[maker_coin]), list(&[taker_coin]));
    let edge = Tx::edge_id_of(&funding, &terms);
    // Open is honestly authorized by both parties; the forgery happens on
    // the close side below (the test's actual subject).
    let open_hash = Tx::open_hash(&funding, &terms);
    let open = Tx::open(
        funding,
        terms,
        sign(&maker_sk, open_hash),
        sign(&taker_sk, open_hash),
    );
    let close_hash = Tx::payload_hash(edge, CloseKind::Mutual, terms_hash, &outputs);
    // Sign with maker's key in *both* slots — taker's signature is forged.
    let proof = Proof::mutual(sign(&maker_sk, close_hash), sign(&maker_sk, close_hash));
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let close = Tx::close(edge, proof, outputs);
    let store = FixedStore::empty([maker_coin, taker_coin, maker_out, taker_out], [edge]);
    let mut state = State::genesis(
        store,
        &[
            Genesis::coin(maker_coin, maker_pk, 10),
            Genesis::coin(taker_coin, taker_pk, 5),
        ],
    )
    .expect("genesis seeds the store");
    let verifier = Secp256k1Verifier::new();

    state
        .apply(CONTEXT, &verifier, &open)
        .expect("open accepted");
    assert_eq!(
        state.apply(CONTEXT, &verifier, &close),
        Err(ApplyError::InvalidProof {
            input: edge,
            reason: InvalidProofReason::BadSignature,
        }),
    );
}

#[test]
fn production_secp256k1_verifier_rejects_dispute_seals() {
    let (_, maker_pk) = keypair(1);
    let (_, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs.clone());
    let edge = EdgeId::from_bytes([9; EdgeId::LENGTH]);
    let hash = Tx::payload_hash(edge, CloseKind::Violation, terms.hash(), &outputs);
    let seal = Seal::placeholder(terms.protocol(), CloseKind::Violation, hash);
    let public = SealPublicInputs {
        edge_id: edge,
        terms: &terms,
        payouts: &outputs,
    };

    assert!(!Secp256k1Verifier::new().verify_seal(seal, &public));
    assert_eq!(CloseKind::Mutual.tag(), 0);
    assert_eq!(CloseKind::Timeout.tag(), 1);
    assert_eq!(CloseKind::Violation.tag(), 2);
    assert_eq!(seal.to_bytes(), *seal.as_bytes());
}
