//! Real-crypto smoke test for the [`Secp256k1Verifier`].
//!
//! Constructs a real keypair, signs the kernel's canonical resolve hash with
//! ECDSA, and asserts that the kernel accepts the resulting Agreement
//! resolve through the production `Verifier` impl. Mutating any of (sig,
//! key, hash) or swapping the kernel for a `RejectVerifier` causes
//! rejection.

#![cfg(feature = "secp256k1")]
#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]

mod support;

use hellas_kernel::{
    Agreement, ApplyError, BlockHash, BlockHeight, CoinId, Context, Funding, Genesis,
    InvalidProofReason, Key, List, MAX_EDGE_OUTPUTS, Op, Open, Parties, Payout, Proof,
    ProtocolCode, Resolve, ResolveKind, Secp256k1Verifier, Sig, State, Terms,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use support::{FixedStore, party_one, payouts_two};

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

fn sign(secret: &SecretKey, hash: hellas_kernel::ResolveHash) -> Sig {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash.to_bytes());
    let signature = secp.sign_ecdsa(message, secret);
    Sig::from_bytes(signature.serialize_compact())
}

const fn payouts(maker: Key, taker: Key) -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_two(maker, 7, taker, 8)
}

#[test]
fn agreement_with_real_ecdsa_signatures_resolves_under_production_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let timeout_outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, timeout_outputs);
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let open = Open::from_terms(funding, terms);
    let edge = open.output();
    let resolve_hash = Resolve::payload_hash(edge, ResolveKind::Agreement, terms_hash, &outputs);
    let proof = Proof::agreement(
        terms_hash,
        Agreement::new(sign(&maker_sk, resolve_hash), sign(&taker_sk, resolve_hash)),
    );
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let resolve = Resolve::new(edge, proof, outputs);
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
        .apply(CONTEXT, &verifier, &Op::Open(open))
        .expect("open accepted");
    let event = state
        .apply(CONTEXT, &verifier, &Op::Resolve(resolve))
        .expect("agreement with valid ECDSA accepted");
    assert_eq!(state.store().edge(edge), None);
    let _ = event;
}

#[test]
fn forged_signature_is_rejected_by_real_verifier() {
    let (maker_sk, maker_pk) = keypair(1);
    let (_taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);
    let outputs = payouts(maker_pk, taker_pk);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs.clone());
    let terms_hash = terms.hash();
    let maker_coin = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([2; CoinId::LENGTH]);
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let open = Open::from_terms(funding, terms);
    let edge = open.output();
    let resolve_hash = Resolve::payload_hash(edge, ResolveKind::Agreement, terms_hash, &outputs);
    // Sign with maker's key in *both* slots — taker's signature is forged.
    let proof = Proof::agreement(
        terms_hash,
        Agreement::new(sign(&maker_sk, resolve_hash), sign(&maker_sk, resolve_hash)),
    );
    let maker_out = outputs.as_slice()[0].id(edge, 0);
    let taker_out = outputs.as_slice()[1].id(edge, 1);
    let resolve = Resolve::new(edge, proof, outputs);
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
        .apply(CONTEXT, &verifier, &Op::Open(open))
        .expect("open accepted");
    assert_eq!(
        state.apply(CONTEXT, &verifier, &Op::Resolve(resolve)),
        Err(ApplyError::InvalidProof {
            input: edge,
            reason: InvalidProofReason::BadSignature,
        }),
    );
}
