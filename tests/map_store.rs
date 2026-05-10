//! Smoke tests for the growing-backend `MapStore`.
//!
//! Drives the kernel against a `BTreeMap`-backed store. Confirms the `Store`
//! trait composes with non-bounded backends, and runs a sequence longer than
//! `FixedStore`'s compile-time slot count to validate the map's grow path.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]

mod support;

use hellas_kernel::{
    BlockHash, BlockHeight, Context, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS, Op, Open,
    Parties, Payout, Proof, ProtocolCode, Resolve, Terms,
};
use support::{FAKE_VERIFIER, coin_id, key, map_store::map_state, party_one, payouts_two};

const TIMEOUT: BlockHeight = BlockHeight::new(2);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));
const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

const fn payouts(
    maker: Key,
    taker: Key,
    maker_value: u64,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_two(maker, maker_value, taker, taker_value)
}

#[test]
fn map_store_round_trip() {
    let maker = key(7);
    let taker = key(8);
    let parties = Parties::new(maker, taker);
    let maker_coin = coin_id(1);
    let taker_coin = coin_id(2);
    let outputs = payouts(maker, taker, 7, 8);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, outputs);
    let open = Open::from_terms(
        Funding::new(party_one(maker_coin), party_one(taker_coin)),
        terms,
    );
    let edge = open.output();
    let resolve = Resolve::new(edge, Proof::timeout(terms), outputs);

    let mut state = map_state([
        Genesis::coin(maker_coin, maker, 10),
        Genesis::coin(taker_coin, taker, 5),
    ]);
    assert_eq!(state.store().coin_count(), 2);
    assert_eq!(state.store().edge_count(), 0);

    state
        .apply(CONTEXT, &FAKE_VERIFIER, &Op::Open(open))
        .expect("open accepted");
    assert_eq!(state.store().coin_count(), 0);
    assert_eq!(state.store().edge_count(), 1);
    assert!(state.store().edge(edge).is_some());

    state
        .apply(TIMEOUT_CONTEXT, &FAKE_VERIFIER, &Op::Resolve(resolve))
        .expect("resolve accepted");
    assert_eq!(state.store().coin_count(), 2);
    assert_eq!(state.store().edge_count(), 0);

    let payout_owners: Vec<Key> = state.store().coins().map(|(_, c)| c.owner()).collect();
    assert!(payout_owners.contains(&maker));
    assert!(payout_owners.contains(&taker));
}

/// Open and resolve N successive edges, each funded by the previous resolve's
/// payout coins. `FixedStore` can't hold this many slots without
/// over-allocation; `MapStore` grows naturally.
#[test]
fn map_store_handles_long_chain() {
    const N: usize = 32;
    let maker = key(7);
    let taker = key(8);
    let parties = Parties::new(maker, taker);
    let payout_outputs = payouts(maker, taker, 7, 8);
    let terms = Terms::basic(ProtocolCode::new(1), parties, TIMEOUT, payout_outputs);

    // Fund with a single big maker coin and a single big taker coin; each
    // resolve splits 15 → (7, 8) which the next open consumes whole.
    let mut maker_coin = coin_id(1);
    let mut taker_coin = coin_id(2);

    let mut state = map_state([
        Genesis::coin(maker_coin, maker, 7),
        Genesis::coin(taker_coin, taker, 8),
    ]);

    for _ in 0..N {
        let open = Open::from_terms(
            Funding::new(party_one(maker_coin), party_one(taker_coin)),
            terms,
        );
        let edge = open.output();
        let outputs = payouts(maker, taker, 7, 8);
        let resolve = Resolve::new(edge, Proof::timeout(terms), outputs);

        state
            .apply(CONTEXT, &FAKE_VERIFIER, &Op::Open(open))
            .expect("open accepted in chain");
        state
            .apply(TIMEOUT_CONTEXT, &FAKE_VERIFIER, &Op::Resolve(resolve))
            .expect("resolve accepted in chain");

        // The two payout coins from this resolve become the next open's
        // funding.
        let resolved_outputs = resolve.output_ids();
        maker_coin = resolved_outputs.as_slice()[0];
        taker_coin = resolved_outputs.as_slice()[1];
    }

    assert_eq!(state.store().edge_count(), 0, "all edges resolved");
    // Each iteration's payouts feed the next open's funding, so at the end
    // only the final iteration's two payout coins remain live.
    assert_eq!(state.store().coin_count(), 2);
}
