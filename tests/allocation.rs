//! Allocation hygiene tests for kernel hot-path primitives.
//!
//! These tests assert zero heap allocations across `apply_all` and
//! `Op::access`/`Op::cost`. The invariant rests on every op-payload type
//! (`Op`, `Open`, `Resolve`, `Funding`, `Terms`, `Proof`, `List<...>`)
//! being stack-only: clones we make in setup or assertions are pure
//! `memcpy`s, never `Box`/`Vec`/`String` allocations. Adding a heap
//! field to any of those types — or changing `List<T, N>` to back its
//! storage on the heap — would silently regress this without a clippy
//! or rustc warning. Re-run `cargo test --test allocation` after any
//! field-shape change to those types.

mod support;

use support::{FAKE_VERIFIER, FixedStore};

use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context, Event, EventKind, Funding, Genesis, Key, List,
    MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties, Payout, Proof,
    ProtocolCode, Resolve, State, Terms,
};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

#[test]
fn open_resolve_and_operation_match_do_not_allocate() {
    let maker_key = Key::from_bytes([7; Key::LENGTH]);
    let taker_key = Key::from_bytes([8; Key::LENGTH]);
    let parties = Parties::new(maker_key, taker_key);
    let maker = CoinId::from_bytes([1; CoinId::LENGTH]);
    let taker = CoinId::from_bytes([2; CoinId::LENGTH]);
    let expected_open = Open::from_terms(
        funding(maker, taker),
        Terms::basic(
            ProtocolCode::new(1),
            parties,
            BlockHeight::new(1),
            payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6)),
        ),
    );
    let edge = expected_open.output();
    let expected_resolve = Resolve::new(
        edge,
        Proof::timeout(Terms::basic(
            ProtocolCode::new(1),
            parties,
            BlockHeight::new(1),
            payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6)),
        )),
        payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6)),
    );
    let maker_out = nth(&expected_resolve.output_ids(), 0);
    let taker_out = nth(&expected_resolve.output_ids(), 1);
    let maker_seed = Genesis::coin(maker, maker_key, 10);
    let taker_seed = Genesis::coin(taker, taker_key, 5);
    let store = FixedStore::empty([maker, taker, maker_out, taker_out], [edge]);

    let info = allocation_counter::measure(|| {
        let store = core::hint::black_box(store);

        let outputs = payouts(Payout::new(maker_key, 9), Payout::new(taker_key, 6));
        let terms = Terms::basic(ProtocolCode::new(1), parties, BlockHeight::new(1), outputs.clone());
        let proof = Proof::timeout(terms.clone());
        let open = Op::Open(Open::from_terms(funding(maker, taker), terms));
        assert_eq!(open, Op::Open(expected_open.clone()));
        let is_open = matches!(open, Op::Open(_));
        let resolve = Op::Resolve(Resolve::new(edge, proof, outputs));
        assert_eq!(resolve, Op::Resolve(expected_resolve.clone()));
        let is_resolve = matches!(resolve, Op::Resolve(_));
        let Ok(mut chain) = State::genesis(store, &[maker_seed, taker_seed]) else {
            panic!("genesis rejected test seed");
        };
        let ops = List::all([open, resolve]);
        let Ok(diff) = chain.apply_all(CONTEXT, &FAKE_VERIFIER, &ops) else {
            panic!("apply_all rejected");
        };

        assert_eq!(
            diff.event(0).map(Event::kind),
            Some(&EventKind::EdgeOpened {
                inputs: input_ids(maker, taker),
                output: edge,
            }),
        );
        assert_eq!(
            diff.event(1).map(Event::kind),
            Some(&EventKind::EdgeResolved {
                input: edge,
                outputs: output_ids(maker_out, taker_out),
            }),
        );

        core::hint::black_box((is_open, is_resolve));
    });

    assert_eq!(info.count_total, 0);
    assert_eq!(info.count_current, 0);
    assert_eq!(info.count_max, 0);
    assert_eq!(info.bytes_total, 0);
    assert_eq!(info.bytes_current, 0);
    assert_eq!(info.bytes_max, 0);
}

fn funding(maker: CoinId, taker: CoinId) -> Funding {
    Funding::new(party1(maker), party1(taker))
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid test party list");
    };
    inputs
}

fn payouts(first: Payout, second: Payout) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new([first, second, first, first], 2) else {
        panic!("invalid test payout list");
    };
    outputs
}

fn input_ids(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(ids) = List::new([first, second, first, first, first, first, first, first], 2) else {
        panic!("invalid test input id list");
    };
    ids
}

fn output_ids(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    let Some(ids) = List::new([first, second, first, first], 2) else {
        panic!("invalid test output id list");
    };
    ids
}

fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}
