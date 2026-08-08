//! Abstract state view canonicalization tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    BlockHash, BlockHeight, Context, Funding, Genesis, MAX_EDGE_OUTPUTS, Parties, Payout,
    ProtocolCode, Terms, Tx,
};
use support::{FAKE_VERIFIER, FixedStore, coin_id, key, list, open_tx as open, state};

#[test]
fn view_compacts_sparse_coins_and_sorts_by_id() {
    let low = coin_id(1);
    let mid = coin_id(5);
    let high = coin_id(9);
    let owner = key(7);
    let state = state(
        FixedStore::empty([high, low, mid], []),
        [
            Genesis::coin(high, owner, 9),
            Genesis::coin(low, owner, 1),
            Genesis::coin(mid, owner, 5),
        ],
    );

    let view = state.view();
    let ids = view.coins().map(|(id, _)| id).collect::<Vec<_>>();

    assert_eq!(view.coin_len(), 3);
    assert_eq!(ids, vec![low, mid, high]);
    assert_eq!(view.coin(low).map(hellas_kernel::Coin::value), Some(1));
    assert_eq!(view.coin(mid).map(hellas_kernel::Coin::value), Some(5));
    assert_eq!(view.coin(high).map(hellas_kernel::Coin::value), Some(9));
}

#[test]
fn view_compacts_sparse_edges_and_sorts_by_id() {
    let maker = key(7);
    let taker = key(8);
    let maker_a = coin_id(1);
    let taker_a = coin_id(2);
    let maker_b = coin_id(3);
    let taker_b = coin_id(4);
    let funding_a = Funding::new(list(&[maker_a]), list(&[taker_a]));
    let funding_b = Funding::new(list(&[maker_b]), list(&[taker_b]));
    let terms_a = terms(maker, taker, 1);
    let terms_b = terms(maker, taker, 2);
    let edge_a = Tx::edge_id_of(&funding_a, &terms_a);
    let edge_b = Tx::edge_id_of(&funding_b, &terms_b);
    let open_a = open(funding_a, terms_a, maker, taker);
    let open_b = open(funding_b, terms_b, maker, taker);
    let mut expected = vec![edge_a, edge_b];
    expected.sort();
    let mut state = state(
        FixedStore::empty(
            [maker_a, taker_a, maker_b, taker_b],
            [expected[1], expected[0]],
        ),
        [
            Genesis::coin(maker_a, maker, 10),
            Genesis::coin(taker_a, taker, 5),
            Genesis::coin(maker_b, maker, 10),
            Genesis::coin(taker_b, taker, 5),
        ],
    );
    let context = Context::new(
        support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    );

    state
        .apply(context, &FAKE_VERIFIER, &open_a)
        .expect("first edge opens");
    state
        .apply(context, &FAKE_VERIFIER, &open_b)
        .expect("second edge opens");
    let ids = state.view().edges().map(|(id, _)| id).collect::<Vec<_>>();

    assert_eq!(ids, expected);
}

fn terms(maker: hellas_kernel::Key, taker: hellas_kernel::Key, protocol: u8) -> Terms {
    let first = Payout::new(maker, 10);
    let mut outputs = [first; MAX_EDGE_OUTPUTS];
    outputs[1] = Payout::new(taker, 5);
    let outputs = hellas_kernel::List::new(outputs, 2).expect("two payouts fit");
    Terms::basic(
        ProtocolCode::new(protocol),
        Parties::new(maker, taker),
        BlockHeight::new(9),
        outputs,
    )
}
