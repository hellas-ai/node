//! Primitive wrapper tests.

use hellas_kernel::{
    BlockHash, BlockHeight, Context, Cost, Fees, Key, Parties, Party, ProtocolCode, Terms,
};

#[test]
fn protocol_code_exposes_value() {
    let code = ProtocolCode::new(7);

    assert_eq!(code.get(), 7);
}

#[test]
fn party_tags_are_stable() {
    assert_eq!(Party::Maker.tag(), 0);
    assert_eq!(Party::Taker.tag(), 1);
    assert_eq!(Party::from_tag(0), Some(Party::Maker));
    assert_eq!(Party::from_tag(1), Some(Party::Taker));
    assert_eq!(Party::from_tag(2), None);
}

#[test]
fn terms_hash_commits_to_basic_fields() {
    let maker = Key::from_bytes([1; Key::LENGTH]);
    let taker = Key::from_bytes([2; Key::LENGTH]);
    let parties = Parties::new(maker, taker);
    let timeout = BlockHeight::new(11);
    let terms = Terms::basic(ProtocolCode::new(7), parties, timeout);

    assert_eq!(terms.protocol(), ProtocolCode::new(7));
    assert_eq!(terms.parties(), parties);
    assert_eq!(terms.timeout(), timeout);
    assert_eq!(terms.hash(), terms.hash());
    assert_ne!(
        terms.hash(),
        Terms::basic(ProtocolCode::new(8), parties, timeout).hash(),
    );
    assert_ne!(
        terms.hash(),
        Terms::basic(ProtocolCode::new(7), parties, BlockHeight::new(12)).hash(),
    );
}

#[test]
fn context_prices_resource_costs() {
    let fees = Fees::new(3, 2, 5, 7);
    let context = Context::with_fees(
        BlockHeight::new(7),
        BlockHash::from_bytes([1; BlockHash::LENGTH]),
        fees,
    );
    let cost = Cost::new(1, 4, 2, 3);

    assert_eq!(cost.base(), 1);
    assert_eq!(cost.reads(), 4);
    assert_eq!(cost.writes(), 2);
    assert_eq!(cost.proofs(), 3);
    assert_eq!(fees.base(), 3);
    assert_eq!(fees.read(), 2);
    assert_eq!(fees.write(), 5);
    assert_eq!(fees.proof(), 7);
    assert_eq!(context.fees(), fees);
    assert_eq!(context.fee(cost), Some(42));
}
