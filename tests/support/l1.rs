#![allow(dead_code)]

use super::{FixedStore, coin_id, state};

use hellas_kernel::{
    BlockHash, BlockHeight, CloseHash, CloseKind, CoinId, Context, Edge, EdgeId, EventKind,
    Funding, Genesis, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    Payout, Proof, ProtocolCode, Seal, Sig, State, Terms, Tx, View,
};

pub(crate) const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
pub(crate) const TIMEOUT: BlockHeight = BlockHeight::new(2);
pub(crate) const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));
pub(crate) const MAKER: Key = Key::from_bytes([7; Key::LENGTH]);
pub(crate) const TAKER: Key = Key::from_bytes([8; Key::LENGTH]);
pub(crate) const PARTIES: Parties = Parties::new(MAKER, TAKER);
pub(crate) const PROTOCOL: ProtocolCode = ProtocolCode::new(1);
pub(crate) const OTHER_PROTOCOL: ProtocolCode = ProtocolCode::new(2);
pub(crate) const MAKER_ID: CoinId = coin_id(1);
pub(crate) const TAKER_ID: CoinId = coin_id(2);
pub(crate) const MAKER_VALUE: u64 = 10;
pub(crate) const TAKER_VALUE: u64 = 5;
pub(crate) const EDGE_VALUE: u64 = MAKER_VALUE + TAKER_VALUE;
pub(crate) const MAKER_PAYOUT: u64 = 7;
pub(crate) const TAKER_PAYOUT: u64 = 8;
pub(crate) const BAD_PAYOUT: u64 = TAKER_PAYOUT + 1;
pub(crate) const TIMEOUT_OUTPUTS: List<Payout, MAX_EDGE_OUTPUTS> =
    payouts_const(MAKER_PAYOUT, TAKER_PAYOUT);

pub(crate) fn terms() -> Terms {
    Terms::basic(PROTOCOL, PARTIES, TIMEOUT, TIMEOUT_OUTPUTS)
}

pub(crate) fn other_terms() -> Terms {
    Terms::basic(OTHER_PROTOCOL, PARTIES, TIMEOUT, TIMEOUT_OUTPUTS)
}

pub(crate) type TraceState = State<FixedStore<6, 2>>;
pub(crate) type TraceView = View<6, 2>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum Step {
    Open(EdgeKey),
    Close(EdgeKey, ProofKey),
    Tick,
}

impl Step {
    pub(crate) const fn context(self) -> Context {
        match self {
            Self::Close(_, ProofKey::Timeout) => TIMEOUT_CONTEXT,
            _ => CONTEXT,
        }
    }

    pub(crate) fn op(self) -> Option<Tx> {
        match self {
            Self::Open(edge) => Some(open(edge)),
            Self::Close(edge, proof) => Some(close(edge, proof)),
            Self::Tick => None,
        }
    }

    pub(crate) fn check(self, event: &EventKind) {
        match (self, event) {
            (Self::Open(edge), EventKind::EdgeOpened { output, .. }) => {
                assert_eq!(*output, edge_id(edge));
            }
            (Self::Close(edge, _), EventKind::EdgeClosed { input, outputs }) => {
                assert_eq!(*input, edge_id(edge));
                assert_eq!(*outputs, output_ids(edge));
            }
            _ => panic!("trace event mismatch"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum EdgeKey {
    First,
    Second,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum OpenKey {
    Full,
    MakerOnly,
    TakerOnly,
    Empty,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) enum ProofKey {
    Mutual,
    Timeout,
    Violation,
    EarlyTimeout,
    WrongTerms,
    BadSeal,
}

pub(crate) fn initial_state() -> TraceState {
    state(
        FixedStore::empty(
            [
                MAKER_ID,
                TAKER_ID,
                maker_out(EdgeKey::First),
                taker_out(EdgeKey::First),
                maker_out(EdgeKey::Second),
                taker_out(EdgeKey::Second),
            ],
            [edge_id(EdgeKey::First), edge_id(EdgeKey::Second)],
        ),
        [
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    )
}

pub(crate) fn genesis<const C: usize, const E: usize>(
    store: FixedStore<C, E>,
) -> State<FixedStore<C, E>> {
    state(
        store,
        [
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    )
}

pub(crate) fn open(edge: EdgeKey) -> Tx {
    match edge {
        EdgeKey::First => open_case(OpenKey::Full),
        EdgeKey::Second => {
            let funding = Funding::new(
                party1(maker_out(EdgeKey::First)),
                party1(taker_out(EdgeKey::First)),
            );
            let terms = terms();
            let (maker_sig, taker_sig) = open_sigs(&funding, &terms, MAKER, TAKER);
            Tx::open(funding, terms, maker_sig, taker_sig)
        }
    }
}

pub(crate) fn open_case(key: OpenKey) -> Tx {
    let funding = open_funding(key);
    let terms = terms();
    let (maker_sig, taker_sig) = open_sigs(&funding, &terms, MAKER, TAKER);
    Tx::open(funding, terms, maker_sig, taker_sig)
}

/// Builds canonical placeholder open signatures (one per party) bound to the
/// open hash of `(funding, terms)`. Use this in tests driven by
/// `FAKE_VERIFIER`, which accepts any placeholder sig keyed to the matching
/// party. Each test that constructs a `Tx::Open` over canonical
/// `(MAKER, TAKER)` parties can call this and forward the pair directly into
/// [`Tx::open`].
pub(crate) fn open_sigs(funding: &Funding, terms: &Terms, maker: Key, taker: Key) -> (Sig, Sig) {
    let hash = Tx::open_hash(funding, terms);
    (Sig::placeholder(maker, hash), Sig::placeholder(taker, hash))
}

pub(crate) fn open_case_op(key: OpenKey) -> Tx {
    open_case(key)
}

pub(crate) fn open_case_id(key: OpenKey) -> EdgeId {
    Tx::edge_id_of(&open_funding(key), &terms())
}

pub(crate) fn open_case_inputs(key: OpenKey) -> List<CoinId, MAX_EDGE_INPUTS> {
    match key {
        OpenKey::Full => input_ids2(MAKER_ID, TAKER_ID),
        OpenKey::MakerOnly => input_ids1(MAKER_ID),
        OpenKey::TakerOnly => input_ids1(TAKER_ID),
        OpenKey::Empty => input_ids0(),
    }
}

pub(crate) fn close(edge: EdgeKey, proof: ProofKey) -> Tx {
    close_with(edge, proof, payouts())
}

pub(crate) fn close_with(
    edge: EdgeKey,
    proof: ProofKey,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
) -> Tx {
    Tx::close(edge_id(edge), proof_for(edge, proof, &outputs), outputs)
}

pub(crate) fn edge_id(edge: EdgeKey) -> EdgeId {
    match edge {
        EdgeKey::First => Tx::edge_id_of(&open_funding(OpenKey::Full), &terms()),
        EdgeKey::Second => Tx::edge_id_of(
            &Funding::new(
                party1(maker_out(EdgeKey::First)),
                party1(taker_out(EdgeKey::First)),
            ),
            &terms(),
        ),
    }
}

pub(crate) fn maker_out(edge: EdgeKey) -> CoinId {
    nth(&output_ids(edge), 0)
}

pub(crate) fn taker_out(edge: EdgeKey) -> CoinId {
    nth(&output_ids(edge), 1)
}

pub(crate) fn output_ids(edge: EdgeKey) -> List<CoinId, MAX_EDGE_OUTPUTS> {
    Tx::close_output_ids(edge_id(edge), &payouts())
}

pub(crate) const fn edge_value(edge: Edge) -> u64 {
    edge.value()
}

pub(crate) fn live_value<const C: usize, const E: usize>(view: &View<C, E>) -> u64 {
    let mut total = 0_u64;
    for (_, coin) in view.coins() {
        total = total.saturating_add(coin.value());
    }
    for (_, edge) in view.edges() {
        total = total.saturating_add(edge.value());
    }
    total
}

pub(crate) fn payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(MAKER_PAYOUT, TAKER_PAYOUT)
}

pub(crate) fn bad_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(MAKER_PAYOUT, BAD_PAYOUT)
}

/// Value-conserving payouts that drain the entire edge to the maker. Used to
/// expose proof-binding holes: any kind that does not bind payouts will accept
/// these instead of the canonical (`MAKER_PAYOUT`, `TAKER_PAYOUT`) split.
pub(crate) fn maker_grab_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    payouts_with(EDGE_VALUE, 0)
}

pub(crate) fn payouts_with(maker: u64, taker: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new(
        [
            Payout::new(MAKER, maker),
            Payout::new(TAKER, taker),
            Payout::new(MAKER, maker),
            Payout::new(MAKER, maker),
        ],
        2,
    ) else {
        panic!("invalid trace payout list");
    };
    outputs
}

const fn payouts_const(maker: u64, taker: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let Some(outputs) = List::new(
        [
            Payout::new(MAKER, maker),
            Payout::new(TAKER, taker),
            Payout::new(MAKER, maker),
            Payout::new(MAKER, maker),
        ],
        2,
    ) else {
        panic!("invalid trace payout list");
    };
    outputs
}

pub(crate) fn input_ids2(first: CoinId, second: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new([first, second, first, first, first, first, first, first], 2)
    else {
        panic!("invalid trace input id list");
    };
    inputs
}

pub(crate) fn input_ids1(id: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new([id; MAX_EDGE_INPUTS], 1) else {
        panic!("invalid trace input id list");
    };
    inputs
}

pub(crate) fn input_ids0() -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new([MAKER_ID; MAX_EDGE_INPUTS], 0) else {
        panic!("invalid trace input id list");
    };
    inputs
}

pub(crate) fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid trace party list");
    };
    inputs
}

pub(crate) fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([MAKER_ID; MAX_PARTY_INPUTS], 0) else {
        panic!("invalid trace party list");
    };
    inputs
}

pub(crate) fn nth<const N: usize>(ids: &List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}

fn proof_for(edge: EdgeKey, proof: ProofKey, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Proof {
    let terms = terms();
    match proof {
        ProofKey::Mutual => Proof::mutual(
            Sig::placeholder(MAKER, hash(edge, CloseKind::Mutual, outputs)),
            Sig::placeholder(TAKER, hash(edge, CloseKind::Mutual, outputs)),
        ),
        ProofKey::Timeout | ProofKey::EarlyTimeout => Proof::timeout(terms),
        ProofKey::Violation => Proof::violation(terms, seal(edge, CloseKind::Violation, outputs)),
        // Submitting a Timeout proof whose terms don't match the edge's terms
        // commitment triggers `TermsMismatch` in the verifier (replaces the
        // old "Proof::basic with other terms" admission test).
        ProofKey::WrongTerms => Proof::timeout(other_terms()),
        // Bind the seal to a payload that does not match the canonical close
        // payload, so the verifier rejects it with `BadSeal`.
        ProofKey::BadSeal => Proof::violation(terms, bad_seal(edge, outputs)),
    }
}

fn open_funding(key: OpenKey) -> Funding {
    match key {
        OpenKey::Full => Funding::new(party1(MAKER_ID), party1(TAKER_ID)),
        OpenKey::MakerOnly => Funding::new(party1(MAKER_ID), empty_party()),
        OpenKey::TakerOnly => Funding::new(empty_party(), party1(TAKER_ID)),
        OpenKey::Empty => Funding::new(empty_party(), empty_party()),
    }
}

fn seal(edge: EdgeKey, kind: CloseKind, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    Seal::placeholder(terms().protocol(), kind, hash(edge, kind, outputs))
}

/// Seal bound to a non-canonical close payload (uses `other_terms()` for the
/// terms-hash binding), so the verifier rejects with `BadSeal` rather than
/// `TermsMismatch`.
fn bad_seal(edge: EdgeKey, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> Seal {
    let bad_hash = Tx::payload_hash(
        edge_id(edge),
        CloseKind::Violation,
        other_terms().hash(),
        outputs,
    );
    Seal::placeholder(terms().protocol(), CloseKind::Violation, bad_hash)
}

fn hash(edge: EdgeKey, kind: CloseKind, outputs: &List<Payout, MAX_EDGE_OUTPUTS>) -> CloseHash {
    Tx::payload_hash(edge_id(edge), kind, terms().hash(), outputs)
}
