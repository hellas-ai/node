//! Stateright model checks for the current kernel operation surface.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_core)]

mod support;

use support::FixedStore;

use hellas_kernel::{
    Agreement, ApplyError, BlockHash, BlockHeight, Coin, CoinId, Context, Edge, EdgeId, EventKind,
    Funding, Genesis, Key, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open,
    Parties, Payout, Proof, ProtocolCode, Resolve, ResolveHash, ResolveKind, Seal, Sig, State,
    Terms, View,
};
use stateright::{Checker, Model, Property};

const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);
const TIMEOUT_CONTEXT: Context =
    Context::new(TIMEOUT, BlockHash::from_bytes([0; BlockHash::LENGTH]));
const MAKER: Key = Key::from_bytes([8; Key::LENGTH]);
const TAKER: Key = Key::from_bytes([9; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER, TAKER);
const MAKER_ID: CoinId = CoinId::from_bytes([10; CoinId::LENGTH]);
const TAKER_ID: CoinId = CoinId::from_bytes([11; CoinId::LENGTH]);
const TIMEOUT: BlockHeight = BlockHeight::new(2);
const TERMS: Terms = Terms::basic(ProtocolCode::new(1), PARTIES, TIMEOUT);
const OTHER_TERMS: Terms = Terms::basic(ProtocolCode::new(2), PARTIES, TIMEOUT);
const MAKER_VALUE: u64 = 10;
const TAKER_VALUE: u64 = 5;
const CHANNEL_VALUE: u64 = MAKER_VALUE + TAKER_VALUE;
const MAKER_PAYOUT: u64 = 7;
const TAKER_PAYOUT: u64 = 8;
type ModelView = View<4, 4>;
type ChannelStore = FixedStore<4, 4>;

fn edge_id() -> EdgeId {
    open_inner().output()
}

fn maker_edge_id() -> EdgeId {
    maker_only_open_inner().output()
}

fn taker_edge_id() -> EdgeId {
    taker_only_open_inner().output()
}

fn empty_edge_id() -> EdgeId {
    empty_funding_open_inner().output()
}

fn maker_out() -> CoinId {
    nth(output_ids(), 0)
}

fn taker_out() -> CoinId {
    nth(output_ids(), 1)
}

#[derive(Clone, Copy)]
struct ChannelModel;

impl Model for ChannelModel {
    type Action = Action;
    type State = State<ChannelStore>;

    fn init_states(&self) -> Vec<Self::State> {
        vec![channel_state()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        let view: ModelView = state.view();

        if view.edge_len() == 0 && view.coin(MAKER_ID).is_some() && view.coin(TAKER_ID).is_some() {
            actions.push(Action::open());
            actions.push(Action::maker_open());
            actions.push(Action::taker_open());
            actions.push(Action::empty_open());
        }

        if view.edge(edge_id()).is_some() {
            actions.push(Action::resolve());
            actions.push(Action::agreement());
            actions.push(Action::timeout());
            actions.push(Action::claimant());
            actions.push(Action::challenger());
            actions.push(Action::early_timeout());
            actions.push(Action::invalid_resolve());
            actions.push(Action::invalid_proof());
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut state = *last_state;

        if let Some(error) = action.error() {
            return Self::invalid_state(&mut state, last_state, &action, error);
        }

        let event = state.apply(action.context, &action.op).ok()?.kind();
        Self::valid_state(&state, &action, &event)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "channel value is conserved",
                |_, state: &State<ChannelStore>| {
                    channel_value(&state.view::<4, 4>()) == CHANNEL_VALUE
                },
            ),
            Property::always(
                "channel objects have one live shape",
                |_, state: &State<ChannelStore>| channel_shape(&state.view::<4, 4>()),
            ),
        ]
    }
}

impl ChannelModel {
    fn invalid_state(
        state: &mut State<ChannelStore>,
        last_state: &State<ChannelStore>,
        action: &Action,
        error: ApplyError,
    ) -> Option<State<ChannelStore>> {
        let rejected = state.apply(action.context, &action.op).err()?;

        if rejected == error && *state == *last_state {
            Some(*state)
        } else {
            None
        }
    }

    fn valid_state(
        state: &State<ChannelStore>,
        action: &Action,
        event: &EventKind,
    ) -> Option<State<ChannelStore>> {
        match (&action.op, event) {
            (
                Op::Open(operation),
                EventKind::EdgeOpened {
                    inputs: event_inputs,
                    output,
                },
            ) => Self::valid_open(state, operation, event_inputs, *output),
            (
                Op::Resolve(operation),
                EventKind::EdgeResolved {
                    input,
                    outputs: event_outputs,
                },
            ) => Self::valid_resolve(state, action.context, operation, *input, event_outputs),
            _ => None,
        }
    }

    fn valid_open(
        state: &State<ChannelStore>,
        operation: &Open,
        inputs: &List<CoinId, MAX_EDGE_INPUTS>,
        output: EdgeId,
    ) -> Option<State<ChannelStore>> {
        let ok = (*operation == open_inner() && *inputs == input_ids() && output == edge_id())
            || (*operation == maker_only_open_inner()
                && *inputs == input_ids1(MAKER_ID)
                && output == maker_edge_id())
            || (*operation == taker_only_open_inner()
                && *inputs == input_ids1(TAKER_ID)
                && output == taker_edge_id())
            || (*operation == empty_funding_open_inner()
                && *inputs == input_ids0()
                && output == empty_edge_id());

        ok.then_some(*state)
    }

    fn valid_resolve(
        state: &State<ChannelStore>,
        context: Context,
        operation: &Resolve,
        input: EdgeId,
        outputs: &List<CoinId, MAX_EDGE_OUTPUTS>,
    ) -> Option<State<ChannelStore>> {
        let ok = input == edge_id()
            && *outputs == output_ids()
            && (*operation == resolve_inner()
                || *operation == agreement_resolve_inner()
                || *operation == claimant_resolve_inner()
                || *operation == challenger_resolve_inner()
                || (*operation == timeout_resolve_inner() && context == TIMEOUT_CONTEXT));

        ok.then_some(*state)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Action {
    context: Context,
    op: Op,
}

impl Action {
    fn open() -> Self {
        Self {
            context: CONTEXT,
            op: open(),
        }
    }

    fn maker_open() -> Self {
        Self {
            context: CONTEXT,
            op: maker_only_open(),
        }
    }

    fn taker_open() -> Self {
        Self {
            context: CONTEXT,
            op: taker_only_open(),
        }
    }

    fn empty_open() -> Self {
        Self {
            context: CONTEXT,
            op: empty_funding_open(),
        }
    }

    fn resolve() -> Self {
        Self {
            context: CONTEXT,
            op: resolve(),
        }
    }

    fn agreement() -> Self {
        Self {
            context: CONTEXT,
            op: agreement_resolve(),
        }
    }

    fn timeout() -> Self {
        Self {
            context: TIMEOUT_CONTEXT,
            op: timeout_resolve(),
        }
    }

    fn claimant() -> Self {
        Self {
            context: CONTEXT,
            op: claimant_resolve(),
        }
    }

    fn challenger() -> Self {
        Self {
            context: CONTEXT,
            op: challenger_resolve(),
        }
    }

    fn early_timeout() -> Self {
        Self {
            context: CONTEXT,
            op: timeout_resolve(),
        }
    }

    fn invalid_resolve() -> Self {
        Self {
            context: CONTEXT,
            op: invalid_resolve(),
        }
    }

    fn invalid_proof() -> Self {
        Self {
            context: CONTEXT,
            op: invalid_proof_resolve(),
        }
    }

    fn error(&self) -> Option<ApplyError> {
        if self == &Self::invalid_resolve() {
            Some(ApplyError::InvalidResolve { input: edge_id() })
        } else if self == &Self::invalid_proof() || self == &Self::early_timeout() {
            Some(ApplyError::InvalidProof { input: edge_id() })
        } else {
            None
        }
    }
}

#[test]
fn open_resolve_model_checks() {
    let checker = ChannelModel.checker().spawn_dfs().join();

    assert!(checker.discoveries().is_empty());
    assert_eq!(checker.unique_state_count(), 6);
}

fn channel_state() -> State<ChannelStore> {
    let Ok(state) = State::genesis(
        empty_channel(),
        &[
            Genesis::coin(MAKER_ID, MAKER, MAKER_VALUE),
            Genesis::coin(TAKER_ID, TAKER, TAKER_VALUE),
        ],
    ) else {
        panic!("genesis rejected channel seed");
    };
    state
}

fn empty_channel() -> ChannelStore {
    FixedStore::empty(
        [MAKER_ID, TAKER_ID, maker_out(), taker_out()],
        [edge_id(), maker_edge_id(), taker_edge_id(), empty_edge_id()],
    )
}

fn open() -> Op {
    Op::Open(open_inner())
}

fn open_inner() -> Open {
    Open::from_terms(funding(), TERMS)
}

fn maker_only_open() -> Op {
    Op::Open(maker_only_open_inner())
}

fn maker_only_open_inner() -> Open {
    Open::from_terms(Funding::new(party1(MAKER_ID), empty_party()), TERMS)
}

fn taker_only_open() -> Op {
    Op::Open(taker_only_open_inner())
}

fn taker_only_open_inner() -> Open {
    Open::from_terms(Funding::new(empty_party(), party1(TAKER_ID)), TERMS)
}

fn empty_funding_open() -> Op {
    Op::Open(empty_funding_open_inner())
}

fn empty_funding_open_inner() -> Open {
    Open::from_terms(Funding::new(empty_party(), empty_party()), TERMS)
}

fn resolve() -> Op {
    Op::Resolve(resolve_inner())
}

fn resolve_inner() -> Resolve {
    Resolve::new(edge_id(), proof(), payouts(MAKER_PAYOUT, TAKER_PAYOUT))
}

fn invalid_resolve() -> Op {
    Op::Resolve(Resolve::new(
        edge_id(),
        proof(),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT + 1),
    ))
}

fn invalid_proof_resolve() -> Op {
    Op::Resolve(Resolve::new(
        edge_id(),
        other_proof(),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    ))
}

fn agreement_resolve() -> Op {
    Op::Resolve(agreement_resolve_inner())
}

fn agreement_resolve_inner() -> Resolve {
    Resolve::new(
        edge_id(),
        agreement_proof(),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn agreement_proof() -> Proof {
    Proof::agreement(
        TERMS.hash(),
        Agreement::new(
            Sig::placeholder(MAKER, agreement_hash()),
            Sig::placeholder(TAKER, agreement_hash()),
        ),
    )
}

fn agreement_hash() -> ResolveHash {
    Resolve::payload_hash(
        edge_id(),
        ResolveKind::Agreement,
        TERMS.hash(),
        &payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn timeout_resolve() -> Op {
    Op::Resolve(timeout_resolve_inner())
}

fn timeout_resolve_inner() -> Resolve {
    Resolve::new(
        edge_id(),
        Proof::timeout(TERMS),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn claimant_resolve() -> Op {
    Op::Resolve(claimant_resolve_inner())
}

fn claimant_resolve_inner() -> Resolve {
    Resolve::new(
        edge_id(),
        Proof::claimant_wins(TERMS, seal(ResolveKind::ClaimantWins)),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn challenger_resolve() -> Op {
    Op::Resolve(challenger_resolve_inner())
}

fn challenger_resolve_inner() -> Resolve {
    Resolve::new(
        edge_id(),
        Proof::challenger_wins(TERMS, seal(ResolveKind::ChallengerWins)),
        payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn seal(kind: ResolveKind) -> Seal {
    Seal::placeholder(TERMS.protocol(), kind, proof_hash(kind))
}

fn proof_hash(kind: ResolveKind) -> ResolveHash {
    Resolve::payload_hash(
        edge_id(),
        kind,
        TERMS.hash(),
        &payouts(MAKER_PAYOUT, TAKER_PAYOUT),
    )
}

fn proof() -> Proof {
    Proof::basic(TERMS.hash())
}

fn other_proof() -> Proof {
    Proof::basic(OTHER_TERMS.hash())
}

fn funding() -> Funding {
    Funding::new(party1(MAKER_ID), party1(TAKER_ID))
}

fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([MAKER_ID; MAX_PARTY_INPUTS], 0) else {
        panic!("invalid model party list");
    };
    inputs
}

fn party1(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("invalid model party list");
    };
    inputs
}

fn payouts(maker_value: u64, taker_value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let maker = Payout::new(MAKER, maker_value);
    let taker = Payout::new(TAKER, taker_value);
    let Some(outputs) = List::new([maker, taker, maker, maker], 2) else {
        panic!("invalid model payout list");
    };
    outputs
}

fn input_ids() -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new(
        [
            MAKER_ID, TAKER_ID, MAKER_ID, MAKER_ID, MAKER_ID, MAKER_ID, MAKER_ID, MAKER_ID,
        ],
        2,
    ) else {
        panic!("invalid model input id list");
    };
    inputs
}

fn input_ids1(id: CoinId) -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new([id; MAX_EDGE_INPUTS], 1) else {
        panic!("invalid model input id list");
    };
    inputs
}

fn input_ids0() -> List<CoinId, MAX_EDGE_INPUTS> {
    let Some(inputs) = List::new([MAKER_ID; MAX_EDGE_INPUTS], 0) else {
        panic!("invalid model input id list");
    };
    inputs
}

fn output_ids() -> List<CoinId, MAX_EDGE_OUTPUTS> {
    resolve_inner().output_ids()
}

fn nth<const N: usize>(ids: List<CoinId, N>, index: usize) -> CoinId {
    ids.as_slice()[index]
}

fn channel_value(view: &ModelView) -> u64 {
    let mut total = 0_u64;
    for (_, coin) in view.coins() {
        total = match total.checked_add(coin.value()) {
            Some(total) => total,
            None => return u64::MAX,
        };
    }
    for (_, edge) in view.edges() {
        total = match total.checked_add(edge.value()) {
            Some(total) => total,
            None => return u64::MAX,
        };
    }
    total
}

fn channel_shape(view: &ModelView) -> bool {
    funding_shape(view)
        || open_shape(view)
        || maker_open_shape(view)
        || taker_open_shape(view)
        || empty_open_shape(view)
        || resolved_shape(view)
}

fn funding_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).is_some()
        && view.coin(TAKER_ID).is_some()
        && view.coin(maker_out()).is_none()
        && view.coin(taker_out()).is_none()
        && view.edge_len() == 0
}

fn open_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).is_none()
        && view.coin(TAKER_ID).is_none()
        && view.coin(maker_out()).is_none()
        && view.coin(taker_out()).is_none()
        && view.edge(edge_id()).map(edge_view) == Some((CHANNEL_VALUE, PARTIES))
}

fn maker_open_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).is_none()
        && view.coin(TAKER_ID).map(Coin::value) == Some(TAKER_VALUE)
        && view.coin(maker_out()).is_none()
        && view.coin(taker_out()).is_none()
        && view.edge(maker_edge_id()).map(edge_view) == Some((MAKER_VALUE, PARTIES))
}

fn taker_open_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).map(Coin::value) == Some(MAKER_VALUE)
        && view.coin(TAKER_ID).is_none()
        && view.coin(maker_out()).is_none()
        && view.coin(taker_out()).is_none()
        && view.edge(taker_edge_id()).map(edge_view) == Some((TAKER_VALUE, PARTIES))
}

fn empty_open_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).map(Coin::value) == Some(MAKER_VALUE)
        && view.coin(TAKER_ID).map(Coin::value) == Some(TAKER_VALUE)
        && view.coin(maker_out()).is_none()
        && view.coin(taker_out()).is_none()
        && view.edge(empty_edge_id()).map(edge_view) == Some((0, PARTIES))
}

fn resolved_shape(view: &ModelView) -> bool {
    view.coin(MAKER_ID).is_none()
        && view.coin(TAKER_ID).is_none()
        && view.edge_len() == 0
        && view.coin(maker_out()).map(Coin::value) == Some(MAKER_PAYOUT)
        && view.coin(taker_out()).map(Coin::value) == Some(TAKER_PAYOUT)
}

const fn edge_view(edge: Edge) -> (u64, Parties) {
    (edge.value(), edge.parties())
}
