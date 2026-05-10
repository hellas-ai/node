//! Stateright model checks for the current kernel operation surface.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_core)]

mod support;

use support::{
    FixedStore,
    l1::{self, EdgeKey, OpenKey, ProofKey},
};

use hellas_kernel::{
    ApplyError, Coin, CoinId, Context, Edge, EdgeId, EventKind, List, MAX_EDGE_INPUTS,
    MAX_EDGE_OUTPUTS, Op, Open, Parties, Resolve, State, View,
};
use stateright::{Checker, Model, Property};

type ModelView = View<4, 4>;
type ChannelStore = FixedStore<4, 4>;

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

        if view.edge_len() == 0
            && view.coin(l1::MAKER_ID).is_some()
            && view.coin(l1::TAKER_ID).is_some()
        {
            actions.push(Action::Open(OpenKey::Full));
            actions.push(Action::Open(OpenKey::MakerOnly));
            actions.push(Action::Open(OpenKey::TakerOnly));
            actions.push(Action::Open(OpenKey::Empty));
        }

        if view.edge(l1::open_case_id(OpenKey::Full)).is_some() {
            actions.push(Action::Resolve(ProofKey::Basic));
            actions.push(Action::Resolve(ProofKey::Agreement));
            actions.push(Action::Resolve(ProofKey::Timeout));
            actions.push(Action::Resolve(ProofKey::Claimant));
            actions.push(Action::Resolve(ProofKey::Challenger));
            actions.push(Action::Resolve(ProofKey::EarlyTimeout));
            actions.push(Action::InvalidResolve);
            actions.push(Action::InvalidProof);
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut state = *last_state;
        let context = action.context();
        let op = action.op();

        if let Some(error) = action.error() {
            return Self::invalid_state(&mut state, last_state, context, &op, error);
        }

        let event = state.apply(context, &op).ok()?.kind();
        Self::valid_state(&state, action, context, &op, &event)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "channel value is conserved",
                |_, state: &State<ChannelStore>| {
                    l1::live_value(&state.view::<4, 4>()) == l1::EDGE_VALUE
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
        context: Context,
        op: &Op,
        error: ApplyError,
    ) -> Option<State<ChannelStore>> {
        let rejected = state.apply(context, op).err()?;

        if rejected == error && *state == *last_state {
            Some(*state)
        } else {
            None
        }
    }

    fn valid_state(
        state: &State<ChannelStore>,
        action: Action,
        context: Context,
        op: &Op,
        event: &EventKind,
    ) -> Option<State<ChannelStore>> {
        match (action, op, event) {
            (
                Action::Open(key),
                Op::Open(operation),
                EventKind::EdgeOpened {
                    inputs: event_inputs,
                    output,
                },
            ) => Self::valid_open(state, key, operation, event_inputs, *output),
            (
                Action::Resolve(proof),
                Op::Resolve(operation),
                EventKind::EdgeResolved {
                    input,
                    outputs: event_outputs,
                },
            ) => Self::valid_resolve(state, proof, context, operation, *input, event_outputs),
            _ => None,
        }
    }

    fn valid_open(
        state: &State<ChannelStore>,
        key: OpenKey,
        operation: &Open,
        inputs: &List<CoinId, MAX_EDGE_INPUTS>,
        output: EdgeId,
    ) -> Option<State<ChannelStore>> {
        let ok = *operation == l1::open_case(key)
            && *inputs == l1::open_case_inputs(key)
            && output == l1::open_case_id(key);

        ok.then_some(*state)
    }

    fn valid_resolve(
        state: &State<ChannelStore>,
        proof: ProofKey,
        context: Context,
        operation: &Resolve,
        input: EdgeId,
        outputs: &List<CoinId, MAX_EDGE_OUTPUTS>,
    ) -> Option<State<ChannelStore>> {
        let ok = input == l1::edge_id(EdgeKey::First)
            && *outputs == l1::output_ids(EdgeKey::First)
            && *operation == l1::resolve(EdgeKey::First, proof)
            && (proof != ProofKey::Timeout || context == l1::TIMEOUT_CONTEXT);

        ok.then_some(*state)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Action {
    Open(OpenKey),
    Resolve(ProofKey),
    InvalidResolve,
    InvalidProof,
}

impl Action {
    const fn context(self) -> Context {
        match self {
            Self::Resolve(ProofKey::Timeout) => l1::TIMEOUT_CONTEXT,
            _ => l1::CONTEXT,
        }
    }

    fn op(self) -> Op {
        match self {
            Self::Open(key) => l1::open_case_op(key),
            Self::Resolve(proof) => Op::Resolve(l1::resolve(EdgeKey::First, proof)),
            Self::InvalidResolve => Op::Resolve(l1::resolve_with(
                EdgeKey::First,
                ProofKey::Basic,
                l1::bad_payouts(),
            )),
            Self::InvalidProof => Op::Resolve(l1::resolve(EdgeKey::First, ProofKey::WrongTerms)),
        }
    }

    fn error(self) -> Option<ApplyError> {
        match self {
            Self::InvalidResolve => Some(ApplyError::InvalidResolve {
                input: l1::edge_id(EdgeKey::First),
            }),
            Self::InvalidProof | Self::Resolve(ProofKey::EarlyTimeout) => {
                Some(ApplyError::InvalidProof {
                    input: l1::edge_id(EdgeKey::First),
                })
            }
            Self::Open(_) | Self::Resolve(_) => None,
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
    l1::genesis(empty_channel())
}

fn empty_channel() -> ChannelStore {
    FixedStore::empty(
        [
            l1::MAKER_ID,
            l1::TAKER_ID,
            l1::maker_out(EdgeKey::First),
            l1::taker_out(EdgeKey::First),
        ],
        [
            l1::open_case_id(OpenKey::Full),
            l1::open_case_id(OpenKey::MakerOnly),
            l1::open_case_id(OpenKey::TakerOnly),
            l1::open_case_id(OpenKey::Empty),
        ],
    )
}

fn channel_shape(view: &ModelView) -> bool {
    funding_shape(view)
        || full_open_shape(view)
        || maker_open_shape(view)
        || taker_open_shape(view)
        || empty_open_shape(view)
        || resolved_shape(view)
}

fn funding_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_some()
        && view.coin(l1::TAKER_ID).is_some()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view.edge_len() == 0
}

fn full_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).is_none()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view.edge(l1::open_case_id(OpenKey::Full)).map(edge_view)
            == Some((l1::EDGE_VALUE, l1::PARTIES))
}

fn maker_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).map(Coin::value) == Some(l1::TAKER_VALUE)
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::MakerOnly))
            .map(edge_view)
            == Some((l1::MAKER_VALUE, l1::PARTIES))
}

fn taker_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).map(Coin::value) == Some(l1::MAKER_VALUE)
        && view.coin(l1::TAKER_ID).is_none()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::TakerOnly))
            .map(edge_view)
            == Some((l1::TAKER_VALUE, l1::PARTIES))
}

fn empty_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).map(Coin::value) == Some(l1::MAKER_VALUE)
        && view.coin(l1::TAKER_ID).map(Coin::value) == Some(l1::TAKER_VALUE)
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view.edge(l1::open_case_id(OpenKey::Empty)).map(edge_view) == Some((0, l1::PARTIES))
}

fn resolved_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).is_none()
        && view.edge_len() == 0
        && view.coin(l1::maker_out(EdgeKey::First)).map(Coin::value) == Some(l1::MAKER_PAYOUT)
        && view.coin(l1::taker_out(EdgeKey::First)).map(Coin::value) == Some(l1::TAKER_PAYOUT)
}

const fn edge_view(edge: Edge) -> (u64, Parties) {
    (edge.value(), edge.parties())
}
