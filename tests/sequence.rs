//! Generated multi-step operation sequence tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_core)]

mod support;

use support::l1::{self, EdgeKey, ProofKey};

use hellas_kernel::{EventKind, Op};
use proptest::{
    collection::vec,
    prelude::{Strategy, prop_assert, prop_assert_eq, proptest},
};

const MAX_STEPS: usize = 16;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Step {
    Open(EdgeKey),
    Resolve(EdgeKey, ProofKey),
    BadPayout(EdgeKey),
}

impl Step {
    const fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Open(EdgeKey::First),
            1 => Self::Open(EdgeKey::Second),
            2 => Self::Resolve(EdgeKey::First, ProofKey::Basic),
            3 => Self::Resolve(EdgeKey::Second, ProofKey::Basic),
            4 => Self::Resolve(EdgeKey::First, ProofKey::Agreement),
            5 => Self::Resolve(EdgeKey::Second, ProofKey::Agreement),
            6 => Self::Resolve(EdgeKey::First, ProofKey::Timeout),
            7 => Self::Resolve(EdgeKey::Second, ProofKey::Timeout),
            8 => Self::Resolve(EdgeKey::First, ProofKey::EarlyTimeout),
            9 => Self::Resolve(EdgeKey::Second, ProofKey::EarlyTimeout),
            10 => Self::Resolve(EdgeKey::First, ProofKey::Claimant),
            11 => Self::Resolve(EdgeKey::Second, ProofKey::Challenger),
            12 => Self::Resolve(EdgeKey::First, ProofKey::WrongTerms),
            13 => Self::Resolve(EdgeKey::Second, ProofKey::BadSeal),
            14 => Self::BadPayout(EdgeKey::First),
            _ => Self::BadPayout(EdgeKey::Second),
        }
    }

    const fn context(self) -> hellas_kernel::Context {
        match self {
            Self::Resolve(_, ProofKey::Timeout) => l1::TIMEOUT_CONTEXT,
            _ => l1::CONTEXT,
        }
    }

    fn op(self) -> Op {
        match self {
            Self::Open(edge) => Op::Open(l1::open(edge)),
            Self::Resolve(edge, proof) => Op::Resolve(l1::resolve(edge, proof)),
            Self::BadPayout(edge) => {
                Op::Resolve(l1::resolve_with(edge, ProofKey::Basic, l1::bad_payouts()))
            }
        }
    }
}

proptest! {
    #[test]
    fn generated_operation_sequences_conserve_value(steps in vec(step(), 0..=MAX_STEPS)) {
        let mut state = l1::initial_state();

        assert_invariants(&state)?;
        for step in steps {
            let before = state;
            let op = step.op();
            let result = state.apply(step.context(), &op);

            if result.is_err() {
                prop_assert_eq!(state, before);
            }
            if let Ok(event) = result {
                assert_event_matches(step, &event.kind())?;
            }
            assert_invariants(&state)?;
        }
    }
}

fn step() -> impl Strategy<Value = Step> {
    (0_u8..=15).prop_map(Step::from_index)
}

fn assert_invariants(state: &l1::TraceState) -> Result<(), proptest::test_runner::TestCaseError> {
    let view: l1::TraceView = state.view();

    prop_assert_eq!(l1::live_value(&view), l1::EDGE_VALUE);
    prop_assert!(view.edge_len() <= 1);
    for (_, edge) in view.edges() {
        prop_assert_eq!(edge.parties(), l1::PARTIES);
        prop_assert_eq!(edge.terms(), l1::TERMS.hash());
    }

    Ok(())
}

fn assert_event_matches(
    step: Step,
    event: &EventKind,
) -> Result<(), proptest::test_runner::TestCaseError> {
    match (step, event) {
        (Step::Open(edge), EventKind::EdgeOpened { output, .. }) => {
            prop_assert_eq!(*output, l1::edge_id(edge));
        }
        (Step::Resolve(edge, proof), EventKind::EdgeResolved { input, outputs })
            if proof != ProofKey::EarlyTimeout
                && proof != ProofKey::WrongTerms
                && proof != ProofKey::BadSeal =>
        {
            prop_assert_eq!(*input, l1::edge_id(edge));
            prop_assert_eq!(*outputs, l1::output_ids(edge));
        }
        (Step::BadPayout(edge), EventKind::EdgeResolved { input, outputs }) => {
            prop_assert_eq!(*input, l1::edge_id(edge));
            prop_assert_eq!(*outputs, l1::output_ids(edge));
        }
        _ => prop_assert!(false),
    }

    Ok(())
}
