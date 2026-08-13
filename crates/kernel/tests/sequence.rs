//! Generated multi-step operation sequence tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use support::{
    FAKE_VERIFIER,
    l1::{self, EdgeKey, ProofKey},
};

use hellas_kernel::{EventKind, Tx};
use proptest::{
    collection::vec,
    prelude::{Strategy, prop_assert, prop_assert_eq, proptest},
};

const MAX_STEPS: usize = 16;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Step {
    Open(EdgeKey),
    Close(EdgeKey, ProofKey),
    BadPayout(EdgeKey),
}

impl Step {
    const fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Open(EdgeKey::First),
            1 => Self::Open(EdgeKey::Second),
            2 => Self::Close(EdgeKey::First, ProofKey::Mutual),
            3 => Self::Close(EdgeKey::Second, ProofKey::Mutual),
            4 => Self::Close(EdgeKey::First, ProofKey::Timeout),
            5 => Self::Close(EdgeKey::Second, ProofKey::Timeout),
            6 => Self::Close(EdgeKey::First, ProofKey::EarlyTimeout),
            7 => Self::Close(EdgeKey::Second, ProofKey::EarlyTimeout),
            8 => Self::Close(EdgeKey::First, ProofKey::Violation),
            9 => Self::Close(EdgeKey::Second, ProofKey::Violation),
            10 => Self::Close(EdgeKey::First, ProofKey::WrongTerms),
            11 => Self::Close(EdgeKey::Second, ProofKey::BadSeal),
            12 => Self::BadPayout(EdgeKey::First),
            13 => Self::BadPayout(EdgeKey::Second),
            14 => Self::Open(EdgeKey::First),
            _ => Self::Open(EdgeKey::Second),
        }
    }

    const fn context(self) -> hellas_kernel::Context {
        match self {
            Self::Close(_, ProofKey::Timeout) => l1::TIMEOUT_CONTEXT,
            _ => l1::CONTEXT,
        }
    }

    fn op(self) -> Tx {
        match self {
            Self::Open(edge) => l1::open(edge),
            Self::Close(edge, proof) => l1::close(edge, proof),
            // Mutual is the only proof shape that does not bind payouts to
            // terms; sending non-canonical payouts under mutual still goes
            // through close-validation. Pick mutual so this exercises the
            // value-mismatch path in the kernel.
            Self::BadPayout(edge) => l1::close_with(edge, ProofKey::Mutual, l1::bad_payouts()),
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
            let result = state.apply(step.context(), &FAKE_VERIFIER, &op);

            if result.is_err() {
                prop_assert_eq!(state, before);
            }
            if let Ok(outcome) = result {
                prop_assert!(
                    outcome.registry().is_empty(),
                    "{:?} wrote registry state",
                    step,
                );
                let Some(event) = outcome.public_event() else {
                    prop_assert!(false, "{:?} applied without announcing itself", step);
                    unreachable!()
                };
                assert_event_matches(step, event.kind())?;
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
        prop_assert_eq!(edge.terms(), l1::terms().hash());
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
        (Step::Close(edge, proof), EventKind::EdgeClosed { input, outputs })
            if proof_accepts(proof) =>
        {
            prop_assert_eq!(*input, l1::edge_id(edge));
            prop_assert_eq!(outputs, &l1::output_ids(edge));
        }
        // BadPayout closes are value-mismatched; the kernel must reject
        // them (handled by the err branch above), never emit an event.
        _ => prop_assert!(false, "unexpected event {event:?} for step {step:?}"),
    }

    Ok(())
}

const fn proof_accepts(proof: ProofKey) -> bool {
    match proof {
        // FAKE_VERIFIER accepts every placeholder-shaped sig/seal, so
        // Mutual/Violation pass under both feature configs.
        ProofKey::Mutual | ProofKey::Timeout | ProofKey::Violation => true,
        ProofKey::EarlyTimeout | ProofKey::WrongTerms | ProofKey::BadSeal => false,
    }
}
