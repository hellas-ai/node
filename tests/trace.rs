//! Replay checks for abstract model traces against concrete Rust state.

mod support;

use support::{
    coin_view,
    l1::{
        EDGE_VALUE, EdgeKey, MAKER, MAKER_ID, MAKER_PAYOUT, MAKER_VALUE, ProofKey, Step, TAKER,
        TAKER_ID, TAKER_PAYOUT, TAKER_VALUE, TraceState, TraceView, edge_id, edge_value,
        initial_state, maker_out, taker_out,
    },
};

use hellas_kernel::ApplyError;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct Trace<const N: usize> {
    frames: [Frame; N],
}

impl<const N: usize> Trace<N> {
    const fn new(frames: [Frame; N]) -> Self {
        Self { frames }
    }

    fn replay(&self) {
        let mut state = initial_state();

        Shape::Genesis.check(&state);
        for frame in self.frames {
            frame.replay(&mut state);
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct Frame {
    step: Step,
    out: Out,
}

impl Frame {
    const fn accept(step: Step, shape: Shape) -> Self {
        Self {
            step,
            out: Out::Accept(shape),
        }
    }

    const fn reject(step: Step, error: ApplyError, shape: Shape) -> Self {
        Self {
            step,
            out: Out::Reject(error, shape),
        }
    }

    fn replay(self, state: &mut TraceState) {
        let Some(op) = self.step.op() else {
            panic!("trace step has no operation");
        };

        match self.out {
            Out::Accept(shape) => {
                let Ok(event) = state.apply(self.step.context(), &op) else {
                    panic!("trace move rejected");
                };
                self.step.check(&event.kind());
                shape.check(state);
            }
            Out::Reject(error, shape) => {
                let before = *state;
                assert_eq!(state.apply(self.step.context(), &op), Err(error));
                assert_eq!(*state, before);
                shape.check(state);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Out {
    Accept(Shape),
    Reject(ApplyError, Shape),
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum Shape {
    Genesis,
    Edge(EdgeKey),
    Payout(EdgeKey),
}

impl Shape {
    fn check(self, state: &TraceState) {
        let view: TraceView = state.view();

        match self {
            Self::Genesis => {
                assert_eq!(view.coin_len(), 2);
                assert_eq!(view.edge_len(), 0);
                assert_eq!(
                    view.coin(MAKER_ID).map(coin_view),
                    Some((MAKER, MAKER_VALUE)),
                );
                assert_eq!(
                    view.coin(TAKER_ID).map(coin_view),
                    Some((TAKER, TAKER_VALUE)),
                );
            }
            Self::Edge(edge) => {
                assert_eq!(view.coin_len(), 0);
                assert_eq!(view.edge_len(), 1);
                assert_eq!(view.edge(edge_id(edge)).map(edge_value), Some(EDGE_VALUE));
            }
            Self::Payout(edge) => {
                assert_eq!(view.coin_len(), 2);
                assert_eq!(view.edge_len(), 0);
                assert_eq!(
                    view.coin(maker_out(edge)).map(coin_view),
                    Some((MAKER, MAKER_PAYOUT)),
                );
                assert_eq!(
                    view.coin(taker_out(edge)).map(coin_view),
                    Some((TAKER, TAKER_PAYOUT)),
                );
            }
        }
    }
}

#[test]
fn replays_basic_trace() {
    Trace::new([
        Frame::accept(Step::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Step::Resolve(EdgeKey::First, ProofKey::Timeout),
            Shape::Payout(EdgeKey::First),
        ),
    ])
    .replay();
}

#[test]
#[cfg(feature = "fake-crypto")]
fn replays_agreement_then_timeout_trace() {
    Trace::new([
        Frame::accept(Step::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Step::Resolve(EdgeKey::First, ProofKey::Agreement),
            Shape::Payout(EdgeKey::First),
        ),
        Frame::accept(Step::Open(EdgeKey::Second), Shape::Edge(EdgeKey::Second)),
        Frame::accept(
            Step::Resolve(EdgeKey::Second, ProofKey::Timeout),
            Shape::Payout(EdgeKey::Second),
        ),
    ])
    .replay();
}

#[test]
#[cfg(feature = "fake-crypto")]
fn replays_dispute_outcome_trace() {
    Trace::new([
        Frame::accept(Step::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::accept(
            Step::Resolve(EdgeKey::First, ProofKey::Claimant),
            Shape::Payout(EdgeKey::First),
        ),
        Frame::accept(Step::Open(EdgeKey::Second), Shape::Edge(EdgeKey::Second)),
        Frame::accept(
            Step::Resolve(EdgeKey::Second, ProofKey::Challenger),
            Shape::Payout(EdgeKey::Second),
        ),
    ])
    .replay();
}

#[test]
fn replays_rejected_trace_step_without_mutation() {
    Trace::new([
        Frame::accept(Step::Open(EdgeKey::First), Shape::Edge(EdgeKey::First)),
        Frame::reject(
            Step::Resolve(EdgeKey::First, ProofKey::EarlyTimeout),
            ApplyError::InvalidProof {
                input: edge_id(EdgeKey::First),
            },
            Shape::Edge(EdgeKey::First),
        ),
        Frame::accept(
            Step::Resolve(EdgeKey::First, ProofKey::Timeout),
            Shape::Payout(EdgeKey::First),
        ),
    ])
    .replay();
}
