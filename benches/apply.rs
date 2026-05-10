//! Kernel apply benchmarks.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::std_instead_of_core)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hellas_kernel::{
    Block, BlockHash, BlockHeight, Coin, CoinId, Context, Edge, EdgeId, Funding, Genesis,
    InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open, Parties,
    Payout, Proof, ProtocolCode, Resolve, ResolveHash, ResolveKind, Seal, Sig, State, Store, Terms,
    Tx, Verifier,
};

/// Bench-only verifier: rejects every signature and seal. The benchmark uses
/// only Timeout proofs (no signatures or seals), so the reject answers are
/// never observed.
struct RejectAllVerifier;

impl Verifier for RejectAllVerifier {
    fn verify_sig(&self, _: Sig, _: Key, _: ResolveHash) -> bool {
        false
    }

    fn verify_seal(&self, _: Seal, _: ProtocolCode, _: ResolveKind, _: ResolveHash) -> bool {
        false
    }
}

const MAKER_KEY: Key = Key::from_bytes([7; Key::LENGTH]);
const TAKER_KEY: Key = Key::from_bytes([8; Key::LENGTH]);
const PARTIES: Parties = Parties::new(MAKER_KEY, TAKER_KEY);
const MAKER: CoinId = CoinId::from_bytes([1; CoinId::LENGTH]);
const TAKER: CoinId = CoinId::from_bytes([2; CoinId::LENGTH]);
const NO_PAYOUTS: List<Payout, MAX_EDGE_OUTPUTS> = List::empty(Payout::new(MAKER_KEY, 0));
const TERMS: Terms = Terms::basic(
    ProtocolCode::new(1),
    PARTIES,
    BlockHeight::new(1),
    NO_PAYOUTS,
);
const CONTEXT: Context = Context::new(
    BlockHeight::new(1),
    BlockHash::from_bytes([0; BlockHash::LENGTH]),
);

fn edge() -> EdgeId {
    Open::from_terms(empty_funding(), TERMS).output()
}

fn proof() -> Proof {
    Proof::timeout(TERMS)
}

fn apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply");

    for sets in [1_usize, 1 << 8, 1 << 16] {
        group.bench_with_input(BenchmarkId::from_parameter(sets), &sets, |b, sets| {
            let mut state = state();
            let open = Op::Open(Open::from_terms(empty_funding(), TERMS));
            let resolve = Op::Resolve(Resolve::new(edge(), proof(), no_payouts()));
            let block = Block::new(CONTEXT, List::all([open, resolve]));

            b.iter(|| {
                for _ in 0..*sets {
                    apply_block(&mut state, &block);
                }
                core::hint::black_box((state.store().coin(MAKER), state.store().coin(TAKER)));
            });
        });
    }

    group.finish();
}

fn apply_block(state: &mut State<FixedStore>, block: &Block<2>) {
    let Ok(diff) = state.apply_block(&RejectAllVerifier, block) else {
        panic!("benchmark operation batch rejected");
    };
    core::hint::black_box(diff.len());
}

fn state() -> State<FixedStore> {
    let Ok(state) = State::genesis(
        FixedStore::empty(),
        &[
            Genesis::coin(MAKER, MAKER_KEY, 10),
            Genesis::coin(TAKER, TAKER_KEY, 5),
        ],
    ) else {
        panic!("genesis rejected benchmark seed");
    };
    state
}

fn empty_funding() -> Funding {
    Funding::new(empty_party(), empty_party())
}

fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(inputs) = List::new([MAKER; MAX_PARTY_INPUTS], 0) else {
        panic!("invalid benchmark party list");
    };
    inputs
}

const fn no_payouts() -> List<Payout, MAX_EDGE_OUTPUTS> {
    NO_PAYOUTS
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct CoinSlot {
    id: CoinId,
    coin: Option<Coin>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct EdgeSlot {
    id: EdgeId,
    edge: Option<Edge>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
struct FixedStore {
    coins: [CoinSlot; 2],
    edges: [EdgeSlot; 1],
}

impl FixedStore {
    fn empty() -> Self {
        Self {
            coins: [CoinSlot::empty(MAKER), CoinSlot::empty(TAKER)],
            edges: [EdgeSlot::empty(edge())],
        }
    }

    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.find_coin(id).and_then(|index| self.coins[index].coin)
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.find_edge(id).and_then(|index| self.edges[index].edge)
    }

    fn find_coin(&self, id: CoinId) -> Option<usize> {
        self.coins.iter().position(|slot| slot.id == id)
    }

    fn find_edge(&self, id: EdgeId) -> Option<usize> {
        self.edges.iter().position(|slot| slot.id == id)
    }
}

impl CoinSlot {
    const fn empty(id: CoinId) -> Self {
        Self { id, coin: None }
    }
}

impl EdgeSlot {
    const fn empty(id: EdgeId) -> Self {
        Self { id, edge: None }
    }
}

impl Store for FixedStore {
    type Tx<'a>
        = FixedTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Tx<'_> {
        FixedTx {
            working: *self,
            parent: self,
        }
    }
}

struct FixedTx<'a> {
    working: FixedStore,
    parent: &'a mut FixedStore,
}

impl Tx for FixedTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.working.coin(id)
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        let Some(index) = self.working.find_coin(id) else {
            return Err(InsertError::Unavailable);
        };
        if self.working.coins[index].coin.is_some() {
            return Err(InsertError::Exists);
        }
        self.working.coins[index].coin = Some(coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        let index = self.working.find_coin(id)?;
        self.working.coins[index].coin.take()
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.working.edge(id)
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        let Some(index) = self.working.find_edge(id) else {
            return Err(InsertError::Unavailable);
        };
        if self.working.edges[index].edge.is_some() {
            return Err(InsertError::Exists);
        }
        self.working.edges[index].edge = Some(edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        let index = self.working.find_edge(id)?;
        self.working.edges[index].edge.take()
    }

    fn commit(self) {
        *self.parent = self.working;
    }
}

criterion_group!(benches, apply);
criterion_main!(benches);
