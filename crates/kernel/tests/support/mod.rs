#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(dead_code)]

pub(crate) mod itf;
pub(crate) mod itf_l1_fees;
pub(crate) mod l1;
pub(crate) mod l1_fees;
pub(crate) mod map_store;

use hellas_kernel::{
    Auth, Batch, BlockHeight, CloseKind, Coin, CoinId, Edge, EdgeId, Funding, Genesis, InsertError,
    KernelResult, Key, List, MAX_EDGE_OUTPUTS, Parties, PayloadHash, Payout, Proof, Seal,
    SealPublicInputs, SealVerifier, Sig, SigVerifier, Snapshot, State, Store, Terms, TermsHash, Tx,
    View,
};

/// Forgeable verifier used by every test in this crate. Accepts the
/// deterministic shapes produced by [`Sig::placeholder`] /
/// [`Seal::placeholder`] in place of real cryptography. Production
/// callers must wire verifiers backed by real crypto or a preverified-
/// cache lookup.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct FakeVerifier;

pub(crate) const FAKE_VERIFIER: FakeVerifier = FakeVerifier;

impl SigVerifier for FakeVerifier {
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: hellas_kernel::PayloadHash) -> bool {
        sig == Sig::placeholder(party_key, hash)
    }
}

impl SealVerifier for FakeVerifier {
    fn verify_seal(&self, seal: Seal, public: &SealPublicInputs<'_>) -> bool {
        let hash = Tx::payload_hash(
            public.edge_id,
            CloseKind::Violation,
            public.terms_hash,
            public.payouts,
        );
        seal == Seal::placeholder(public.protocol, CloseKind::Violation, hash)
    }
}

/// Production-shaped verifier stub: rejects every signature and seal.
/// Tests that exercise "what happens without an accepting verifier" use
/// this to stand in for the unconfigured production case.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct RejectVerifier;

pub(crate) const REJECT_VERIFIER: RejectVerifier = RejectVerifier;

impl SigVerifier for RejectVerifier {
    fn verify_sig(&self, _sig: Sig, _party_key: Key, _hash: hellas_kernel::PayloadHash) -> bool {
        false
    }
}

impl SealVerifier for RejectVerifier {
    fn verify_seal(&self, _seal: Seal, _public: &SealPublicInputs<'_>) -> bool {
        false
    }
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
pub(crate) struct FixedStore<const C: usize, const E: usize> {
    coins: [CoinSlot; C],
    edges: [EdgeSlot; E],
}

impl<const C: usize, const E: usize> FixedStore<C, E> {
    pub(crate) const fn empty(coins: [CoinId; C], edges: [EdgeId; E]) -> Self {
        let mut coin_slots = [CoinSlot::EMPTY; C];
        let mut edge_slots = [EdgeSlot::EMPTY; E];
        let mut index = 0;

        while index < C {
            coin_slots[index] = CoinSlot::empty(coins[index]);
            index += 1;
        }

        index = 0;
        while index < E {
            edge_slots[index] = EdgeSlot::empty(edges[index]);
            index += 1;
        }

        Self {
            coins: coin_slots,
            edges: edge_slots,
        }
    }

    pub(crate) fn coin(&self, id: CoinId) -> Option<Coin> {
        self.find_coin(id).and_then(|index| self.coins[index].coin)
    }

    pub(crate) fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.find_edge(id).and_then(|index| self.edges[index].edge)
    }

    fn find_coin(&self, id: CoinId) -> Option<usize> {
        self.coins.iter().position(|slot| slot.id == id)
    }

    fn find_edge(&self, id: EdgeId) -> Option<usize> {
        self.edges.iter().position(|slot| slot.id == id)
    }
}

impl<const C: usize, const E: usize> Store for FixedStore<C, E> {
    type Batch<'a>
        = FixedTx<'a, C, E>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        FixedTx {
            working: *self,
            parent: self,
        }
    }
}

pub(crate) struct FixedTx<'a, const C: usize, const E: usize> {
    working: FixedStore<C, E>,
    parent: &'a mut FixedStore<C, E>,
}

impl<const C: usize, const E: usize> Batch for FixedTx<'_, C, E> {
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

impl<const C: usize, const E: usize> Snapshot for FixedStore<C, E> {
    type View = View<C, E>;

    fn view(&self) -> Self::View {
        View::new(
            self.coins.map(|slot| slot.coin.map(|coin| (slot.id, coin))),
            self.edges.map(|slot| slot.edge.map(|edge| (slot.id, edge))),
        )
    }
}

impl CoinSlot {
    const EMPTY: Self = Self {
        id: CoinId::from_bytes([0; CoinId::LENGTH]),
        coin: None,
    };

    const fn empty(id: CoinId) -> Self {
        Self { id, coin: None }
    }
}

impl EdgeSlot {
    const EMPTY: Self = Self {
        id: EdgeId::from_bytes([0; EdgeId::LENGTH]),
        edge: None,
    };

    const fn empty(id: EdgeId) -> Self {
        Self { id, edge: None }
    }
}

pub(crate) fn state<const C: usize, const E: usize, const G: usize>(
    store: FixedStore<C, E>,
    seeds: [Genesis; G],
) -> State<FixedStore<C, E>> {
    let Ok(state) = State::genesis(store, &seeds) else {
        panic!("genesis rejected test seed");
    };
    state
}

pub(crate) const fn coin_id(byte: u8) -> CoinId {
    CoinId::from_bytes([byte; CoinId::LENGTH])
}

pub(crate) const fn edge_id(byte: u8) -> EdgeId {
    EdgeId::from_bytes([byte; EdgeId::LENGTH])
}

pub(crate) const fn key(byte: u8) -> Key {
    Key::from_bytes([byte; Key::LENGTH])
}

pub(crate) const fn coin_view(coin: Coin) -> (Key, u64) {
    (coin.owner(), coin.value())
}

pub(crate) const fn edge_view(edge: Edge) -> (u64, u64, BlockHeight, Parties, TermsHash) {
    (
        edge.value(),
        edge.reserve(),
        edge.timeout(),
        edge.parties(),
        edge.terms(),
    )
}

/// Bounded list literal: the given items live, remaining slots defaulted.
/// The capacity `N` is inferred from the call site.
pub(crate) fn list<T: Copy + Default, const N: usize>(items: &[T]) -> List<T, N> {
    let mut buf = [T::default(); N];
    buf[..items.len()].copy_from_slice(items);
    let Some(list) = List::new(buf, items.len()) else {
        panic!("test list exceeds capacity");
    };
    list
}

/// Payout list literal from `(owner, value)` pairs.
pub(crate) fn payouts(entries: &[(Key, u64)]) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let mut buf = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, (owner, value)) in buf.iter_mut().zip(entries) {
        *slot = Payout::new(*owner, *value);
    }
    let Some(list) = List::new(buf, entries.len()) else {
        panic!("test payouts exceed capacity");
    };
    list
}

/// `Tx::Open` authorized with the placeholder sigs `FAKE_VERIFIER`
/// accepts, keyed to `maker`/`taker`. Adversarial tests pass mismatching
/// keys.
pub(crate) fn open_tx(funding: Funding, terms: Terms, maker: Key, taker: Key) -> Tx {
    let hash = Tx::open_hash(&funding, &terms);
    Tx::open(
        funding,
        terms,
        Auth::native(Sig::placeholder(maker, hash)),
        Auth::native(Sig::placeholder(taker, hash)),
    )
}

/// Placeholder-signed mutual close proof over the canonical close payload.
pub(crate) fn placeholder_mutual(
    input: EdgeId,
    terms: TermsHash,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    maker: Key,
    taker: Key,
) -> Proof {
    let hash = mutual_hash(input, terms, outputs);
    Proof::mutual(
        Auth::native(Sig::placeholder(maker, hash)),
        Auth::native(Sig::placeholder(taker, hash)),
    )
}

/// Canonical payload hash a mutual close witness signs.
pub(crate) fn mutual_hash(
    input: EdgeId,
    terms: TermsHash,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> PayloadHash {
    Tx::payload_hash(input, CloseKind::Mutual, terms, outputs)
}

/// Placeholder seal bound to the canonical violation close payload, as
/// `FAKE_VERIFIER` expects.
pub(crate) fn placeholder_seal(
    input: EdgeId,
    terms: &Terms,
    outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
) -> Seal {
    let hash = Tx::payload_hash(input, CloseKind::Violation, terms.hash(), outputs);
    Seal::placeholder(terms.protocol(), CloseKind::Violation, hash)
}
