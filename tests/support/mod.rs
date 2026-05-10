#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(dead_code)]

pub(crate) mod l1;
pub(crate) mod map_store;

use hellas_kernel::{
    Coin, CoinId, Edge, EdgeId, Genesis, InsertError, KernelResult, Key, Parties, ProtocolCode,
    ResolveHash, ResolveKind, Seal, Sig, Snapshot, State, Store, TermsHash, Tx, Verifier, View,
};

/// Forgeable verifier used by every test in this crate. Accepts any signature
/// or seal whose bytes match the deterministic placeholder shape, mirroring
/// the behaviour the kernel previously hardwired behind
/// `cfg(feature = "fake-crypto")`. Production callers must wire a verifier
/// backed by real cryptography or a preverified-cache lookup.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct FakeVerifier;

pub(crate) const FAKE_VERIFIER: FakeVerifier = FakeVerifier;

impl Verifier for FakeVerifier {
    fn verify_sig(&self, sig: Sig, key: Key, hash: ResolveHash) -> bool {
        sig == Sig::placeholder(key, hash)
    }

    fn verify_seal(
        &self,
        seal: Seal,
        protocol: ProtocolCode,
        kind: ResolveKind,
        hash: ResolveHash,
    ) -> bool {
        seal == Seal::placeholder(protocol, kind, hash)
    }
}

/// Production-shaped verifier stub: rejects every signature and seal. Tests
/// that exercise "what happens without an accepting verifier" use this to
/// stand in for the unconfigured production case.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct RejectVerifier;

pub(crate) const REJECT_VERIFIER: RejectVerifier = RejectVerifier;

impl Verifier for RejectVerifier {
    fn verify_sig(&self, _sig: Sig, _key: Key, _hash: ResolveHash) -> bool {
        false
    }

    fn verify_seal(
        &self,
        _seal: Seal,
        _protocol: ProtocolCode,
        _kind: ResolveKind,
        _hash: ResolveHash,
    ) -> bool {
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
    type Tx<'a>
        = FixedTx<'a, C, E>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Tx<'_> {
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

impl<const C: usize, const E: usize> Tx for FixedTx<'_, C, E> {
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

pub(crate) const fn edge_view(edge: Edge) -> (u64, u64, Parties, TermsHash) {
    (edge.value(), edge.reserve(), edge.parties(), edge.terms())
}

/// One-coin party funding: a `MAX_PARTY_INPUTS`-sized list with `id` in
/// position 0 and a single live entry. The fill value is `id` itself, which
/// is harmless because `as_slice()` only exposes the first `len` entries.
pub(crate) const fn party_one(
    id: CoinId,
) -> hellas_kernel::List<CoinId, { hellas_kernel::MAX_PARTY_INPUTS }> {
    let Some(list) = hellas_kernel::List::new([id; hellas_kernel::MAX_PARTY_INPUTS], 1) else {
        panic!("one-coin party fits");
    };
    list
}

/// Bilateral payouts with explicit values: `(maker_key, maker_value)` at
/// position 0, `(taker_key, taker_value)` at position 1, len = 2.
pub(crate) const fn payouts_two(
    maker: Key,
    maker_value: u64,
    taker: Key,
    taker_value: u64,
) -> hellas_kernel::List<hellas_kernel::Payout, { hellas_kernel::MAX_EDGE_OUTPUTS }> {
    let payout = hellas_kernel::Payout::new(maker, maker_value);
    let mut buf = [payout; hellas_kernel::MAX_EDGE_OUTPUTS];
    buf[1] = hellas_kernel::Payout::new(taker, taker_value);
    let Some(list) = hellas_kernel::List::new(buf, 2) else {
        panic!("two payouts fit");
    };
    list
}
