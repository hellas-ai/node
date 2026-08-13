//! Synchronous block working set for kernel block application.

use std::collections::HashMap;

use hellas_kernel::{
    Batch, Coin, CoinId, Edge, EdgeId, InsertError, KernelResult, RegistryChunk, RegistryChunkId,
    Store,
};

/// Synchronous staging area for one block's apply pass.
///
/// Holds one entry per `(CoinId | EdgeId | RegistryChunkId)` the block
/// references, with
/// `None` representing "slot is currently empty" (e.g. an output coin id
/// the block will create) and `Some(_)` representing "slot is currently
/// occupied". The kernel reads through [`Batch::coin`] / [`Batch::edge`]
/// and writes through [`Batch::insert_coin`] / [`Batch::remove_coin`]
/// (analogous for edges).
///
/// **Pre-load required.** Inserts and removes only operate on slots
/// declared in advance via [`Self::insert_coin_slot`] /
/// [`Self::insert_edge_slot`] / [`Self::insert_registry_chunk_slot`]. A
/// kernel write to an unknown slot returns [`InsertError::Unavailable`] —
/// the parallel-execution safety property: the host has to surface every
/// id it intends to mutate.
#[derive(Debug, Clone, Default)]
pub struct BlockWorkingSet {
    coins: HashMap<CoinId, Option<Coin>>,
    edges: HashMap<EdgeId, Option<Edge>>,
    registry: HashMap<RegistryChunkId, Option<RegistryChunk>>,
}

impl BlockWorkingSet {
    /// Creates an empty working set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a coin slot. `coin` is `Some(_)` if the slot is currently
    /// occupied in the backing store, `None` if it's empty (e.g. an
    /// output id the block will produce).
    pub fn insert_coin_slot(&mut self, id: CoinId, coin: Option<Coin>) {
        self.coins.insert(id, coin);
    }

    /// Declares an edge slot. Same semantics as [`Self::insert_coin_slot`].
    pub fn insert_edge_slot(&mut self, id: EdgeId, edge: Option<Edge>) {
        self.edges.insert(id, edge);
    }

    /// Declares a registry chunk slot. Same semantics as
    /// [`Self::insert_coin_slot`].
    pub fn insert_registry_chunk_slot(
        &mut self,
        id: RegistryChunkId,
        chunk: Option<RegistryChunk>,
    ) {
        self.registry.insert(id, chunk);
    }

    /// Reads the current coin at `id`, ignoring pre-load tracking.
    #[must_use]
    pub fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied().flatten()
    }

    /// Reads the current edge at `id`.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied().flatten()
    }

    /// Reads the current registry chunk at `id`.
    #[must_use]
    pub fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied().flatten()
    }
}

impl Store for BlockWorkingSet {
    type Batch<'a>
        = WorkingBatch<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        WorkingBatch {
            coins: self.coins.clone(),
            edges: self.edges.clone(),
            registry: self.registry.clone(),
            parent: self,
        }
    }
}

/// Staged transaction over a [`BlockWorkingSet`].
///
/// Reads observe the working copy; writes mutate the working copy;
/// [`Batch::commit`] copies the working copy back into the parent
/// `BlockWorkingSet`. A dropped (uncommitted) batch rolls back.
pub struct WorkingBatch<'a> {
    coins: HashMap<CoinId, Option<Coin>>,
    edges: HashMap<EdgeId, Option<Edge>>,
    registry: HashMap<RegistryChunkId, Option<RegistryChunk>>,
    parent: &'a mut BlockWorkingSet,
}

impl Batch for WorkingBatch<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied().flatten()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        match self.coins.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.coins.insert(id, Some(coin));
                Ok(())
            }
        }
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        let slot = self.coins.get_mut(&id)?;
        slot.take()
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied().flatten()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        match self.edges.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.edges.insert(id, Some(edge));
                Ok(())
            }
        }
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        let slot = self.edges.get_mut(&id)?;
        slot.take()
    }

    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied().flatten()
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        match self.registry.get(&id) {
            None => Err(InsertError::Unavailable),
            Some(Some(_)) => Err(InsertError::Exists),
            Some(None) => {
                self.registry.insert(id, Some(chunk));
                Ok(())
            }
        }
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        let slot = self.registry.get_mut(&id)?;
        slot.take()
    }

    fn commit(self) {
        self.parent.coins = self.coins;
        self.parent.edges = self.edges;
        self.parent.registry = self.registry;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::{
        Auth, CloseKind, Funding, Genesis, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
        PayloadHash, Payout, ProtocolCode, SealPublicInputs, SealVerifier, Sig, SigVerifier, State,
        Terms, Tx,
    };

    const MAKER: Key = Key::from_bytes([0xaa; Key::LENGTH]);
    const TAKER: Key = Key::from_bytes([0xbb; Key::LENGTH]);

    struct FakeVerifier;
    impl SigVerifier for FakeVerifier {
        fn verify_sig(&self, sig: Sig, key: Key, hash: PayloadHash) -> bool {
            sig == Sig::placeholder(key, hash)
        }
    }
    impl SealVerifier for FakeVerifier {
        fn verify_seal(&self, _seal: hellas_kernel::Seal, _public: &SealPublicInputs<'_>) -> bool {
            false
        }
    }

    fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
        List::new([id; MAX_PARTY_INPUTS], 1).expect("one-coin party")
    }

    fn payouts(maker_value: u64, taker_value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
        let payout = Payout::new(MAKER, maker_value);
        let mut buf = [payout; MAX_EDGE_OUTPUTS];
        buf[1] = Payout::new(TAKER, taker_value);
        List::new(buf, 2).expect("two payouts")
    }

    #[test]
    fn load_apply_replay_round_trip() {
        // -- 1. Genesis: two coins in the durable store, conceptually.
        let maker_coin = CoinId::from_bytes([0x01; CoinId::LENGTH]);
        let taker_coin = CoinId::from_bytes([0x02; CoinId::LENGTH]);

        // -- 2. Build a block: open the edge, immediately mutual-close
        // back to the same parties. Walk the block to enumerate every
        // id it touches; pre-load each into the working set.
        let terms = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(MAKER, TAKER),
            hellas_kernel::BlockHeight::new(2),
            payouts(10, 5),
        );
        let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
        let edge = Tx::edge_id_of(&funding, &terms);

        let open_hash = Tx::open_hash(crate::domain::TEST_NETWORK, &funding, &terms);
        let open = Tx::open(
            funding,
            terms.clone(),
            Auth::native(Sig::placeholder(MAKER, open_hash)),
            Auth::native(Sig::placeholder(TAKER, open_hash)),
        );

        let close_outputs = payouts(10, 5);
        let close_hash = Tx::payload_hash(
            crate::domain::TEST_NETWORK,
            edge,
            CloseKind::Mutual,
            terms.hash(),
            &close_outputs,
        );
        let close_output_ids = Tx::close_output_ids(edge, &close_outputs);
        let close = Tx::close(
            edge,
            hellas_kernel::Proof::mutual(
                Auth::native(Sig::placeholder(MAKER, close_hash)),
                Auth::native(Sig::placeholder(TAKER, close_hash)),
            ),
            close_outputs,
        );

        let mut working = BlockWorkingSet::new();
        working.insert_coin_slot(maker_coin, None);
        working.insert_coin_slot(taker_coin, None);
        working.insert_edge_slot(edge, None);
        for id in close_output_ids.iter() {
            working.insert_coin_slot(*id, None);
        }

        // -- 3. Seed genesis into the working set, then drive the
        // kernel against the resulting state.
        let mut state = State::genesis(
            working,
            &[
                Genesis::coin(maker_coin, MAKER, 10),
                Genesis::coin(taker_coin, TAKER, 5),
            ],
        )
        .expect("genesis seeds the working set");
        let ctx = hellas_kernel::Context::new(
            crate::domain::TEST_NETWORK,
            hellas_kernel::BlockHeight::new(1),
            hellas_kernel::BlockHash::from_bytes([0; hellas_kernel::BlockHash::LENGTH]),
        );
        state
            .apply(ctx, &FakeVerifier, &open)
            .expect("open accepted");
        state
            .apply(ctx, &FakeVerifier, &close)
            .expect("close accepted");

        // -- 5. Inspect only the ids named by the authoritative close event.
        let final_set = state.into_store();
        assert!(
            close_output_ids
                .iter()
                .all(|id| final_set.coin(*id).is_some()),
            "expected every payout coin"
        );
        assert!(final_set.edge(edge).is_none(), "edge should be consumed");

        // Input coins are gone.
        assert!(
            final_set.coin(maker_coin).is_none(),
            "maker_coin should be consumed"
        );
        assert!(
            final_set.coin(taker_coin).is_none(),
            "taker_coin should be consumed"
        );
    }

    #[test]
    fn dropped_batch_rolls_back() {
        // Seed one coin into the working set via genesis, then start
        // a batch, remove the coin, and drop the batch without
        // committing. The slot should still hold the original coin.
        let id = CoinId::from_bytes([0x42; CoinId::LENGTH]);
        let mut working = BlockWorkingSet::new();
        working.insert_coin_slot(id, None);
        let state = State::genesis(working, &[Genesis::coin(id, MAKER, 100)])
            .expect("genesis seeds the working set");
        let mut working = state.into_store();
        assert!(
            working.coin(id).is_some(),
            "post-genesis slot must hold a coin"
        );

        {
            let mut batch = working.begin();
            let _ = batch.remove_coin(id);
            // Drop without committing.
        }

        assert!(
            working.coin(id).is_some(),
            "uncommitted remove must roll back"
        );
    }
}
