//! End-to-end channel lifecycle against a real backend and real crypto.
//!
//! This example shows the kernel composing through its three caller-supplied
//! interfaces:
//!
//!   - `Store` — a minimal `BTreeMap`-backed implementation lives inline
//!     here, mirroring the shape a production backend (e.g.
//!     `commonware-storage::qmdb`) would take. Tests use `MapStore` from
//!     `tests/support/`; downstream code follows the same pattern.
//!   - `Verifier` — `Secp256k1Verifier` from the kernel's `secp256k1`
//!     feature. Real ECDSA, no placeholder semantics.
//!   - `Context` — block height, previous hash, fee schedule. The example
//!     drives the kernel as if a tiny consensus had handed it two finalized
//!     blocks: one with an `Open`, one with a `Resolve`.
//!
//! Build and run with:
//!
//! ```sh
//! cargo run --example end_to_end --features secp256k1
//! ```

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::format_push_string)]
#![allow(clippy::print_stdout)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use hellas_kernel::{
    Agreement, Block, BlockHash, BlockHeight, Coin, CoinId, Context, Edge, EdgeId, EventKind, Fees,
    Funding, Genesis, InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op,
    Open, Parties, Payout, Proof, ProtocolCode, Resolve, ResolveKind, Secp256k1Verifier, Sig,
    Batch, State, Store, Terms,
};
use secp256k1::{Message, Secp256k1, SecretKey};

// ---------------------------------------------------------------------------
// 1. A minimal real-shape Store backend.
//
// Production backends are persistent, authenticated, and concurrency-aware.
// This `MemStore` keeps state in `BTreeMap`s with a copy-on-write working
// snapshot per transaction. Same shape, simpler internals — enough to
// demonstrate the trait wiring.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MemStore {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
}

impl Store for MemStore {
    type Batch<'a>
        = MemTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        let working = (self.coins.clone(), self.edges.clone());
        MemTx {
            coins: working.0,
            edges: working.1,
            parent: self,
        }
    }
}

struct MemTx<'a> {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
    parent: &'a mut MemStore,
}

impl Batch for MemTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.coins.get(&id).copied()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        if self.coins.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        self.coins.remove(&id)
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        if self.edges.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.edges.remove(&id)
    }

    fn commit(self) {
        self.parent.coins = self.coins;
        self.parent.edges = self.edges;
    }
}

// ---------------------------------------------------------------------------
// 2. A real keypair pair via `secp256k1`. The kernel never sees the secrets.
// ---------------------------------------------------------------------------

fn keypair(seed: u8) -> (SecretKey, Key) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([seed; 32]).expect("non-zero seed");
    let public = secret.public_key(&secp);
    (secret, Key::from_bytes(public.serialize()))
}

fn sign(secret: &SecretKey, hash: hellas_kernel::ResolveHash) -> Sig {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash.to_bytes());
    let signature = secp.sign_ecdsa(message, secret);
    Sig::from_bytes(signature.serialize_compact())
}

// ---------------------------------------------------------------------------
// 3. Drive two finalized blocks past the kernel.
// ---------------------------------------------------------------------------

const fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    let Some(list) = List::new([id; MAX_PARTY_INPUTS], 1) else {
        panic!("one-coin party fits");
    };
    list
}

const fn payouts(
    maker: Key,
    taker: Key,
    maker_value: u64,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let payout = Payout::new(maker, maker_value);
    let mut buf = [payout; MAX_EDGE_OUTPUTS];
    buf[1] = Payout::new(taker, taker_value);
    let Some(list) = List::new(buf, 2) else {
        panic!("two payouts fit");
    };
    list
}

fn main() {
    println!("== Hellas kernel end-to-end ==");
    println!();

    // -- Setup ----------------------------------------------------------
    let (maker_sk, maker_pk) = keypair(1);
    let (taker_sk, taker_pk) = keypair(2);
    let parties = Parties::new(maker_pk, taker_pk);

    let maker_coin = CoinId::from_bytes([0xaa; CoinId::LENGTH]);
    let taker_coin = CoinId::from_bytes([0xbb; CoinId::LENGTH]);

    let timeout_payouts = payouts(maker_pk, taker_pk, 6, 4);
    let agreement_payouts = payouts(maker_pk, taker_pk, 7, 8);
    let timeout_height = BlockHeight::new(2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        parties,
        timeout_height,
        timeout_payouts,
    );
    let terms_hash = terms.hash();

    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let open = Open::from_terms(funding, terms);
    let edge = open.output();

    // Production verifier — real ECDSA, no placeholder bytes.
    let verifier = Secp256k1Verifier::new();

    // Genesis the store with two coins owned by the real public keys.
    let mut state = State::genesis(
        MemStore::default(),
        &[
            Genesis::coin(maker_coin, maker_pk, 10),
            Genesis::coin(taker_coin, taker_pk, 5),
        ],
    )
    .expect("genesis seeds the store");
    println!(
        "genesis: maker has 10, taker has 5; store holds {} coins, {} edges",
        state.store().coins.len(),
        state.store().edges.len(),
    );

    // -- Block 1: open the edge ----------------------------------------
    let context_open = Context::with_fees(
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
        Fees::ZERO,
    );
    let block_open = Block::new(context_open, List::all([Op::Open(open)]));
    let diff_open = state
        .apply_block(&verifier, &block_open)
        .expect("open block accepted");
    let event = diff_open.event(0).expect("one event in the open block");
    println!();
    println!("block 1 (height 1): submit Op::Open");
    println!("  emitted event: {}", summarize(&event.kind()));
    println!(
        "  store now: {} coins, {} edges; edge value = {}",
        state.store().coins.len(),
        state.store().edges.len(),
        state
            .store()
            .edges
            .get(&edge)
            .expect("edge present")
            .value(),
    );

    // -- Block 2: cooperative resolve via real ECDSA --------------------
    let resolve_hash = Resolve::payload_hash(
        edge,
        ResolveKind::Agreement,
        terms_hash,
        &agreement_payouts,
    );
    let proof = Proof::agreement(
        terms_hash,
        Agreement::new(sign(&maker_sk, resolve_hash), sign(&taker_sk, resolve_hash)),
    );
    let resolve = Resolve::new(edge, proof, agreement_payouts);
    let context_resolve = Context::with_fees(
        BlockHeight::new(3),
        BlockHash::from_bytes([1; BlockHash::LENGTH]),
        Fees::ZERO,
    );
    let block_resolve = Block::new(context_resolve, List::all([Op::Resolve(resolve)]));
    let diff_resolve = state
        .apply_block(&verifier, &block_resolve)
        .expect("agreement resolve accepted under real ECDSA");
    let event = diff_resolve
        .event(0)
        .expect("one event in the resolve block");
    println!();
    println!("block 2 (height 3): submit Op::Resolve(Agreement)");
    println!("  emitted event: {}", summarize(&event.kind()));
    println!(
        "  store now: {} coins, {} edges",
        state.store().coins.len(),
        state.store().edges.len(),
    );

    // -- Final state ----------------------------------------------------
    println!();
    println!("== Final live coins ==");
    for (id, coin) in &state.store().coins {
        println!(
            "  {:>16}: owner={}, value={}",
            short(id.as_bytes()),
            short(coin.owner().as_bytes()),
            coin.value(),
        );
    }
    println!();
    println!("Done. Kernel never saw a secret key, never hashed a signature,");
    println!("never allocated on the apply path. Three injected interfaces");
    println!("(Store, Verifier, Context) handled the rest.");
}

fn short(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in &bytes[..4] {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push('…');
    for byte in &bytes[bytes.len() - 2..] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn summarize(event: &EventKind) -> String {
    match event {
        EventKind::EdgeOpened { inputs, output } => {
            let inputs: Vec<String> = inputs
                .as_slice()
                .iter()
                .map(|id| short(id.as_bytes()))
                .collect();
            format!(
                "EdgeOpened(inputs=[{}], output={})",
                inputs.join(", "),
                short(output.as_bytes()),
            )
        }
        EventKind::EdgeResolved { input, outputs } => {
            let outputs: Vec<String> = outputs
                .as_slice()
                .iter()
                .map(|id| short(id.as_bytes()))
                .collect();
            format!(
                "EdgeResolved(input={}, outputs=[{}])",
                short(input.as_bytes()),
                outputs.join(", "),
            )
        }
    }
}
