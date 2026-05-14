//! Executable end-to-end reference for the public kernel surface.
//!
//! The example wires the three host-owned boundaries the kernel needs:
//!
//! - `Store`: an inline `BTreeMap` backend with staged rollback semantics.
//! - `SigVerifier`: real secp256k1 ECDSA via `Secp256k1Verifier`.
//! - `Context`: block height, previous hash, and deterministic fees.
//!
//! It runs two small lifecycles:
//!
//! - a bilaterally funded edge closed cooperatively before timeout;
//! - a maker-funded edge closed by timeout, with the taker contributing no
//!   funding but still authorizing the open.
//!
//! Build and run with:
//!
//! ```sh
//! cargo run --example end_to_end --features secp256k1
//! ```

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;

use hellas_kernel::{
    Batch, Block, BlockHash, BlockHeight, CloseKind, Coin, CoinId, Context, Cost, Edge, EdgeId,
    EventKind, Fees, Funding, Genesis, InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, Parties, PayloadHash, Payout, Proof, ProtocolCode, Secp256k1Verifier, Sig,
    State, Store, Terms, Tx,
};
use secp256k1::{Message, Secp256k1, SecretKey};

const FEES: Fees = Fees::new(1, 1, 2, 1);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);

#[derive(Debug)]
struct Wallets {
    maker_secret: SecretKey,
    maker_key: Key,
    taker_secret: SecretKey,
    taker_key: Key,
}

impl Wallets {
    fn deterministic() -> Self {
        let (maker_secret, maker_key) = keypair(1);
        let (taker_secret, taker_key) = keypair(2);
        Self {
            maker_secret,
            maker_key,
            taker_secret,
            taker_key,
        }
    }

    const fn parties(&self) -> Parties {
        Parties::new(self.maker_key, self.taker_key)
    }
}

#[derive(Debug, Default)]
struct MemStore {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
}

impl MemStore {
    fn coin_count(&self) -> usize {
        self.coins.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }

    fn coins(&self) -> impl Iterator<Item = (CoinId, Coin)> + '_ {
        self.coins.iter().map(|(id, coin)| (*id, *coin))
    }
}

impl Store for MemStore {
    type Batch<'a>
        = MemTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        MemTx {
            working: Working {
                coins: self.coins.clone(),
                edges: self.edges.clone(),
            },
            parent: self,
        }
    }
}

#[derive(Debug, Default)]
struct Working {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
}

struct MemTx<'a> {
    working: Working,
    parent: &'a mut MemStore,
}

impl Batch for MemTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.working.coins.get(&id).copied()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        if self.working.coins.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        self.working.coins.remove(&id)
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.working.edges.get(&id).copied()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        if self.working.edges.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.working.edges.remove(&id)
    }

    fn commit(self) {
        self.parent.coins = self.working.coins;
        self.parent.edges = self.working.edges;
    }
}

fn main() {
    let verifier = Secp256k1Verifier::new();
    let wallets = Wallets::deterministic();

    println!("== Hellas kernel end-to-end ==");
    println!(
        "fees: base={}, slot={}, proof={}, lifetime={}/block",
        FEES.base(),
        FEES.slot(),
        FEES.proof(),
        FEES.lifetime(),
    );

    run_bilateral_mutual(&wallets, &verifier);
    run_maker_funded_timeout(&wallets, &verifier);

    println!();
    println!("The kernel saw public keys, signatures, terms, and object ids.");
    println!("Secrets stayed in the host, and dispute seals remain host-defined.");
}

fn run_bilateral_mutual(wallets: &Wallets, verifier: &Secp256k1Verifier) {
    let maker_coin = coin_id(0xa1);
    let taker_coin = coin_id(0xb1);
    let open_context = context(1, 0x10);
    let close_context = context(3, 0x11);
    let timeout = BlockHeight::new(5);
    let timeout_outputs = payouts2(wallets.maker_key, 30, wallets.taker_key, 16);
    let mutual_outputs = payouts2(wallets.maker_key, 28, wallets.taker_key, 16);
    let terms = Terms::basic(PROTOCOL, wallets.parties(), timeout, timeout_outputs);
    let terms_hash = terms.hash();
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = signed_open(wallets, funding, terms);
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);

    let mut state = genesis(&[
        Genesis::coin(maker_coin, wallets.maker_key, 40),
        Genesis::coin(taker_coin, wallets.taker_key, 20),
    ]);

    println!();
    println!("== 1. Bilateral funding, mutual close ==");
    println!(
        "genesis: maker coin=40, taker coin=20; store={} coins/{} edges",
        state.store().coin_count(),
        state.store().edge_count(),
    );

    let event = apply_one(&mut state, verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event)
    );
    println!(
        "  funding 60 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );
    println!(
        "  store={} coins/{} edges",
        state.store().coin_count(),
        state.store().edge_count(),
    );

    let close = signed_mutual_close(wallets, edge_id, terms_hash, mutual_outputs);
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, verifier, close_context, close);
    println!(
        "close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from open-time reserve");
    print_live_coins(state.store());
}

fn run_maker_funded_timeout(wallets: &Wallets, verifier: &Secp256k1Verifier) {
    let maker_coin = coin_id(0xa2);
    let open_context = context(1, 0x20);
    let close_context = context(3, 0x21);
    let timeout = BlockHeight::new(3);
    let timeout_outputs = payout1(wallets.maker_key, 60);
    let terms = Terms::basic(
        PROTOCOL,
        wallets.parties(),
        timeout,
        timeout_outputs.clone(),
    );
    let funding = Funding::new(party_one(maker_coin), empty_party());
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open = signed_open(wallets, funding, terms.clone());
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);

    let mut state = genesis(&[Genesis::coin(maker_coin, wallets.maker_key, 70)]);

    println!();
    println!("== 2. Maker-funded edge, timeout close ==");
    println!("genesis: maker coin=70, taker contributes no coin but signs the open");

    let event = apply_one(&mut state, verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event)
    );
    println!(
        "  funding 70 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );

    let close = Tx::close(edge_id, Proof::timeout(terms), timeout_outputs);
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, verifier, close_context, close);
    println!(
        "timeout close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from reserve; surplus returns through timeout terms");
    print_live_coins(state.store());
}

fn genesis(seeds: &[Genesis]) -> State<MemStore> {
    State::genesis(MemStore::default(), seeds).expect("genesis seeds are valid")
}

fn apply_one(
    state: &mut State<MemStore>,
    verifier: &Secp256k1Verifier,
    context: Context,
    operation: Tx,
) -> EventKind {
    let block = Block::new(context, List::all([operation]));
    let diff = state
        .apply_block(verifier, &block)
        .expect("single-op block accepted");
    diff.event(0)
        .expect("single-op block emits one event")
        .kind()
        .clone()
}

fn signed_open(wallets: &Wallets, funding: Funding, terms: Terms) -> Tx {
    let hash = Tx::open_hash(&funding, &terms);
    Tx::open(
        funding,
        terms,
        sign(&wallets.maker_secret, hash),
        sign(&wallets.taker_secret, hash),
    )
}

fn signed_mutual_close(
    wallets: &Wallets,
    edge_id: EdgeId,
    terms_hash: hellas_kernel::TermsHash,
    outputs: List<Payout, MAX_EDGE_OUTPUTS>,
) -> Tx {
    let hash = Tx::payload_hash(edge_id, CloseKind::Mutual, terms_hash, &outputs);
    Tx::close(
        edge_id,
        Proof::mutual(
            sign(&wallets.maker_secret, hash),
            sign(&wallets.taker_secret, hash),
        ),
        outputs,
    )
}

fn keypair(seed: u8) -> (SecretKey, Key) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([seed; 32]).expect("non-zero seed");
    let public = secret.public_key(&secp);
    (secret, Key::from_bytes(public.serialize()))
}

fn sign(secret: &SecretKey, hash: PayloadHash) -> Sig {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash.to_bytes());
    let signature = secp.sign_ecdsa(message, secret);
    Sig::from_bytes(signature.serialize_compact())
}

const fn context(height: u64, hash_byte: u8) -> Context {
    Context::with_fees(
        BlockHeight::new(height),
        BlockHash::from_bytes([hash_byte; BlockHash::LENGTH]),
        FEES,
    )
}

fn context_fee(context: Context, cost: Cost) -> u64 {
    context.fee(cost).expect("fee calculation fits")
}

fn schedule_fee(fees: Fees, cost: Cost) -> u64 {
    fees.charge(cost).expect("fee calculation fits")
}

const fn lifetime_fee(context: Context, timeout: BlockHeight) -> u64 {
    let blocks = timeout
        .get()
        .checked_sub(context.block_height().get())
        .expect("timeout is in the future");
    context
        .fees()
        .lifetime()
        .checked_mul(blocks)
        .expect("lifetime fee fits")
}

const fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    List::take([id; MAX_PARTY_INPUTS], 1)
}

const fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    List::empty(CoinId::from_bytes([0; CoinId::LENGTH]))
}

const fn payouts2(
    maker: Key,
    maker_value: u64,
    taker: Key,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let first = Payout::new(maker, maker_value);
    let second = Payout::new(taker, taker_value);
    let mut outputs = [first; MAX_EDGE_OUTPUTS];
    outputs[1] = second;
    List::take(outputs, 2)
}

const fn payout1(owner: Key, value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    List::take([Payout::new(owner, value); MAX_EDGE_OUTPUTS], 1)
}

const fn coin_id(tag: u8) -> CoinId {
    CoinId::from_bytes([tag; CoinId::LENGTH])
}

fn print_live_coins(store: &MemStore) {
    println!("  final live coins:");
    for (id, coin) in store.coins() {
        println!(
            "    {} owner={} value={}",
            short(id.as_bytes()),
            short(coin.owner().as_bytes()),
            coin.value(),
        );
    }
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
        EventKind::EdgeClosed { input, outputs } => {
            let outputs: Vec<String> = outputs
                .as_slice()
                .iter()
                .map(|id| short(id.as_bytes()))
                .collect();
            format!(
                "EdgeClosed(input={}, outputs=[{}])",
                short(input.as_bytes()),
                outputs.join(", "),
            )
        }
    }
}

fn short(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in &bytes[..4] {
        push_hex(&mut out, *byte);
    }
    out.push_str("...");
    for byte in &bytes[bytes.len() - 2..] {
        push_hex(&mut out, *byte);
    }
    out
}

fn push_hex(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 0x0f)]));
}
