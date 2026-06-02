#![allow(dead_code)]
#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeMap;

use hellas_kernel::{
    Batch, Block, BlockHash, BlockHeight, Coin, CoinId, Context, Cost, Edge, EdgeId, EventKind,
    Fees, Genesis, InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    PayloadHash, Payout, SealVerifier, Sig, SigVerifier, State, Store, Tx,
};
use secp256k1::{Message, Secp256k1, SecretKey};

#[cfg(feature = "webauthn")]
use hellas_kernel::{MAX_WEBAUTHN_DATA_LENGTH, WebAuthnAssertion, WebAuthnData, p256_key};
#[cfg(feature = "webauthn")]
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};
#[cfg(feature = "webauthn")]
use sha2::{Digest, Sha256};

#[derive(Debug, Default)]
pub(crate) struct MemStore {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
}

impl MemStore {
    pub(crate) fn coin_count(&self) -> usize {
        self.coins.len()
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn edge(&self, id: EdgeId) -> Option<Edge> {
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

pub(crate) struct MemTx<'a> {
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

pub(crate) fn genesis(seeds: &[Genesis]) -> State<MemStore> {
    State::genesis(MemStore::default(), seeds).expect("genesis seeds are valid")
}

pub(crate) fn apply_one<V>(
    state: &mut State<MemStore>,
    verifier: &V,
    context: Context,
    operation: Tx,
) -> EventKind
where
    V: SigVerifier + SealVerifier + ?Sized,
{
    let block = Block::new(context, List::all([operation]));
    let diff = state
        .apply_block(verifier, &block)
        .expect("single-op block accepted");
    diff.event(0)
        .expect("single-op block emits one event")
        .kind()
        .clone()
}

pub(crate) fn secp_keypair(seed: u8) -> (SecretKey, Key) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([seed; 32]).expect("non-zero seed");
    let public = secret.public_key(&secp);
    (secret, Key::from_bytes(public.serialize()))
}

pub(crate) fn secp_sign(secret: &SecretKey, hash: PayloadHash) -> Sig {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash.to_bytes());
    let signature = secp.sign_ecdsa(message, secret);
    Sig::from_bytes(signature.serialize_compact())
}

#[cfg(feature = "webauthn")]
pub(crate) fn p256_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("seed is a valid P-256 scalar")
}

#[cfg(feature = "webauthn")]
pub(crate) fn p256_public_key(signing_key: &SigningKey) -> (Key, [u8; 32], [u8; 32]) {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let mut pub_key_x = [0_u8; PayloadHash::LENGTH];
    let mut pub_key_y = [0_u8; PayloadHash::LENGTH];
    pub_key_x.copy_from_slice(point.x().expect("P-256 point has x-coordinate"));
    pub_key_y.copy_from_slice(point.y().expect("P-256 point has y-coordinate"));
    let key = p256_key(&pub_key_x, &pub_key_y).expect("valid P-256 key");
    (key, pub_key_x, pub_key_y)
}

#[cfg(feature = "webauthn")]
pub(crate) fn webauthn_assertion(
    signing_key: &SigningKey,
    hash: PayloadHash,
    origin: &str,
) -> (WebAuthnAssertion, Key) {
    let (key, pub_key_x, pub_key_y) = p256_public_key(signing_key);

    let mut authenticator_data = [0_u8; 37];
    authenticator_data[0..32].copy_from_slice(&[0xaa; 32]);
    authenticator_data[32] = 0x01;

    let challenge = base64url_32(hash.as_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    );

    let client_data_hash = Sha256::digest(client_data_json.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(authenticator_data);
    hasher.update(client_data_hash);
    let message_hash = hasher.finalize();

    let signature: P256Signature = signing_key
        .sign_prehash(&message_hash)
        .expect("P-256 prehash signing succeeds");
    let signature = signature.normalize_s().unwrap_or(signature);
    let sig_bytes = signature.to_bytes();
    let mut r = [0_u8; PayloadHash::LENGTH];
    let mut s = [0_u8; PayloadHash::LENGTH];
    r.copy_from_slice(&sig_bytes[..PayloadHash::LENGTH]);
    s.copy_from_slice(&sig_bytes[PayloadHash::LENGTH..]);

    let mut data = [0_u8; MAX_WEBAUTHN_DATA_LENGTH];
    data[..authenticator_data.len()].copy_from_slice(&authenticator_data);
    let client_data = client_data_json.as_bytes();
    let len = authenticator_data.len() + client_data.len();
    data[authenticator_data.len()..len].copy_from_slice(client_data);
    let webauthn_data: WebAuthnData =
        List::new(data, len).expect("example WebAuthn payload fits kernel bound");

    (
        WebAuthnAssertion::new(r, s, pub_key_x, pub_key_y, webauthn_data),
        key,
    )
}

#[cfg(feature = "webauthn")]
fn base64url_32(input: &[u8; PayloadHash::LENGTH]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(43);
    let mut i = 0;
    while i + 3 <= input.len() {
        let bits =
            (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8) | u32::from(input[i + 2]);
        out.push(char::from(TABLE[((bits >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((bits >> 12) & 0x3f) as usize]));
        out.push(char::from(TABLE[((bits >> 6) & 0x3f) as usize]));
        out.push(char::from(TABLE[(bits & 0x3f) as usize]));
        i += 3;
    }
    let bits = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
    out.push(char::from(TABLE[((bits >> 18) & 0x3f) as usize]));
    out.push(char::from(TABLE[((bits >> 12) & 0x3f) as usize]));
    out.push(char::from(TABLE[((bits >> 6) & 0x3f) as usize]));
    out
}

pub(crate) const fn context(height: u64, hash_byte: u8, fees: Fees) -> Context {
    Context::with_fees(
        BlockHeight::new(height),
        BlockHash::from_bytes([hash_byte; BlockHash::LENGTH]),
        fees,
    )
}

pub(crate) fn context_fee(context: Context, cost: Cost) -> u64 {
    context.fee(cost).expect("fee calculation fits")
}

pub(crate) fn schedule_fee(fees: Fees, cost: Cost) -> u64 {
    fees.charge(cost).expect("fee calculation fits")
}

pub(crate) const fn lifetime_fee(context: Context, timeout: BlockHeight) -> u64 {
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

pub(crate) const fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    List::take([id; MAX_PARTY_INPUTS], 1)
}

pub(crate) const fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    List::empty(CoinId::from_bytes([0; CoinId::LENGTH]))
}

pub(crate) const fn payouts2(
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

pub(crate) const fn payout1(owner: Key, value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    List::take([Payout::new(owner, value); MAX_EDGE_OUTPUTS], 1)
}

pub(crate) const fn coin_id(tag: u8) -> CoinId {
    CoinId::from_bytes([tag; CoinId::LENGTH])
}

pub(crate) fn print_live_coins(store: &MemStore) {
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

pub(crate) fn summarize(event: &EventKind) -> String {
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

pub(crate) fn short(bytes: &[u8]) -> String {
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
