//! Content-addressed catgrad artifact primitives.
//!
//! catnix gives catgrad-shaped objects Nix-like input and output addresses.
//! It deliberately does not know about Hellas receipts, producer
//! signatures, settlement, prices, or evidence — those live in
//! `hellas-core` and consume the IDs catnix produces.
//!
//! # Primitives
//!
//! catnix has two primitive notions:
//!
//! - **[`Value`]**: a marker type for *any* hashable catgrad-shaped
//!   datum. `ValueId = OutputId<Value>` is the universal
//!   content-addressed reference. A Value's identity is the BLAKE3
//!   hash of its canonical DAG-CBOR bytes (produced by some
//!   `Canonical` Rust type).
//! - **[`Term`]**: an input-addressed binding of a program (itself
//!   a Value) to a `BTreeMap<BindingKey, ValueId>` of input Values.
//!   A Term's `TermId = InputId<Term>` is the BLAKE3 hash of its
//!   canonical bytes; the bytes include the program ValueId and
//!   the bindings in canonical (key-sorted) order. Executing a Term
//!   produces a Value.
//!
//! # Caveat on `Term` naming
//!
//! `catnix::Term` is intentionally chosen for the Nix-style
//! input-addressed-derivation concept. It is **not** the same notion as
//! catgrad's `Term` (a graph; see `catgrad::category::lang::types::Term`).
//! Two related but distinct concepts:
//! - catgrad `Term` = the computation graph (`OpenHypergraph<...>`).
//! - catnix `Term` = the bound invocation: this program, these inputs.
//!   The catgrad graph appears here as a Value referenced by `program`.
//!
//! Hellas-kernel's [`hellas_kernel::terms`] module talks about
//! protocol-level *Terms* used in on-chain commitments — a different
//! third notion. Module-qualify in code: prefer `catnix::Term`,
//! `catgrad::category::lang::types::Term`, `hellas_kernel::terms::Terms`
//! to avoid ambiguity.

use std::collections::BTreeMap;
use std::marker::PhantomData;

// ---- Schema tag constants -------------------------------------------------

const TERM_SCHEMA: &str = "catnix.term.v1";
const BINDING_KEY_ARG_SCHEMA: &str = "catnix.binding_key.arg.v1";
const BINDING_KEY_PATH_SCHEMA: &str = "catnix.binding_key.path.v1";
const BINDING_KEY_NAMED_SCHEMA: &str = "catnix.binding_key.named.v1";

const TOKEN_IDS_SCHEMA: &str = "catnix.token_ids.v1";
const TEXT_POLICY_SCHEMA: &str = "catnix.text.policy.v1";
const TEXT_STATE_SCHEMA: &str = "catnix.text.state.v1";
const TEXT_RUN_OUTPUT_SCHEMA: &str = "catnix.text.run_output.v1";
const STOP_REASON_SCHEMA: &str = "catnix.text.stop_reason.v1";

// ---- Digest ---------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({self})")
    }
}

// ---- Canonical encoding / decoding ----------------------------------------

pub trait Canonical {
    fn encode(&self, encoder: &mut DagCborEncoder);

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }

    /// The catnix `ValueId` for this object: BLAKE3 of canonical bytes,
    /// wrapped as `OutputId<Value>`. Every `Canonical` type is a Value
    /// by construction; this is how typed objects (`TokenIds`,
    /// `TextPolicy`, `TextState`, `TextRunOutput`) and untyped catnix
    /// values both produce ValueIds for binding into `Term`s.
    fn value_id(&self) -> ValueId {
        ValueId::from_digest(Digest::from_canonical_bytes(&self.canonical_bytes()))
    }
}

pub trait CanonicalDecode: Canonical + Sized {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
}

/// Marker for input-addressed catnix objects (today: just [`Term`]).
///
/// The associated `Artifact` type names what this input-address
/// produces when evaluated. For [`Term`] that's [`Value`] — the
/// universal catnix output type. There is intentionally no
/// `OutputAddressed` bound on `Artifact`: `Value` is a marker, not a
/// concrete `Canonical` type, so it cannot be `OutputAddressed`
/// itself; what's output-addressed are the concrete `Canonical` types
/// whose `value_id()` produces a `ValueId`.
pub trait InputAddressed: Canonical {
    type Artifact;

    fn input_id(&self) -> InputId<Self>
    where
        Self: Sized,
    {
        InputId::from_digest(Digest::from_canonical_bytes(&self.canonical_bytes()))
    }
}

// ---- Typed CID newtypes ---------------------------------------------------

pub struct InputId<I> {
    digest: Digest,
    _ty: PhantomData<I>,
}

impl<I> InputId<I> {
    pub const fn from_digest(digest: Digest) -> Self {
        Self {
            digest,
            _ty: PhantomData,
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_digest(Digest::from_bytes(bytes))
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl<I> Clone for InputId<I> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I> Copy for InputId<I> {}

impl<I> PartialEq for InputId<I> {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<I> Eq for InputId<I> {}

impl<I> std::hash::Hash for InputId<I> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<I> std::fmt::Display for InputId<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<I> std::fmt::Debug for InputId<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InputId({})", self.digest)
    }
}

pub struct OutputId<O> {
    digest: Digest,
    _ty: PhantomData<O>,
}

impl<O> OutputId<O> {
    pub const fn from_digest(digest: Digest) -> Self {
        Self {
            digest,
            _ty: PhantomData,
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_digest(Digest::from_bytes(bytes))
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl<O> Clone for OutputId<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O> Copy for OutputId<O> {}

impl<O> PartialEq for OutputId<O> {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<O> Eq for OutputId<O> {}

impl<O> std::hash::Hash for OutputId<O> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<O> std::fmt::Display for OutputId<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<O> std::fmt::Debug for OutputId<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutputId({})", self.digest)
    }
}

// ---- Value (marker) + ValueId --------------------------------------------

/// Marker for "any catnix Value". `ValueId = OutputId<Value>` is the
/// universal content-addressed reference catnix uses to identify the
/// canonical bytes of a Canonical object. `Value` itself is uninhabited
/// at the type level — you never have a `Value` instance, only a
/// `ValueId` referring to one.
pub enum Value {}

pub type ValueId = OutputId<Value>;

// ---- Term + TermId + BindingKey ------------------------------------------

/// A binding key into a `Term`'s arguments.
///
/// Three flavors that all canonically distinct:
///
/// - `Arg(u32)`: positional argument, used when the underlying program
///   takes inputs by position.
/// - `Path(Vec<String>)`: hierarchical/path-keyed, used for catgrad
///   parameter trees (catgrad's `BTreeMap<Path, Value>` parameter
///   stores).
/// - `Named(String)`: arbitrary name, used for human-readable bindings
///   in prose-shaped APIs.
///
/// Mixed use within a single `Term` is allowed; the canonical encoding
/// of a `Term` sorts all bindings (regardless of flavor) by their
/// canonical bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum BindingKey {
    Arg(u32),
    Path(Vec<String>),
    Named(String),
}

impl BindingKey {
    pub fn arg(index: u32) -> Self {
        Self::Arg(index)
    }

    pub fn path(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Path(segments.into_iter().map(Into::into).collect())
    }

    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }

    fn encode(&self, encoder: &mut DagCborEncoder) {
        match self {
            Self::Arg(index) => {
                encoder.array(2);
                encoder.str(BINDING_KEY_ARG_SCHEMA);
                encoder.u64(*index as u64);
            }
            Self::Path(segments) => {
                encoder.array(2);
                encoder.str(BINDING_KEY_PATH_SCHEMA);
                encoder.array(segments.len() as u64);
                for segment in segments {
                    encoder.str(segment);
                }
            }
            Self::Named(name) => {
                encoder.array(2);
                encoder.str(BINDING_KEY_NAMED_SCHEMA);
                encoder.str(name);
            }
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }
}

/// An input-addressed binding: this program, called with these inputs.
///
/// A `Term`'s identity (`TermId`) is the BLAKE3 of its canonical
/// DAG-CBOR bytes: the program ValueId followed by an array of
/// `(BindingKey, ValueId)` pairs sorted by `BindingKey`'s canonical
/// byte order. Two implementations that build the same Term with the
/// same bindings produce the same `TermId`.
///
/// The semantics of *what* the program does, and what each binding
/// means, are owned by the program — catnix doesn't interpret either
/// the program's bytes or the bindings' bytes. It only addresses them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Term {
    pub program: ValueId,
    pub bindings: BTreeMap<BindingKey, ValueId>,
}

pub type TermId = InputId<Term>;

impl Term {
    pub fn new(program: ValueId, bindings: BTreeMap<BindingKey, ValueId>) -> Self {
        Self { program, bindings }
    }

    /// Convenience builder for purely-positional Terms.
    pub fn positional(program: ValueId, args: impl IntoIterator<Item = ValueId>) -> Self {
        let bindings = args
            .into_iter()
            .enumerate()
            .map(|(i, v)| (BindingKey::Arg(i as u32), v))
            .collect();
        Self { program, bindings }
    }
}

impl Canonical for Term {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(3);
        encoder.str(TERM_SCHEMA);
        encoder.bytes(self.program.as_bytes());
        // Sort bindings by the canonical bytes of their keys so the
        // encoding is independent of insertion order. BTreeMap already
        // gives us deterministic iteration order by `Ord`, but `Ord`
        // on BindingKey is structural, not canonical-bytes — sort
        // explicitly here to be sure.
        let mut entries: Vec<(&BindingKey, &ValueId)> = self.bindings.iter().collect();
        entries.sort_by(|a, b| a.0.canonical_bytes().cmp(&b.0.canonical_bytes()));
        encoder.array(entries.len() as u64);
        for (key, value) in entries {
            encoder.array(2);
            // Embed each key's canonical bytes inline rather than
            // re-encoding inside an inner array. This keeps the wire
            // shape predictable.
            key.encode(encoder);
            encoder.bytes(value.as_bytes());
        }
    }
}

impl InputAddressed for Term {
    type Artifact = Value;
}

impl CanonicalDecode for Term {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_term)
    }
}

// ---- TokenId + TokenIds (catgrad-text Value) ------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(u32);

impl TokenId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for TokenId {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<i32> for TokenId {
    type Error = TokenIdError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match u32::try_from(value) {
            Ok(value) => Ok(Self(value)),
            Err(_) => Err(TokenIdError { value }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenIdError {
    value: i32,
}

impl TokenIdError {
    pub const fn value(self) -> i32 {
        self.value
    }
}

impl std::fmt::Display for TokenIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "token id {} is negative", self.value)
    }
}

impl std::error::Error for TokenIdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIds {
    tokens: Vec<TokenId>,
}

impl TokenIds {
    pub fn new(tokens: impl Into<Vec<TokenId>>) -> Self {
        Self {
            tokens: tokens.into(),
        }
    }

    pub fn from_u32s(tokens: impl IntoIterator<Item = u32>) -> Self {
        Self {
            tokens: tokens.into_iter().map(TokenId::new).collect(),
        }
    }

    pub fn as_slice(&self) -> &[TokenId] {
        &self.tokens
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl<const N: usize> From<[u32; N]> for TokenIds {
    fn from(value: [u32; N]) -> Self {
        Self::from_u32s(value)
    }
}

impl From<Vec<u32>> for TokenIds {
    fn from(value: Vec<u32>) -> Self {
        Self::from_u32s(value)
    }
}

impl FromIterator<TokenId> for TokenIds {
    fn from_iter<T: IntoIterator<Item = TokenId>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect::<Vec<_>>())
    }
}

impl FromIterator<u32> for TokenIds {
    fn from_iter<T: IntoIterator<Item = u32>>(iter: T) -> Self {
        Self::from_u32s(iter)
    }
}

impl Canonical for TokenIds {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(2);
        encoder.str(TOKEN_IDS_SCHEMA);
        encoder.array(self.tokens.len() as u64);
        for token in &self.tokens {
            encoder.u64(token.as_u32() as u64);
        }
    }
}

impl CanonicalDecode for TokenIds {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_token_ids)
    }
}

// ---- TextPolicy (catgrad-text Value) -------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextPolicy {
    max_new_tokens: u32,
    stop_token_ids: Vec<TokenId>,
}

impl TextPolicy {
    pub fn new(max_new_tokens: u32, stop_token_ids: impl IntoIterator<Item = TokenId>) -> Self {
        let mut stop_token_ids: Vec<_> = stop_token_ids.into_iter().collect();
        stop_token_ids.sort_unstable();
        stop_token_ids.dedup();
        Self {
            max_new_tokens,
            stop_token_ids,
        }
    }

    pub fn from_u32_stop_tokens(
        max_new_tokens: u32,
        stop_token_ids: impl IntoIterator<Item = u32>,
    ) -> Self {
        Self::new(max_new_tokens, stop_token_ids.into_iter().map(TokenId::new))
    }

    pub const fn max_new_tokens(&self) -> u32 {
        self.max_new_tokens
    }

    pub fn stop_token_ids(&self) -> &[TokenId] {
        &self.stop_token_ids
    }
}

impl Canonical for TextPolicy {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(3);
        encoder.str(TEXT_POLICY_SCHEMA);
        encoder.u64(self.max_new_tokens as u64);
        encoder.array(self.stop_token_ids.len() as u64);
        for token in &self.stop_token_ids {
            encoder.u64(token.as_u32() as u64);
        }
    }
}

impl CanonicalDecode for TextPolicy {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_policy)
    }
}

// ---- TextState (catgrad-text Value: materialized decoder state) -----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextState {
    tokens: ValueId,
}

impl TextState {
    pub const fn new(tokens: ValueId) -> Self {
        Self { tokens }
    }

    pub const fn tokens(&self) -> ValueId {
        self.tokens
    }
}

impl Canonical for TextState {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(2);
        encoder.str(TEXT_STATE_SCHEMA);
        encoder.bytes(self.tokens.as_bytes());
    }
}

impl CanonicalDecode for TextState {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_state)
    }
}

// ---- TextRunOutput (catgrad-text Value: result of running a Term) --------

/// Why a text-run terminated.
///
/// Same shape pattern as the now-removed `Dtype`: a `u8` newtype with
/// named constants, deliberately no `Default`, an `unknown()` ctor
/// for forward-compat on the wire. The numeric values intentionally
/// align with `hellas.v1.FinishStatus`'s proto enum so the runtime
/// bridge is a straight byte cast.
///
/// `UNSPECIFIED = 0` exists for forward-compat with serde-decoded
/// reasons that pre-date a particular `stop_reason` migration; the
/// projection layer rejects `UNSPECIFIED` for settlement-relevant
/// runs (a producer signing a receipt with an `UNSPECIFIED` stop
/// reason is hiding what actually happened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StopReason(u8);

impl StopReason {
    pub const UNSPECIFIED: Self = Self(0);
    pub const END_OF_SEQUENCE: Self = Self(1);
    pub const MAX_OUTPUT: Self = Self(2);
    pub const CANCELLED: Self = Self(3);

    pub const fn unknown(byte: u8) -> Self {
        Self(byte)
    }

    pub const fn to_byte(self) -> u8 {
        self.0
    }

    pub const fn is_known_concrete(self) -> bool {
        matches!(self.0, 1 | 2 | 3)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }

    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(2);
        encoder.str(STOP_REASON_SCHEMA);
        encoder.u64(self.to_byte() as u64);
    }
}

/// The Value produced by running a catgrad-text Term.
///
/// Fields:
/// - `term`: the input-addressed `TermId` that was run. For a settled
///   delivery this must equal the `TermId` of the projected `Call`'s
///   payload (CatgradText's `project_result` enforces this).
/// - `position`: the **absolute final decoder position** after the run
///   — that is, `len(initial_state) + len(prompt_prefill) +
///   len(generated)`. NOT the count of newly-generated tokens alone.
///   For a continuation, the previous run's `position` is what the
///   next run's initial state corresponds to.
/// - `state`: ValueId of the materialized decoder state at `position`
///   (a `TextState` whose canonical bytes hash to this id).
/// - `generated_tokens`: ValueId of the tokens generated during this
///   run (a `TokenIds` whose canonical bytes hash to this id).
/// - `stop_reason`: why the run terminated (end-of-sequence,
///   max-output, cancelled, ...). Required because a partial result
///   (e.g. cancelled mid-stream) signed without this distinction
///   would be indistinguishable from a complete one.
///
/// Replaces the old `TextArtifact::Output` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextRunOutput {
    pub term: TermId,
    pub position: u64,
    pub state: ValueId,
    pub generated_tokens: ValueId,
    pub stop_reason: StopReason,
}

impl TextRunOutput {
    pub const fn new(
        term: TermId,
        position: u64,
        state: ValueId,
        generated_tokens: ValueId,
        stop_reason: StopReason,
    ) -> Self {
        Self {
            term,
            position,
            state,
            generated_tokens,
            stop_reason,
        }
    }
}

impl Canonical for TextRunOutput {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(6);
        encoder.str(TEXT_RUN_OUTPUT_SCHEMA);
        encoder.bytes(self.term.as_bytes());
        encoder.u64(self.position);
        encoder.bytes(self.state.as_bytes());
        encoder.bytes(self.generated_tokens.as_bytes());
        encoder.u64(self.stop_reason.to_byte() as u64);
    }
}

impl CanonicalDecode for TextRunOutput {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_run_output)
    }
}

// ---- Decoding ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    message: String,
}

impl DecodeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for DecodeError {}

fn parse_canonical<T: Canonical>(
    bytes: &[u8],
    decode: fn(&mut DagCborDecoder<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut decoder = DagCborDecoder::new(bytes);
    let value = decode(&mut decoder)?;
    decoder.finish()?;
    if value.canonical_bytes() != bytes {
        return Err(DecodeError::new("value is not in catnix canonical form"));
    }
    Ok(value)
}

fn decode_token_ids(decoder: &mut DagCborDecoder<'_>) -> Result<TokenIds, DecodeError> {
    decoder.array_exact(2)?;
    decoder.expect_str(TOKEN_IDS_SCHEMA)?;
    let len = decoder.array_len()?;
    let mut tokens = Vec::with_capacity(len);
    for _ in 0..len {
        tokens.push(TokenId::new(decoder.u32()?));
    }
    Ok(TokenIds::new(tokens))
}

fn decode_text_policy(decoder: &mut DagCborDecoder<'_>) -> Result<TextPolicy, DecodeError> {
    decoder.array_exact(3)?;
    decoder.expect_str(TEXT_POLICY_SCHEMA)?;
    let max_new_tokens = decoder.u32()?;
    let len = decoder.array_len()?;
    let mut stop_token_ids = Vec::with_capacity(len);
    for _ in 0..len {
        stop_token_ids.push(TokenId::new(decoder.u32()?));
    }
    Ok(TextPolicy::new(max_new_tokens, stop_token_ids))
}

fn decode_text_state(decoder: &mut DagCborDecoder<'_>) -> Result<TextState, DecodeError> {
    decoder.array_exact(2)?;
    decoder.expect_str(TEXT_STATE_SCHEMA)?;
    Ok(TextState::new(ValueId::from_bytes(decoder.bytes_32()?)))
}

fn decode_text_run_output(decoder: &mut DagCborDecoder<'_>) -> Result<TextRunOutput, DecodeError> {
    decoder.array_exact(6)?;
    decoder.expect_str(TEXT_RUN_OUTPUT_SCHEMA)?;
    let term = TermId::from_bytes(decoder.bytes_32()?);
    let position = decoder.u64()?;
    let state = ValueId::from_bytes(decoder.bytes_32()?);
    let generated_tokens = ValueId::from_bytes(decoder.bytes_32()?);
    let stop_reason = StopReason::unknown(
        u8::try_from(decoder.u64()?)
            .map_err(|_| DecodeError::new("stop_reason byte exceeds u8 range"))?,
    );
    Ok(TextRunOutput::new(
        term,
        position,
        state,
        generated_tokens,
        stop_reason,
    ))
}

fn decode_binding_key(decoder: &mut DagCborDecoder<'_>) -> Result<BindingKey, DecodeError> {
    decoder.array_exact(2)?;
    match decoder.str()? {
        BINDING_KEY_ARG_SCHEMA => {
            let index = decoder.u32()?;
            Ok(BindingKey::Arg(index))
        }
        BINDING_KEY_PATH_SCHEMA => {
            let len = decoder.array_len()?;
            let mut segments = Vec::with_capacity(len);
            for _ in 0..len {
                segments.push(decoder.str()?.to_string());
            }
            Ok(BindingKey::Path(segments))
        }
        BINDING_KEY_NAMED_SCHEMA => {
            let name = decoder.str()?.to_string();
            Ok(BindingKey::Named(name))
        }
        other => Err(DecodeError::new(format!(
            "unexpected binding key schema tag {other:?}"
        ))),
    }
}

fn decode_term(decoder: &mut DagCborDecoder<'_>) -> Result<Term, DecodeError> {
    decoder.array_exact(3)?;
    decoder.expect_str(TERM_SCHEMA)?;
    let program = ValueId::from_bytes(decoder.bytes_32()?);
    let len = decoder.array_len()?;
    let mut bindings = BTreeMap::new();
    let mut prev_key_bytes: Option<Vec<u8>> = None;
    for _ in 0..len {
        decoder.array_exact(2)?;
        let key = decode_binding_key(decoder)?;
        let key_bytes = key.canonical_bytes();
        if let Some(prev) = &prev_key_bytes {
            if &key_bytes <= prev {
                return Err(DecodeError::new(
                    "term bindings are not in canonical key-byte order",
                ));
            }
        }
        prev_key_bytes = Some(key_bytes);
        let value = ValueId::from_bytes(decoder.bytes_32()?);
        bindings.insert(key, value);
    }
    Ok(Term::new(program, bindings))
}

// ---- DagCborEncoder / DagCborDecoder (unchanged) -------------------------

pub struct DagCborEncoder {
    bytes: Vec<u8>,
}

impl DagCborEncoder {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn array(&mut self, len: u64) {
        self.header(4, len);
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.header(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    pub fn str(&mut self, value: &str) {
        self.header(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.header(0, value);
    }

    pub fn i64(&mut self, value: i64) {
        if value >= 0 {
            self.header(0, value as u64);
        } else {
            self.header(1, (-1_i128 - value as i128) as u64);
        }
    }

    fn header(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => self.bytes.push(major | value as u8),
            24..=0xff => self.bytes.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.bytes.push(major | 25);
                self.bytes.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.bytes.push(major | 26);
                self.bytes.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.bytes.push(major | 27);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

impl Default for DagCborEncoder {
    fn default() -> Self {
        Self::new()
    }
}

struct DagCborDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DagCborDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DecodeError::new(format!(
                "trailing bytes after canonical object: {}",
                self.bytes.len() - self.offset
            )))
        }
    }

    fn array_exact(&mut self, expected: u64) -> Result<(), DecodeError> {
        let actual = self.read_len(4)?;
        if actual == expected {
            Ok(())
        } else {
            Err(DecodeError::new(format!(
                "expected array length {expected}, got {actual}"
            )))
        }
    }

    fn array_len(&mut self) -> Result<usize, DecodeError> {
        usize::try_from(self.read_len(4)?)
            .map_err(|_| DecodeError::new("array length exceeds usize range"))
    }

    fn bytes_32(&mut self) -> Result<[u8; 32], DecodeError> {
        let bytes = self.bytes()?;
        bytes
            .try_into()
            .map_err(|_| DecodeError::new(format!("expected 32 bytes, got {}", bytes.len())))
    }

    fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = usize::try_from(self.read_len(2)?)
            .map_err(|_| DecodeError::new("byte string length exceeds usize range"))?;
        self.read_exact(len)
    }

    fn expect_str(&mut self, expected: &str) -> Result<(), DecodeError> {
        let actual = self.str()?;
        if actual == expected {
            Ok(())
        } else {
            Err(DecodeError::new(format!(
                "expected schema tag {expected:?}, got {actual:?}"
            )))
        }
    }

    fn str(&mut self) -> Result<&'a str, DecodeError> {
        let len = usize::try_from(self.read_len(3)?)
            .map_err(|_| DecodeError::new("text string length exceeds usize range"))?;
        let bytes = self.read_exact(len)?;
        std::str::from_utf8(bytes).map_err(|err| DecodeError::new(format!("invalid utf-8: {err}")))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        u32::try_from(self.u64()?).map_err(|_| DecodeError::new("integer exceeds u32 range"))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        self.read_len(0)
    }

    fn read_len(&mut self, expected_major: u8) -> Result<u64, DecodeError> {
        let first = self.read_u8()?;
        let major = first >> 5;
        if major != expected_major {
            return Err(DecodeError::new(format!(
                "expected CBOR major type {expected_major}, got {major}"
            )));
        }
        let additional = first & 0x1f;
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let value = self.read_u8()? as u64;
                if value < 24 {
                    return Err(DecodeError::new("non-canonical one-byte integer"));
                }
                Ok(value)
            }
            25 => {
                let value = u16::from_be_bytes(self.read_array()?);
                if value <= 0xff {
                    return Err(DecodeError::new("non-canonical two-byte integer"));
                }
                Ok(value as u64)
            }
            26 => {
                let value = u32::from_be_bytes(self.read_array()?);
                if value <= 0xffff {
                    return Err(DecodeError::new("non-canonical four-byte integer"));
                }
                Ok(value as u64)
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array()?);
                if value <= 0xffff_ffff {
                    return Err(DecodeError::new("non-canonical eight-byte integer"));
                }
                Ok(value)
            }
            _ => Err(DecodeError::new(
                "unsupported indefinite or reserved CBOR length",
            )),
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.read_exact(N)?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| DecodeError::new("decoder offset overflow"))?;
        if end > self.bytes.len() {
            return Err(DecodeError::new("unexpected end of CBOR input"));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_exact(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_id_from(byte: u8) -> ValueId {
        ValueId::from_bytes([byte; 32])
    }

    #[test]
    fn token_ids_value_id_depends_on_contents() {
        let a = TokenIds::from([1, 2, 3]);
        let b = TokenIds::from([1, 2, 3]);
        let c = TokenIds::from([3, 2, 1]);

        assert_eq!(
            a.as_slice(),
            &[TokenId::new(1), TokenId::new(2), TokenId::new(3)]
        );
        assert_eq!(a.value_id(), b.value_id());
        assert_ne!(a.value_id(), c.value_id());
    }

    #[test]
    fn negative_model_token_ids_are_rejected_at_the_boundary() {
        assert_eq!(TokenId::try_from(7_i32).unwrap(), TokenId::new(7));
        let err = TokenId::try_from(-1_i32).unwrap_err();
        assert_eq!(err.value(), -1);
    }

    #[test]
    fn policy_canonicalizes_stop_ids() {
        let a = TextPolicy::from_u32_stop_tokens(16, [2, 1, 2]);
        let b = TextPolicy::from_u32_stop_tokens(16, [1, 2]);
        assert_eq!(a.stop_token_ids(), &[TokenId::new(1), TokenId::new(2)]);
        assert_eq!(a.value_id(), b.value_id());
    }

    #[test]
    fn text_state_value_id_depends_on_tokens() {
        let a_tokens = TokenIds::from([1, 2, 3]).value_id();
        let b_tokens = TokenIds::from([1, 2, 4]).value_id();
        let a = TextState::new(a_tokens);
        let b = TextState::new(b_tokens);
        assert_ne!(a.value_id(), b.value_id());
    }

    fn sample_program() -> ValueId {
        value_id_from(0xaa)
    }

    #[test]
    fn term_input_id_changes_when_program_changes() {
        let bindings = {
            let mut m = BTreeMap::new();
            m.insert(BindingKey::Named("from".into()), value_id_from(1));
            m
        };
        let a = Term::new(sample_program(), bindings.clone());
        let b = Term::new(value_id_from(0xbb), bindings);
        assert_ne!(a.input_id(), b.input_id());
    }

    #[test]
    fn term_input_id_changes_when_bindings_change() {
        let program = sample_program();
        let mut bindings_a = BTreeMap::new();
        bindings_a.insert(BindingKey::Named("from".into()), value_id_from(1));
        let mut bindings_b = bindings_a.clone();
        bindings_b.insert(BindingKey::Named("from".into()), value_id_from(2));
        let a = Term::new(program, bindings_a);
        let b = Term::new(program, bindings_b);
        assert_ne!(a.input_id(), b.input_id());
    }

    #[test]
    fn term_input_id_is_independent_of_insertion_order() {
        let program = sample_program();
        let mut bindings_a = BTreeMap::new();
        bindings_a.insert(BindingKey::Named("a".into()), value_id_from(1));
        bindings_a.insert(BindingKey::Named("b".into()), value_id_from(2));
        let mut bindings_b = BTreeMap::new();
        bindings_b.insert(BindingKey::Named("b".into()), value_id_from(2));
        bindings_b.insert(BindingKey::Named("a".into()), value_id_from(1));
        let a = Term::new(program, bindings_a);
        let b = Term::new(program, bindings_b);
        assert_eq!(a.input_id(), b.input_id());
    }

    #[test]
    fn binding_key_flavors_are_canonically_distinct() {
        let program = sample_program();
        let mut bindings_arg = BTreeMap::new();
        bindings_arg.insert(BindingKey::Arg(0), value_id_from(1));
        let mut bindings_named = BTreeMap::new();
        bindings_named.insert(BindingKey::Named("0".into()), value_id_from(1));
        let mut bindings_path = BTreeMap::new();
        bindings_path.insert(BindingKey::Path(vec!["0".into()]), value_id_from(1));
        let a = Term::new(program, bindings_arg);
        let b = Term::new(program, bindings_named);
        let c = Term::new(program, bindings_path);
        assert_ne!(a.input_id(), b.input_id());
        assert_ne!(b.input_id(), c.input_id());
        assert_ne!(a.input_id(), c.input_id());
    }

    #[test]
    fn term_canonical_bytes_round_trip() {
        let program = sample_program();
        let mut bindings = BTreeMap::new();
        bindings.insert(BindingKey::Arg(0), value_id_from(1));
        bindings.insert(BindingKey::Named("name".into()), value_id_from(2));
        bindings.insert(
            BindingKey::Path(vec!["a".into(), "b".into()]),
            value_id_from(3),
        );
        let term = Term::new(program, bindings);
        let bytes = term.canonical_bytes();
        let decoded = Term::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, term);
    }

    #[test]
    fn text_run_output_round_trips() {
        let term = TermId::from_bytes([7; 32]);
        let state = value_id_from(8);
        let tokens = value_id_from(9);
        let out = TextRunOutput::new(term, 5, state, tokens, StopReason::END_OF_SEQUENCE);
        let bytes = out.canonical_bytes();
        let decoded = TextRunOutput::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, out);
    }

    #[test]
    fn text_run_output_value_id_depends_on_stop_reason() {
        let term = TermId::from_bytes([7; 32]);
        let state = value_id_from(8);
        let tokens = value_id_from(9);
        let eos = TextRunOutput::new(term, 5, state, tokens, StopReason::END_OF_SEQUENCE);
        let cancelled = TextRunOutput::new(term, 5, state, tokens, StopReason::CANCELLED);
        // Same term, position, state, tokens — but different stop_reason.
        // Without this binding, a cancelled partial run would be
        // indistinguishable from a completed one at the receipt level.
        assert_ne!(eos.value_id(), cancelled.value_id());
    }

    #[test]
    fn stop_reason_constants_distinct() {
        assert_ne!(StopReason::UNSPECIFIED, StopReason::END_OF_SEQUENCE);
        assert_ne!(StopReason::END_OF_SEQUENCE, StopReason::MAX_OUTPUT);
        assert_ne!(StopReason::MAX_OUTPUT, StopReason::CANCELLED);
    }

    #[test]
    fn stop_reason_known_concrete_excludes_unspecified_and_unknown() {
        assert!(!StopReason::UNSPECIFIED.is_known_concrete());
        assert!(StopReason::END_OF_SEQUENCE.is_known_concrete());
        assert!(StopReason::MAX_OUTPUT.is_known_concrete());
        assert!(StopReason::CANCELLED.is_known_concrete());
        assert!(!StopReason::unknown(255).is_known_concrete());
    }

    #[test]
    fn canonical_text_values_decode_round_trip() {
        let tokens = TokenIds::from([1, 2, 3]);
        assert_eq!(
            TokenIds::from_canonical_bytes(&tokens.canonical_bytes()).unwrap(),
            tokens
        );

        let policy = TextPolicy::from_u32_stop_tokens(16, [4, 5]);
        assert_eq!(
            TextPolicy::from_canonical_bytes(&policy.canonical_bytes()).unwrap(),
            policy
        );

        let state = TextState::new(tokens.value_id());
        assert_eq!(
            TextState::from_canonical_bytes(&state.canonical_bytes()).unwrap(),
            state
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes() {
        let mut bytes = TokenIds::from([1]).canonical_bytes();
        bytes.push(0);

        let err = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn decoder_rejects_wrong_schema() {
        let mut bytes = TokenIds::from([1]).canonical_bytes();
        bytes[2] = b'x';

        let err = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("schema tag"));
    }

    #[test]
    fn decoder_rejects_out_of_order_term_bindings() {
        // Hand-build a Term whose binding bytes are in the wrong order:
        // we encode using a vector instead of a sorted map.
        let mut encoder = DagCborEncoder::new();
        encoder.array(3);
        encoder.str(TERM_SCHEMA);
        encoder.bytes(value_id_from(0xaa).as_bytes());
        encoder.array(2);
        // "b" key first, then "a" — wrong order.
        let key_b = BindingKey::Named("b".into());
        let key_a = BindingKey::Named("a".into());
        encoder.array(2);
        key_b.encode(&mut encoder);
        encoder.bytes(value_id_from(2).as_bytes());
        encoder.array(2);
        key_a.encode(&mut encoder);
        encoder.bytes(value_id_from(1).as_bytes());
        let bytes = encoder.into_bytes();

        let err = Term::from_canonical_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("canonical key-byte order"));
    }
}
