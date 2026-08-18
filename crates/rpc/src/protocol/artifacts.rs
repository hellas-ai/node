//! Content-addressed evaluate artifact schema.
//!
//! These are the canonical bodies an execution is addressed by: the
//! prompt tokens, the generation policy, the execution that binds them to
//! a source, and the identity or output artifact that source resolves to.
//! Their bytes are content ids, so there is exactly one encoder and one
//! decoder for them in the workspace.
//!
//! They live in the neutral RPC protocol crate rather than in the
//! executor because both endpoints need them: the provider builds these
//! bodies while executing, and the client must rebuild them to check a
//! paid result rather than accepting a returned digest. A second
//! implementation on the client side would be a second opinion about what
//! a content id means.
//!
//! The decoder is strict in the way a content-addressed schema has to be:
//! [`CanonicalDecode::from_canonical_bytes`] re-encodes what it decoded
//! and rejects any input whose bytes it does not reproduce, so a
//! noncanonical integer, a reordered field, or a trailing byte cannot
//! produce a value that would hash to a different id than it arrived
//! under.

use crate::{DagCborEncoder, Digest};
use std::{format, marker::PhantomData, str, string::String, vec::Vec};

const SOURCE_INPUT_SCHEMA: &str = "hellas.evaluate.source.input.v1";
const SOURCE_OUTPUT_SCHEMA: &str = "hellas.evaluate.source.output.v1";
const TOKEN_IDS_SCHEMA: &str = "hellas.evaluate.token_ids.v1";
const TEXT_POLICY_SCHEMA: &str = "hellas.evaluate.text.policy.v1";
const TEXT_EXECUTION_SCHEMA: &str = "hellas.evaluate.text.execution.v1";
const TEXT_STATE_SCHEMA: &str = "hellas.evaluate.text.state.v1";
const TEXT_ARTIFACT_IDENTITY_SCHEMA: &str = "hellas.evaluate.text.artifact.identity.v1";
const TEXT_ARTIFACT_OUTPUT_SCHEMA: &str = "hellas.evaluate.text.artifact.output.v1";

pub trait Canonical {
    fn encode(&self, encoder: &mut DagCborEncoder);

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }
}

pub trait CanonicalDecode: Canonical + Sized {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
}

pub trait InputAddressed: Canonical {
    type Artifact: OutputAddressed;

    fn input_id(&self) -> InputId<Self>
    where
        Self: Sized,
    {
        InputId::from_digest(Digest::hash(&self.canonical_bytes()))
    }
}

pub trait OutputAddressed: Canonical {
    fn output_id(&self) -> OutputId<Self>
    where
        Self: Sized,
    {
        OutputId::from_digest(Digest::hash(&self.canonical_bytes()))
    }
}

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

impl<I> core::hash::Hash for InputId<I> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<I> core::fmt::Display for InputId<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<I> core::fmt::Debug for InputId<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl<O> core::hash::Hash for OutputId<O> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<O> core::fmt::Display for OutputId<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<O> core::fmt::Debug for OutputId<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OutputId({})", self.digest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceRef<I: InputAddressed> {
    Input(InputId<I>),
    Output(OutputId<I::Artifact>),
}

impl<I: InputAddressed> SourceRef<I> {
    pub const fn input(id: InputId<I>) -> Self {
        Self::Input(id)
    }

    pub const fn output(id: OutputId<I::Artifact>) -> Self {
        Self::Output(id)
    }

    fn encode(&self, encoder: &mut DagCborEncoder) {
        match self {
            Self::Input(id) => {
                encoder.array(2);
                encoder.str(SOURCE_INPUT_SCHEMA);
                encoder.bytes(id.as_bytes());
            }
            Self::Output(id) => {
                encoder.array(2);
                encoder.str(SOURCE_OUTPUT_SCHEMA);
                encoder.bytes(id.as_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoundTerm;

pub type BoundTermId = OutputId<BoundTerm>;
pub type TokenIdsId = OutputId<TokenIds>;
pub type TextPolicyId = OutputId<TextPolicy>;
pub type TextExecutionId = InputId<TextExecution>;
pub type TextArtifactId = OutputId<TextArtifact>;
pub type TextStateId = OutputId<TextState>;

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

impl core::fmt::Display for TokenId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    #[cfg(test)]
    fn value(self) -> i32 {
        self.value
    }
}

impl core::fmt::Display for TokenIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "token id {} is negative", self.value)
    }
}

impl core::error::Error for TokenIdError {}

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

impl OutputAddressed for TokenIds {}

impl CanonicalDecode for TokenIds {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_token_ids)
    }
}

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

impl OutputAddressed for TextPolicy {}

impl CanonicalDecode for TextPolicy {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_policy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextState {
    tokens: TokenIdsId,
}

impl TextState {
    pub const fn new(tokens: TokenIdsId) -> Self {
        Self { tokens }
    }

    pub const fn tokens(&self) -> TokenIdsId {
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

impl OutputAddressed for TextState {}

impl CanonicalDecode for TextState {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_state)
    }
}

pub type TextSource = SourceRef<TextExecution>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextExecution {
    from: TextSource,
    prompt_tokens: TokenIdsId,
    policy: TextPolicyId,
}

impl TextExecution {
    pub const fn new(from: TextSource, prompt_tokens: TokenIdsId, policy: TextPolicyId) -> Self {
        Self {
            from,
            prompt_tokens,
            policy,
        }
    }

    pub const fn from(&self) -> &TextSource {
        &self.from
    }

    pub const fn prompt_tokens(&self) -> TokenIdsId {
        self.prompt_tokens
    }

    pub const fn policy(&self) -> TextPolicyId {
        self.policy
    }
}

impl Canonical for TextExecution {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(4);
        encoder.str(TEXT_EXECUTION_SCHEMA);
        self.from.encode(encoder);
        encoder.bytes(self.prompt_tokens.as_bytes());
        encoder.bytes(self.policy.as_bytes());
    }
}

impl InputAddressed for TextExecution {
    type Artifact = TextArtifact;
}

impl CanonicalDecode for TextExecution {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_execution)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextOutput {
    execution: TextExecutionId,
    position: u64,
    state: TextStateId,
    generated_tokens: TokenIdsId,
}

impl TextOutput {
    pub const fn new(
        execution: TextExecutionId,
        position: u64,
        state: TextStateId,
        generated_tokens: TokenIdsId,
    ) -> Self {
        Self {
            execution,
            position,
            state,
            generated_tokens,
        }
    }

    pub const fn execution(&self) -> TextExecutionId {
        self.execution
    }

    pub const fn state(&self) -> TextStateId {
        self.state
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextArtifact {
    Identity {
        bound_term: BoundTermId,
        model_id: String,
        revision: String,
        dtype: String,
    },
    Output(TextOutput),
}

impl TextArtifact {
    pub fn identity(
        bound_term: BoundTermId,
        model_id: impl Into<String>,
        revision: impl Into<String>,
        dtype: impl Into<String>,
    ) -> Self {
        Self::Identity {
            bound_term,
            model_id: model_id.into(),
            revision: revision.into(),
            dtype: dtype.into(),
        }
    }

    pub const fn output(
        execution: TextExecutionId,
        position: u64,
        state: TextStateId,
        generated_tokens: TokenIdsId,
    ) -> Self {
        Self::Output(TextOutput::new(
            execution,
            position,
            state,
            generated_tokens,
        ))
    }
}

impl Canonical for TextArtifact {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        match self {
            Self::Identity {
                bound_term,
                model_id,
                revision,
                dtype,
            } => {
                encoder.array(5);
                encoder.str(TEXT_ARTIFACT_IDENTITY_SCHEMA);
                encoder.bytes(bound_term.as_bytes());
                encoder.str(model_id);
                encoder.str(revision);
                encoder.str(dtype);
            }
            Self::Output(output) => {
                encoder.array(5);
                encoder.str(TEXT_ARTIFACT_OUTPUT_SCHEMA);
                encoder.bytes(output.execution.as_bytes());
                encoder.u64(output.position);
                encoder.bytes(output.state.as_bytes());
                encoder.bytes(output.generated_tokens.as_bytes());
            }
        }
    }
}

impl OutputAddressed for TextArtifact {}

impl CanonicalDecode for TextArtifact {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        parse_canonical(bytes, decode_text_artifact)
    }
}

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

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.message.fmt(f)
    }
}

impl core::error::Error for DecodeError {}

fn parse_canonical<T: Canonical>(
    bytes: &[u8],
    decode: fn(&mut DagCborDecoder<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut decoder = DagCborDecoder::new(bytes);
    let value = decode(&mut decoder)?;
    decoder.finish()?;
    if value.canonical_bytes() != bytes {
        return Err(DecodeError::new("value is not in canonical artifact form"));
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
    Ok(TextState::new(TokenIdsId::from_bytes(decoder.bytes_32()?)))
}

fn decode_text_source(decoder: &mut DagCborDecoder<'_>) -> Result<TextSource, DecodeError> {
    decoder.array_exact(2)?;
    match decoder.str()? {
        SOURCE_INPUT_SCHEMA => Ok(SourceRef::input(TextExecutionId::from_bytes(
            decoder.bytes_32()?,
        ))),
        SOURCE_OUTPUT_SCHEMA => Ok(SourceRef::output(TextArtifactId::from_bytes(
            decoder.bytes_32()?,
        ))),
        other => Err(DecodeError::new(format!(
            "unexpected text source schema tag {other:?}"
        ))),
    }
}

fn decode_text_execution(decoder: &mut DagCborDecoder<'_>) -> Result<TextExecution, DecodeError> {
    decoder.array_exact(4)?;
    decoder.expect_str(TEXT_EXECUTION_SCHEMA)?;
    let from = decode_text_source(decoder)?;
    let prompt_tokens = TokenIdsId::from_bytes(decoder.bytes_32()?);
    let policy = TextPolicyId::from_bytes(decoder.bytes_32()?);
    Ok(TextExecution::new(from, prompt_tokens, policy))
}

fn decode_text_artifact(decoder: &mut DagCborDecoder<'_>) -> Result<TextArtifact, DecodeError> {
    let len = decoder.array_len()?;
    match decoder.str()? {
        TEXT_ARTIFACT_IDENTITY_SCHEMA => {
            if len != 5 {
                return Err(DecodeError::new(format!(
                    "{TEXT_ARTIFACT_IDENTITY_SCHEMA} expected array length 5, got {len}"
                )));
            }
            Ok(TextArtifact::identity(
                BoundTermId::from_bytes(decoder.bytes_32()?),
                decoder.str()?,
                decoder.str()?,
                decoder.str()?,
            ))
        }
        TEXT_ARTIFACT_OUTPUT_SCHEMA => {
            if len != 5 {
                return Err(DecodeError::new(format!(
                    "{TEXT_ARTIFACT_OUTPUT_SCHEMA} expected array length 5, got {len}"
                )));
            }
            Ok(TextArtifact::output(
                TextExecutionId::from_bytes(decoder.bytes_32()?),
                decoder.u64()?,
                TextStateId::from_bytes(decoder.bytes_32()?),
                TokenIdsId::from_bytes(decoder.bytes_32()?),
            ))
        }
        other => Err(DecodeError::new(format!(
            "unexpected text artifact schema tag {other:?}"
        ))),
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
        str::from_utf8(bytes).map_err(|err| DecodeError::new(format!("invalid utf-8: {err}")))
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
    use super::{
        BoundTerm, Canonical, CanonicalDecode, InputAddressed, OutputAddressed, OutputId,
        SourceRef, TextArtifact, TextExecution, TextPolicy, TextState, TokenId, TokenIds,
    };

    fn output_id<T>(byte: u8) -> OutputId<T> {
        OutputId::from_bytes([byte; 32])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Golden bytes, captured from this schema's previous home in
    /// `hellas-executor`, decoded field by field.
    ///
    /// Round-tripping cannot catch a field order that moves in the
    /// encoder and the decoder together, and every id below is the hash
    /// of these exact bytes: an artifact that re-encoded differently
    /// would silently re-address every stored blob. So the bytes are the
    /// assertion, not the values they decode to.
    #[test]
    fn canonical_bytes_are_pinned_by_golden_vectors() {
        let tokens = TokenIds::from([1, 2, 300_000]);
        assert_eq!(
            hex(&tokens.canonical_bytes()),
            concat!(
                "82",                                                 // array(2)
                "781c", "68656c6c61732e6576616c756174652e746f6b656e5f6964732e7631", // schema tag
                "83",                                                 // array(3) tokens
                "01", "02", "1a000493e0",                             // 1, 2, 300000
            )
        );

        let policy = TextPolicy::from_u32_stop_tokens(16, [5, 4]);
        assert_eq!(
            hex(&policy.canonical_bytes()),
            concat!(
                "83",                                                 // array(3)
                "781e", "68656c6c61732e6576616c756174652e746578742e706f6c6963792e7631",
                "10",                                                 // max_new_tokens = 16
                "82", "04", "05",                                     // sorted stop ids
            )
        );

        let identity = TextArtifact::identity(output_id::<BoundTerm>(7), "model", "main", "f32");
        assert_eq!(
            hex(&identity.canonical_bytes()),
            concat!(
                "85",                                                 // array(5)
                "7829",
                "68656c6c61732e6576616c756174652e746578742e61727469666163742e6964656e746974792e7631",
                "5820", "0707070707070707070707070707070707070707070707070707070707070707",
                "65", "6d6f64656c",                                   // "model"
                "64", "6d61696e",                                     // "main"
                "63", "663332",                                       // "f32"
            )
        );

        let state = TextState::new(tokens.output_id());
        assert_eq!(
            hex(&state.canonical_bytes()),
            concat!(
                "82",
                "781d", "68656c6c61732e6576616c756174652e746578742e73746174652e7631",
                "5820", "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
            )
        );

        let execution = TextExecution::new(
            SourceRef::output(identity.output_id()),
            tokens.output_id(),
            policy.output_id(),
        );
        assert_eq!(
            hex(&execution.canonical_bytes()),
            concat!(
                "84",                                                 // array(4)
                "7821", "68656c6c61732e6576616c756174652e746578742e657865637574696f6e2e7631",
                "82",                                                 // source array(2)
                "7820", "68656c6c61732e6576616c756174652e736f757263652e6f75747075742e7631",
                "5820", "f343b61a66133adec0c1c8ebee47989b00eb65a6db9b2dc63d743d9329515e1e",
                "5820", "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
                "5820", "3540781322ed7b80e3459cf7b40106c9a7472dd2cf2d6e8e9d5d4d25ae11aa60",
            )
        );

        let artifact =
            TextArtifact::output(execution.input_id(), 3, state.output_id(), tokens.output_id());
        assert_eq!(
            hex(&artifact.canonical_bytes()),
            concat!(
                "85",
                "7827",
                "68656c6c61732e6576616c756174652e746578742e61727469666163742e6f75747075742e7631",
                "5820", "6d0ea1474c6b42b534024ba508d444fc0fd7c1db10243cd7d289711523775cfd",
                "03",                                                 // position
                "5820", "4a7cc97833bc25d2340ce377de92c012f336858cfeb8e2859f67fd12975916b8",
                "5820", "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
            )
        );

        assert_eq!(
            hex(identity.output_id().as_bytes()),
            "f343b61a66133adec0c1c8ebee47989b00eb65a6db9b2dc63d743d9329515e1e"
        );
        assert_eq!(
            hex(execution.input_id().as_bytes()),
            "6d0ea1474c6b42b534024ba508d444fc0fd7c1db10243cd7d289711523775cfd"
        );
    }

    #[test]
    fn token_ids_are_output_addressed_values() {
        let a = TokenIds::from([1, 2, 3]);
        let b = TokenIds::from([1, 2, 3]);
        let c = TokenIds::from([3, 2, 1]);

        assert_eq!(
            a.as_slice(),
            &[TokenId::new(1), TokenId::new(2), TokenId::new(3)]
        );
        assert_eq!(a.output_id(), b.output_id());
        assert_ne!(a.output_id(), c.output_id());
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
        assert_eq!(a.output_id(), b.output_id());
    }

    #[test]
    fn text_state_is_output_addressed_by_token_artifact() {
        let a = TextState::new(TokenIds::from([1, 2, 3]).output_id());
        let b = TextState::new(TokenIds::from([1, 2, 3]).output_id());
        let c = TextState::new(TokenIds::from([1, 2, 4]).output_id());

        assert_eq!(a.tokens(), b.tokens());
        assert_eq!(a.output_id(), b.output_id());
        assert_ne!(a.output_id(), c.output_id());
    }

    #[test]
    fn identity_is_output_addressed_genesis() {
        let identity = TextArtifact::identity(output_id::<BoundTerm>(7), "model", "main", "f32");
        let other_model = TextArtifact::identity(output_id::<BoundTerm>(7), "other", "main", "f32");
        let prompt_tokens = TokenIds::from([1]).output_id();
        let policy = TextPolicy::from_u32_stop_tokens(4, []).output_id();
        let execution = TextExecution::new(
            SourceRef::output(identity.output_id()),
            prompt_tokens,
            policy,
        );

        assert_ne!(identity.output_id(), other_model.output_id());
        assert_ne!(
            execution.input_id().as_bytes(),
            identity.output_id().as_bytes()
        );
    }

    #[test]
    fn execution_input_id_changes_when_source_changes() {
        let identity = TextArtifact::identity(output_id::<BoundTerm>(7), "model", "main", "f32");
        let prompt_tokens = TokenIds::from([1]).output_id();
        let policy = TextPolicy::from_u32_stop_tokens(4, []).output_id();
        let first = TextExecution::new(
            SourceRef::output(identity.output_id()),
            prompt_tokens,
            policy,
        );
        let second = TextExecution::new(SourceRef::input(first.input_id()), prompt_tokens, policy);

        assert_ne!(first.input_id(), second.input_id());
    }

    #[test]
    fn output_artifact_id_changes_when_generated_tokens_change() {
        let execution = TextExecution::new(
            SourceRef::output(
                TextArtifact::identity(output_id::<BoundTerm>(7), "model", "main", "f32")
                    .output_id(),
            ),
            TokenIds::from([1]).output_id(),
            TextPolicy::from_u32_stop_tokens(4, []).output_id(),
        )
        .input_id();
        let a = TextArtifact::output(
            execution,
            5,
            TextState::new(TokenIds::from([1]).output_id()).output_id(),
            TokenIds::from([1]).output_id(),
        );
        let b = TextArtifact::output(
            execution,
            5,
            TextState::new(TokenIds::from([1]).output_id()).output_id(),
            TokenIds::from([2]).output_id(),
        );

        assert_ne!(a.output_id(), b.output_id());
    }

    #[test]
    fn canonical_text_objects_decode_round_trip() {
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

        let state = TextState::new(tokens.output_id());
        assert_eq!(
            TextState::from_canonical_bytes(&state.canonical_bytes()).unwrap(),
            state
        );

        let identity = TextArtifact::identity(output_id::<BoundTerm>(7), "model", "main", "f32");
        assert_eq!(
            TextArtifact::from_canonical_bytes(&identity.canonical_bytes()).unwrap(),
            identity
        );

        let execution = TextExecution::new(
            SourceRef::output(identity.output_id()),
            tokens.output_id(),
            policy.output_id(),
        );
        assert_eq!(
            TextExecution::from_canonical_bytes(&execution.canonical_bytes()).unwrap(),
            execution
        );

        let artifact = TextArtifact::output(
            execution.input_id(),
            3,
            state.output_id(),
            tokens.output_id(),
        );
        assert_eq!(
            TextArtifact::from_canonical_bytes(&artifact.canonical_bytes()).unwrap(),
            artifact
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
        let schema_start = bytes
            .iter()
            .position(|byte| *byte == b'h')
            .expect("schema tag starts with h");
        bytes[schema_start] = b'x';

        let err = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("schema tag"));
    }
}
