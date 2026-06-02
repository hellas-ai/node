use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hellas_core::{
    InputCommitment, InputEventEnvelope, OutputEventEnvelope, ProducerId, PublicKey,
    canonical_dag_cbor, decode_dag_cbor,
};
use hellas_rpc::fetch::{
    FetchInput, FetchProtocolError, verify_input_events, verify_output_events,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchTranscript {
    input_commitment: InputCommitment,
    input: Vec<InputEventEnvelope>,
    output: Vec<OutputEventEnvelope>,
}

impl FetchTranscript {
    pub fn new(
        input_commitment: InputCommitment,
        input: Vec<InputEventEnvelope>,
        output: Vec<OutputEventEnvelope>,
    ) -> Self {
        Self {
            input_commitment,
            input,
            output,
        }
    }

    pub const fn input_commitment(&self) -> InputCommitment {
        self.input_commitment
    }

    pub fn output_events(&self) -> &[OutputEventEnvelope] {
        &self.output
    }

    pub fn from_quote(quote: &FetchQuote, output: Vec<OutputEventEnvelope>) -> Self {
        Self::new(quote.input_commitment, quote.input.clone(), output)
    }

    pub fn verify(&self, producer_key: &PublicKey) -> Result<FetchInput, FetchTranscriptError> {
        let input = verify_input_events(&self.input)?;
        if input.input_commitment != self.input_commitment {
            return Err(FetchTranscriptError::InputCommitmentMismatch);
        }
        let output = verify_output_events(input.input_commitment, &self.output)?;
        if output.producer_key != *producer_key {
            return Err(FetchTranscriptError::ProducerKeyMismatch);
        }
        Ok(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchQuote {
    pub input_commitment: InputCommitment,
    pub caller_key: PublicKey,
    pub input: Vec<InputEventEnvelope>,
}

impl FetchQuote {
    pub fn from_verified(verified: &FetchInput, input: Vec<InputEventEnvelope>) -> Self {
        Self {
            input_commitment: verified.input_commitment,
            caller_key: verified.caller_key,
            input,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchTicketState {
    Quoted(FetchQuote),
    Running(FetchQuote),
    Completed(FetchTranscript),
    Failed(String),
}

pub trait FetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError>;
    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryFetchTranscriptStore {
    transcripts: Arc<Mutex<HashMap<InputCommitment, FetchTranscript>>>,
}

impl FetchTranscriptStore for MemoryFetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        let mut transcripts = self
            .transcripts
            .lock()
            .map_err(|_| FetchStoreError::Poisoned)?;
        match transcripts.get(&transcript.input_commitment()) {
            Some(existing) if existing == transcript => Ok(()),
            Some(_) => Err(FetchStoreError::Conflict {
                input: transcript.input_commitment(),
            }),
            None => {
                transcripts.insert(transcript.input_commitment(), transcript.clone());
                Ok(())
            }
        }
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        let transcripts = self
            .transcripts
            .lock()
            .map_err(|_| FetchStoreError::Poisoned)?;
        Ok(transcripts.get(&input).cloned())
    }
}

#[derive(Clone, Debug)]
pub enum FetchTranscriptStoreBackend {
    Memory(MemoryFetchTranscriptStore),
    Fs(FsFetchTranscriptStore),
}

impl FetchTranscriptStoreBackend {
    pub fn memory() -> Self {
        Self::Memory(MemoryFetchTranscriptStore::default())
    }

    pub fn fs(root: impl Into<PathBuf>) -> Self {
        Self::Fs(FsFetchTranscriptStore::new(root))
    }
}

impl FetchTranscriptStore for FetchTranscriptStoreBackend {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        match self {
            Self::Memory(store) => store.put_completed(transcript),
            Self::Fs(store) => store.put_completed(transcript),
        }
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        match self {
            Self::Memory(store) => store.get_completed(input),
            Self::Fs(store) => store.get_completed(input),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FetchCallerPolicy {
    trusted: HashMap<ProducerId, PublicKey>,
}

impl FetchCallerPolicy {
    pub fn new(trusted: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            trusted: trusted
                .into_iter()
                .map(|key| (ProducerId::from_public_key(&key), key))
                .collect(),
        }
    }

    pub fn single(key: PublicKey) -> Self {
        Self::new([key])
    }

    pub fn is_authorized(&self, key: &PublicKey) -> bool {
        self.trusted
            .get(&ProducerId::from_public_key(key))
            .is_some_and(|trusted| trusted == key)
    }
}

#[derive(Debug, Clone)]
pub struct FsFetchTranscriptStore {
    root: PathBuf,
}

impl FsFetchTranscriptStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, input: InputCommitment) -> PathBuf {
        self.root.join(format!("{}.dagcbor", input.digest()))
    }
}

impl FetchTranscriptStore for FsFetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        fs::create_dir_all(&self.root).map_err(FetchStoreError::Io)?;
        let bytes = canonical_dag_cbor(transcript).map_err(|err| {
            FetchStoreError::Encode(format!("transcript DAG-CBOR encode failed: {err}"))
        })?;
        let path = self.path(transcript.input_commitment());
        match atomic_create_no_clobber(&path, &bytes) {
            Ok(()) => Ok(()),
            Err(FetchStoreError::AlreadyExists) => {
                let existing = fs::read(&path).map_err(FetchStoreError::Io)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(FetchStoreError::Conflict {
                        input: transcript.input_commitment(),
                    })
                }
            }
            Err(err) => Err(err),
        }
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        let path = self.path(input);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(FetchStoreError::Io(err)),
        };
        let transcript = decode_dag_cbor(&bytes).map_err(|err| {
            FetchStoreError::Decode(format!("transcript DAG-CBOR decode failed: {err}"))
        })?;
        Ok(Some(transcript))
    }
}

fn atomic_create_no_clobber(path: &Path, bytes: &[u8]) -> Result<(), FetchStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("transcript");
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(FetchStoreError::Io)?;
        file.write_all(bytes).map_err(FetchStoreError::Io)?;
        file.sync_all().map_err(FetchStoreError::Io)?;
        drop(file);

        match fs::hard_link(&tmp, path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                Err(FetchStoreError::AlreadyExists)
            }
            Err(err) => Err(FetchStoreError::Io(err)),
        }
    })();

    let _ = fs::remove_file(&tmp);
    result
}

pub struct FetchStateMachine<S> {
    store: S,
    caller_policy: FetchCallerPolicy,
    tickets: HashMap<InputCommitment, FetchTicketState>,
}

impl<S> FetchStateMachine<S>
where
    S: FetchTranscriptStore,
{
    pub fn new(store: S, caller_policy: FetchCallerPolicy) -> Self {
        Self {
            store,
            caller_policy,
            tickets: HashMap::new(),
        }
    }

    fn insert_quote(&mut self, quote: FetchQuote) -> Result<(), FetchStateError> {
        if !self.caller_policy.is_authorized(&quote.caller_key) {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        let input = quote.input_commitment;
        match self.tickets.get(&input) {
            Some(FetchTicketState::Quoted(_)) | Some(FetchTicketState::Running(_)) => {
                Err(FetchStateError::AlreadyExists)
            }
            Some(FetchTicketState::Completed(_)) => Err(FetchStateError::AlreadyCompleted),
            Some(FetchTicketState::Failed(_)) => Err(FetchStateError::Failed),
            None => {
                self.tickets.insert(input, FetchTicketState::Quoted(quote));
                Ok(())
            }
        }
    }

    pub fn quote_input(
        &mut self,
        input: Vec<InputEventEnvelope>,
    ) -> Result<(FetchQuote, FetchInput), FetchStateError> {
        let verified = verify_input_events(&input)?;
        let quote = FetchQuote::from_verified(&verified, input);
        if !self.caller_policy.is_authorized(&quote.caller_key) {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        if self.store.get_completed(quote.input_commitment)?.is_some() {
            return Ok((quote, verified));
        }
        self.insert_quote(quote.clone())?;
        Ok((quote, verified))
    }

    pub fn start(&mut self, input: InputCommitment) -> Result<FetchQuote, FetchStateError> {
        if self.store.get_completed(input)?.is_some() {
            return Err(FetchStateError::AlreadyCompleted);
        }
        let state = self
            .tickets
            .get_mut(&input)
            .ok_or(FetchStateError::NotFound)?;
        match state {
            FetchTicketState::Quoted(quote) => {
                let quote = quote.clone();
                *state = FetchTicketState::Running(quote.clone());
                Ok(quote)
            }
            FetchTicketState::Running(_) => Err(FetchStateError::AlreadyRunning),
            FetchTicketState::Completed(_) => Err(FetchStateError::AlreadyCompleted),
            FetchTicketState::Failed(_) => Err(FetchStateError::Failed),
        }
    }

    pub fn complete_output(
        &mut self,
        input: InputCommitment,
        output: Vec<OutputEventEnvelope>,
        producer_key: &PublicKey,
    ) -> Result<FetchTranscript, FetchStateError> {
        let quote = match self.tickets.get(&input) {
            Some(FetchTicketState::Running(quote)) => quote.clone(),
            Some(FetchTicketState::Quoted(_)) => return Err(FetchStateError::NotRunning),
            Some(FetchTicketState::Completed(_)) => return Err(FetchStateError::AlreadyCompleted),
            Some(FetchTicketState::Failed(_)) => return Err(FetchStateError::Failed),
            None => return Err(FetchStateError::NotFound),
        };
        let transcript = FetchTranscript::from_quote(&quote, output);
        self.complete_transcript(transcript.clone(), producer_key)?;
        Ok(transcript)
    }

    fn complete_transcript(
        &mut self,
        transcript: FetchTranscript,
        producer_key: &PublicKey,
    ) -> Result<(), FetchStateError> {
        let input = transcript.input_commitment();
        let quote = match self.tickets.get(&input) {
            Some(FetchTicketState::Running(quote)) => quote,
            Some(FetchTicketState::Quoted(_)) => return Err(FetchStateError::NotRunning),
            Some(FetchTicketState::Completed(_)) => return Err(FetchStateError::AlreadyCompleted),
            Some(FetchTicketState::Failed(_)) => return Err(FetchStateError::Failed),
            None => return Err(FetchStateError::NotFound),
        };
        if transcript.input != quote.input {
            return Err(FetchStateError::QuoteMismatch);
        }
        let verified = transcript.verify(producer_key)?;
        if verified.caller_key != quote.caller_key {
            return Err(FetchStateError::QuoteMismatch);
        }

        self.store.put_completed(&transcript)?;
        self.tickets
            .insert(input, FetchTicketState::Completed(transcript));
        Ok(())
    }

    pub fn fail(
        &mut self,
        input: InputCommitment,
        reason: impl Into<String>,
    ) -> Result<(), FetchStateError> {
        let state = self
            .tickets
            .get_mut(&input)
            .ok_or(FetchStateError::NotFound)?;
        match state {
            FetchTicketState::Running(_) | FetchTicketState::Quoted(_) => {
                *state = FetchTicketState::Failed(reason.into());
                Ok(())
            }
            FetchTicketState::Completed(_) => Err(FetchStateError::AlreadyCompleted),
            FetchTicketState::Failed(_) => Err(FetchStateError::Failed),
        }
    }

    pub fn replay_completed(
        &self,
        input: InputCommitment,
        producer_key: &PublicKey,
    ) -> Result<FetchTranscript, FetchStateError> {
        let transcript = match self.store.get_completed(input)? {
            Some(transcript) => transcript,
            None => match self.tickets.get(&input) {
                Some(FetchTicketState::Completed(transcript)) => transcript.clone(),
                Some(FetchTicketState::Failed(_)) => return Err(FetchStateError::Failed),
                Some(FetchTicketState::Quoted(_)) | Some(FetchTicketState::Running(_)) => {
                    return Err(FetchStateError::NotCompleted);
                }
                None => return Err(FetchStateError::NotFound),
            },
        };
        if transcript.input_commitment() != input {
            return Err(FetchStateError::QuoteMismatch);
        }
        let verified = transcript.verify(producer_key)?;
        if !self.caller_policy.is_authorized(&verified.caller_key) {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        Ok(transcript)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchTranscriptError {
    #[error("stored input commitment does not match input transcript")]
    InputCommitmentMismatch,
    #[error("producer key does not match output transcript signer")]
    ProducerKeyMismatch,
    #[error("fetch protocol error: {0}")]
    Protocol(#[from] FetchProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum FetchStateError {
    #[error("fetch ticket not found")]
    NotFound,
    #[error("fetch ticket already exists")]
    AlreadyExists,
    #[error("fetch ticket already running")]
    AlreadyRunning,
    #[error("fetch ticket is not running")]
    NotRunning,
    #[error("fetch ticket is not completed")]
    NotCompleted,
    #[error("fetch ticket already completed")]
    AlreadyCompleted,
    #[error("fetch transcript does not match the stored quote")]
    QuoteMismatch,
    #[error("fetch ticket failed")]
    Failed,
    #[error("fetch caller key is not authorized")]
    UnauthorizedCaller,
    #[error("fetch store error: {0}")]
    Store(#[from] FetchStoreError),
    #[error("fetch transcript verification failed: {0}")]
    Verify(#[from] FetchTranscriptError),
    #[error("fetch input verification failed: {0}")]
    Input(#[from] FetchProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum FetchStoreError {
    #[error("fetch transcript already exists")]
    AlreadyExists,
    #[error("conflicting completed transcript for input {input:?}")]
    Conflict { input: InputCommitment },
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("fetch transcript memory store lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_core::ProducerSigningKey;
    use hellas_rpc::fetch::{build_input_events, build_output_events, verify_input_events};

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hellas-fetch-test-{name}-{}",
            Uuid::new_v4().simple()
        ))
    }

    fn sample_transcript() -> (FetchQuote, FetchTranscript, PublicKey, PublicKey) {
        let caller = key(1);
        let producer = key(2);
        let producer_key = producer.public_key();

        let input_events =
            build_input_events("openai", "responses", br#"{"model":"gpt-test"}"#, &caller).unwrap();
        let verified = verify_input_events(&input_events).unwrap();
        let caller_key = verified.caller_key;
        let quote = FetchQuote::from_verified(&verified, input_events);
        let output_events = build_output_events(
            verified.input_commitment,
            br#"{"status":"completed"}"#,
            &producer,
        )
        .unwrap();
        let transcript = FetchTranscript::from_quote(&quote, output_events);
        (quote, transcript, caller_key, producer_key)
    }

    fn trusted_state(
        store: FsFetchTranscriptStore,
        caller: PublicKey,
    ) -> FetchStateMachine<FsFetchTranscriptStore> {
        FetchStateMachine::new(store, FetchCallerPolicy::single(caller))
    }

    fn trusted_memory_state(caller: PublicKey) -> FetchStateMachine<MemoryFetchTranscriptStore> {
        FetchStateMachine::new(
            MemoryFetchTranscriptStore::default(),
            FetchCallerPolicy::single(caller),
        )
    }

    #[test]
    fn transcript_verifies_both_directions() {
        let (_quote, transcript, caller, producer) = sample_transcript();

        let verified = transcript.verify(&producer).unwrap();

        assert_eq!(verified.caller_key, caller);
    }

    #[test]
    fn cannot_start_same_ticket_twice() {
        let dir = root("double-start");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, _transcript, caller, _producer) = sample_transcript();
        let input = quote.input_commitment;
        let mut state = trusted_state(store, caller);
        state.quote_input(quote.input.clone()).unwrap();

        state.start(input).unwrap();
        assert!(matches!(
            state.start(input).unwrap_err(),
            FetchStateError::AlreadyRunning
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn quote_input_verifies_and_stores_ticket() {
        let dir = root("quote-input");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, _transcript, caller, _producer) = sample_transcript();
        let mut state = trusted_state(store, caller);

        let (stored, _verified) = state.quote_input(quote.input.clone()).unwrap();

        assert_eq!(stored.input_commitment, quote.input_commitment);
        assert_eq!(
            state
                .start(stored.input_commitment)
                .unwrap()
                .input_commitment,
            quote.input_commitment
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn quote_input_rejects_untrusted_caller() {
        let dir = root("unauthorized-caller");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, _transcript, _caller, _producer) = sample_transcript();
        let untrusted = key(9).public_key();
        let mut state = FetchStateMachine::new(store, FetchCallerPolicy::single(untrusted));

        assert!(matches!(
            state.quote_input(quote.input.clone()).unwrap_err(),
            FetchStateError::UnauthorizedCaller
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completed_ticket_replays_transcript() {
        let dir = root("replay");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, transcript, caller, producer) = sample_transcript();
        let input = quote.input_commitment;
        let mut state = trusted_state(store, caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        let completed = state
            .complete_output(input, transcript.output_events().to_vec(), &producer)
            .unwrap();

        assert_eq!(completed, transcript);
        assert_eq!(
            state.replay_completed(input, &producer).unwrap(),
            transcript
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completed_input_can_be_quoted_again_for_replay() {
        let (quote, transcript, caller, producer) = sample_transcript();
        let input = quote.input_commitment;
        let mut state = trusted_memory_state(caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        state
            .complete_output(input, transcript.output_events().to_vec(), &producer)
            .unwrap();

        let (repeated, _verified) = state.quote_input(quote.input.clone()).unwrap();

        assert_eq!(repeated.input_commitment, input);
        assert_eq!(
            state.replay_completed(input, &producer).unwrap(),
            transcript
        );
    }

    #[test]
    fn memory_store_rejects_conflicting_completion() {
        let (_quote, first, _caller, _producer) = sample_transcript();
        let mut second = first.clone();
        second.output = Vec::new();
        let store = MemoryFetchTranscriptStore::default();

        store.put_completed(&first).unwrap();

        assert!(matches!(
            store.put_completed(&second).unwrap_err(),
            FetchStoreError::Conflict { input } if input == first.input_commitment()
        ));
    }

    #[test]
    fn completion_rejects_untrusted_producer_key() {
        let dir = root("wrong-producer");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, transcript, caller, _producer) = sample_transcript();
        let wrong_producer = key(9).public_key();
        let input = quote.input_commitment;
        let mut state = trusted_state(store, caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();

        assert!(matches!(
            state
                .complete_output(input, transcript.output_events().to_vec(), &wrong_producer)
                .unwrap_err(),
            FetchStateError::Verify(FetchTranscriptError::ProducerKeyMismatch)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completion_rejects_transcript_that_does_not_match_quote() {
        let dir = root("quote-mismatch");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, mut transcript, caller, producer) = sample_transcript();
        let input = quote.input_commitment;
        transcript.input.clear();
        let mut state = trusted_state(store, caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();

        assert!(matches!(
            state
                .complete_transcript(transcript, &producer)
                .unwrap_err(),
            FetchStateError::QuoteMismatch
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_ticket_does_not_replay() {
        let dir = root("failed");
        let store = FsFetchTranscriptStore::new(&dir);
        let (quote, _transcript, caller, _producer) = sample_transcript();
        let input = quote.input_commitment;
        let mut state = trusted_state(store, caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        state.fail(input, "provider failed").unwrap();

        assert!(matches!(
            state
                .replay_completed(input, &key(2).public_key())
                .unwrap_err(),
            FetchStateError::Failed
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completed_transcript_survives_store_reload() {
        let dir = root("reload");
        let store = FsFetchTranscriptStore::new(&dir);
        let (_quote, transcript, _caller, _producer) = sample_transcript();
        let input = transcript.input_commitment();
        store.put_completed(&transcript).unwrap();

        let reloaded = FsFetchTranscriptStore::new(&dir);
        assert_eq!(reloaded.get_completed(input).unwrap(), Some(transcript));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completed_store_put_is_idempotent_for_same_bytes() {
        let dir = root("idempotent-put");
        let store = FsFetchTranscriptStore::new(&dir);
        let (_quote, transcript, _caller, _producer) = sample_transcript();

        store.put_completed(&transcript).unwrap();
        store.put_completed(&transcript).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
