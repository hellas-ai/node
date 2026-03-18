#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "client")]
pub mod driver;
pub mod pb;
pub mod service;

// Graph execution requests can carry full serialized model graphs for large models.
pub const GRPC_MESSAGE_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBytesError {
    len: usize,
}

impl std::fmt::Display for TokenBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token byte payload length {} is not divisible by 4",
            self.len
        )
    }
}

impl std::error::Error for TokenBytesError {}

pub fn encode_token_ids(token_ids: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(token_ids));
    for token_id in token_ids {
        bytes.extend_from_slice(&token_id.to_le_bytes());
    }
    bytes
}

pub fn decode_token_ids(bytes: &[u8]) -> Result<Vec<u32>, TokenBytesError> {
    let mut chunks = bytes.chunks_exact(std::mem::size_of::<u32>());
    if !chunks.remainder().is_empty() {
        return Err(TokenBytesError { len: bytes.len() });
    }

    Ok(chunks
        .by_ref()
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunk size checked")))
        .collect())
}
