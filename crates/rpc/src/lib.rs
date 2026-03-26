pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "client")]
pub mod driver;
pub mod pb;
pub mod service;

// Graph execution requests can carry full serialized model graphs for large models.
pub const GRPC_MESSAGE_LIMIT: usize = 128 * 1024 * 1024;
const TOKEN_BYTES_LEN: usize = std::mem::size_of::<u32>();

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
    let mut bytes = Vec::with_capacity(token_ids.len() * TOKEN_BYTES_LEN);
    for token_id in token_ids {
        bytes.extend_from_slice(&token_id.to_le_bytes());
    }
    bytes
}

pub fn decode_token_ids(bytes: &[u8]) -> Result<Vec<u32>, TokenBytesError> {
    let (chunks, remainder) = bytes.as_chunks::<TOKEN_BYTES_LEN>();
    if !remainder.is_empty() {
        return Err(TokenBytesError { len: bytes.len() });
    }

    Ok(chunks
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{TokenBytesError, decode_token_ids, encode_token_ids};

    #[test]
    fn token_ids_round_trip_through_bytes() {
        let token_ids = [1, 42, u32::MAX, 7];
        let encoded = encode_token_ids(&token_ids);
        let decoded = decode_token_ids(&encoded).expect("token bytes should decode");
        assert_eq!(decoded, token_ids);
    }

    #[test]
    fn decode_rejects_partial_token_bytes() {
        let err = decode_token_ids(&[1, 2, 3]).expect_err("partial token bytes must fail");
        assert_eq!(err, TokenBytesError { len: 3 });
    }
}
