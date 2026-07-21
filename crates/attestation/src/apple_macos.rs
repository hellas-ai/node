use std::ffi::{CStr, CString, c_char};

use hellas_rpc::pb::execute::AssuranceEvidence;
use hellas_rpc::{APPLE_APP_ATTEST, ContentId};
use sha2::{Digest as _, Sha256};

use crate::{AppleCredential, AttestationError, Attester, Binding};

pub struct AppleAppAttest {
    key: String,
    credential: ContentId,
}

impl AppleAppAttest {
    pub fn create(client_data_hash: [u8; 32]) -> Result<(Self, AppleCredential), AttestationError> {
        if !unsafe { hellas_apple_supported() } {
            return Err(AttestationError::Platform("unavailable to this app".into()));
        }
        let key = String::from_utf8(call(unsafe { hellas_apple_generate_key() })?)
            .map_err(|_| AttestationError::Platform("invalid key identifier".into()))?;
        let attestation = call(unsafe {
            hellas_apple_attest(cstring(&key)?.as_ptr(), client_data_hash.as_ptr())
        })?;
        let credential = AppleCredential {
            attestation,
            client_data_hash,
        };
        Ok((
            Self {
                key,
                credential: credential.content_id(),
            },
            credential,
        ))
    }

    pub fn load(key: String, credential: ContentId) -> Self {
        Self { key, credential }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn assertion(&self, client_data_hash: [u8; 32]) -> Result<Vec<u8>, AttestationError> {
        call(unsafe {
            hellas_apple_assert(cstring(&self.key)?.as_ptr(), client_data_hash.as_ptr())
        })
    }
}

impl Attester for AppleAppAttest {
    async fn attest(&self, binding: Binding) -> Result<AssuranceEvidence, AttestationError> {
        Ok(AssuranceEvidence {
            codec: APPLE_APP_ATTEST.into(),
            credential: self.credential.as_bytes().to_vec(),
            proof: self.assertion(*binding.as_bytes())?,
        })
    }
}

pub fn client_data_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[repr(C)]
struct NativeResult {
    bytes: *mut u8,
    len: usize,
    error: *mut c_char,
}

fn cstring(value: &str) -> Result<CString, AttestationError> {
    CString::new(value).map_err(|_| AttestationError::Platform("invalid key identifier".into()))
}

fn call(value: NativeResult) -> Result<Vec<u8>, AttestationError> {
    let result = if value.error.is_null() {
        Ok(unsafe { std::slice::from_raw_parts(value.bytes, value.len) }.to_vec())
    } else {
        Err(AttestationError::Platform(
            unsafe { CStr::from_ptr(value.error) }
                .to_string_lossy()
                .into_owned(),
        ))
    };
    unsafe { hellas_apple_result_free(value) };
    result
}

unsafe extern "C" {
    fn hellas_apple_supported() -> bool;
    fn hellas_apple_generate_key() -> NativeResult;
    fn hellas_apple_attest(key: *const c_char, hash: *const u8) -> NativeResult;
    fn hellas_apple_assert(key: *const c_char, hash: *const u8) -> NativeResult;
    fn hellas_apple_result_free(value: NativeResult);
}
