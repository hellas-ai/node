//! `WebAuthn` verification for open authorizations.
//!
//! This follows Tempo's consensus shape: the kernel validates the `WebAuthn`
//! assertion and requires `clientDataJSON.challenge` to be the base64url
//! encoding of the canonical open hash. It intentionally does not enforce
//! `origin` or `rpIdHash`; those bytes are still signed by the authenticator,
//! but the verifier treats `WebAuthn` as a portable P-256 transaction-signing
//! envelope.

use p256::{
    EncodedPoint,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};
use sha2::{Digest, Sha256};

use crate::{
    primitive::{Key, PayloadHash},
    tx::WebAuthnAssertion,
};

const MIN_AUTH_DATA_LEN: usize = 37;
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;
const ED: u8 = 0x80;
const MAX_JSON_DEPTH: usize = 16;

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const P256_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Reason a `WebAuthn` open assertion failed verification.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum WebAuthnError {
    /// `authenticatorData || clientDataJSON` is too short to contain both
    /// required pieces.
    DataTooShort,
    /// Neither the user-presence nor user-verification flag is set.
    MissingUserPresence,
    /// Assertion auth data must not carry attested credential data.
    AttestedCredentialDataUnsupported,
    /// Extension data is not supported by the kernel verifier.
    ExtensionsUnsupported,
    /// `clientDataJSON` is not accepted by the kernel's strict parser.
    InvalidClientDataJson,
    /// `clientDataJSON.type` is not `webauthn.get`.
    InvalidClientDataType,
    /// `clientDataJSON.challenge` does not match the expected open hash.
    InvalidChallenge,
    /// `clientDataJSON` is missing a required top-level field.
    MissingClientDataField,
    /// `clientDataJSON` repeats a required top-level field.
    DuplicateClientDataField,
    /// The supplied P-256 coordinates do not encode a valid public key.
    InvalidPublicKey,
    /// The P-256 public key does not match the party key.
    SignerMismatch,
    /// The P-256 signature uses a high-s value.
    HighS,
    /// The P-256 signature is malformed or does not verify.
    InvalidSignature,
}

/// Verifies a `WebAuthn` assertion against a party key and open hash.
///
/// The party key is the compressed SEC1 encoding of the P-256 public key
/// carried by the assertion.
///
/// # Errors
///
/// Returns [`WebAuthnError`] when the assertion is malformed, its challenge
/// does not match `hash`, its P-256 key does not match `key`, or its
/// signature fails verification.
pub fn verify_webauthn_assertion(
    assertion: &WebAuthnAssertion,
    key: Key,
    hash: PayloadHash,
) -> Result<(), WebAuthnError> {
    if p256_key(assertion.pub_key_x(), assertion.pub_key_y())? != key {
        return Err(WebAuthnError::SignerMismatch);
    }

    let message_hash = webauthn_message_hash(assertion.webauthn_data().as_slice(), hash)?;
    verify_p256_signature(assertion, &message_hash)
}

/// Returns the compressed P-256 key bytes used as a Hellas party key.
///
/// Use this when constructing `Terms` for a party controlled by a passkey.
///
/// # Errors
///
/// Returns [`WebAuthnError::InvalidPublicKey`] if the coordinates do not
/// encode a valid P-256 public key.
pub fn p256_key(
    pub_key_x: &[u8; PayloadHash::LENGTH],
    pub_key_y: &[u8; PayloadHash::LENGTH],
) -> Result<Key, WebAuthnError> {
    let verifying_key = verifying_key(pub_key_x, pub_key_y)?;
    let encoded = verifying_key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != Key::LENGTH {
        return Err(WebAuthnError::InvalidPublicKey);
    }

    let mut out = [0_u8; Key::LENGTH];
    out.copy_from_slice(bytes);
    Ok(Key::from_bytes(out))
}

fn verifying_key(
    pub_key_x: &[u8; PayloadHash::LENGTH],
    pub_key_y: &[u8; PayloadHash::LENGTH],
) -> Result<VerifyingKey, WebAuthnError> {
    let mut encoded = [0_u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(pub_key_x);
    encoded[33..].copy_from_slice(pub_key_y);
    let point = EncodedPoint::from_bytes(encoded).map_err(|_| WebAuthnError::InvalidPublicKey)?;
    VerifyingKey::from_encoded_point(&point).map_err(|_| WebAuthnError::InvalidPublicKey)
}

fn verify_p256_signature(
    assertion: &WebAuthnAssertion,
    message_hash: &[u8; PayloadHash::LENGTH],
) -> Result<(), WebAuthnError> {
    if assertion.s() > &P256_N_HALF {
        return Err(WebAuthnError::HighS);
    }

    let verifying_key = verifying_key(assertion.pub_key_x(), assertion.pub_key_y())?;
    let mut sig = [0_u8; 64];
    sig[..PayloadHash::LENGTH].copy_from_slice(assertion.r());
    sig[PayloadHash::LENGTH..].copy_from_slice(assertion.s());
    let signature = P256Signature::from_slice(&sig).map_err(|_| WebAuthnError::InvalidSignature)?;

    verifying_key
        .verify_prehash(message_hash, &signature)
        .map_err(|_| WebAuthnError::InvalidSignature)
}

fn webauthn_message_hash(
    webauthn_data: &[u8],
    hash: PayloadHash,
) -> Result<[u8; PayloadHash::LENGTH], WebAuthnError> {
    if webauthn_data.len() < MIN_AUTH_DATA_LEN + PayloadHash::LENGTH {
        return Err(WebAuthnError::DataTooShort);
    }

    let flags = webauthn_data[32];
    if flags & (UP | UV) == 0 {
        return Err(WebAuthnError::MissingUserPresence);
    }
    if flags & AT != 0 {
        return Err(WebAuthnError::AttestedCredentialDataUnsupported);
    }
    if flags & ED != 0 {
        return Err(WebAuthnError::ExtensionsUnsupported);
    }

    let auth_data = &webauthn_data[..MIN_AUTH_DATA_LEN];
    let client_data_json = &webauthn_data[MIN_AUTH_DATA_LEN..];
    validate_client_data_json(client_data_json, &base64url_32(hash.as_bytes()))?;

    let client_data_hash = Sha256::digest(client_data_json);
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    let digest = hasher.finalize();

    let mut out = [0_u8; PayloadHash::LENGTH];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn base64url_32(input: &[u8; PayloadHash::LENGTH]) -> [u8; 43] {
    let mut out = [0_u8; 43];
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index + 3 <= input.len() {
        let bits = (u32::from(input[input_index]) << 16)
            | (u32::from(input[input_index + 1]) << 8)
            | u32::from(input[input_index + 2]);
        out[output_index] = BASE64URL[((bits >> 18) & 0x3f) as usize];
        out[output_index + 1] = BASE64URL[((bits >> 12) & 0x3f) as usize];
        out[output_index + 2] = BASE64URL[((bits >> 6) & 0x3f) as usize];
        out[output_index + 3] = BASE64URL[(bits & 0x3f) as usize];
        input_index += 3;
        output_index += 4;
    }

    let bits = (u32::from(input[input_index]) << 16) | (u32::from(input[input_index + 1]) << 8);
    out[output_index] = BASE64URL[((bits >> 18) & 0x3f) as usize];
    out[output_index + 1] = BASE64URL[((bits >> 12) & 0x3f) as usize];
    out[output_index + 2] = BASE64URL[((bits >> 6) & 0x3f) as usize];

    out
}

fn validate_client_data_json(
    input: &[u8],
    expected_challenge: &[u8; 43],
) -> Result<(), WebAuthnError> {
    let mut parser = JsonParser::new(input);
    parser.skip_ws();
    parser.expect(b'{')?;

    let mut seen_type = false;
    let mut seen_challenge = false;

    parser.skip_ws();
    if parser.consume(b'}') {
        return Err(WebAuthnError::MissingClientDataField);
    }

    loop {
        parser.skip_ws();
        let key = parser.parse_string()?;
        parser.skip_ws();
        parser.expect(b':')?;
        parser.skip_ws();

        match field_name(key) {
            FieldName::Type => {
                if seen_type {
                    return Err(WebAuthnError::DuplicateClientDataField);
                }
                seen_type = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != b"webauthn.get" {
                    return Err(WebAuthnError::InvalidClientDataType);
                }
            }
            FieldName::Challenge => {
                if seen_challenge {
                    return Err(WebAuthnError::DuplicateClientDataField);
                }
                seen_challenge = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != expected_challenge {
                    return Err(WebAuthnError::InvalidChallenge);
                }
            }
            FieldName::Other => parser.skip_value(0)?,
        }

        parser.skip_ws();
        if parser.consume(b'}') {
            break;
        }
        parser.expect(b',')?;
    }

    parser.skip_ws();
    if !parser.is_done() {
        return Err(WebAuthnError::InvalidClientDataJson);
    }
    if !seen_type || !seen_challenge {
        return Err(WebAuthnError::MissingClientDataField);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct JsonString<'a> {
    bytes: &'a [u8],
    escaped: bool,
}

#[derive(Debug, Clone, Copy)]
enum FieldName {
    Type,
    Challenge,
    Other,
}

fn field_name(value: JsonString<'_>) -> FieldName {
    if value.escaped {
        return FieldName::Other;
    }
    match value.bytes {
        b"type" => FieldName::Type,
        b"challenge" => FieldName::Challenge,
        _ => FieldName::Other,
    }
}

#[derive(Debug, Clone, Copy)]
struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    const fn is_done(&self) -> bool {
        self.pos == self.input.len()
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek()
            && matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), WebAuthnError> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(WebAuthnError::InvalidClientDataJson)
        }
    }

    fn parse_string(&mut self) -> Result<JsonString<'a>, WebAuthnError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut escaped = false;

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Ok(JsonString {
                        bytes: &self.input[start..end],
                        escaped,
                    });
                }
                b'\\' => {
                    escaped = true;
                    self.pos += 1;
                    self.skip_escape()?;
                }
                0x00..=0x1f => return Err(WebAuthnError::InvalidClientDataJson),
                _ => self.pos += 1,
            }
        }

        Err(WebAuthnError::InvalidClientDataJson)
    }

    fn skip_escape(&mut self) -> Result<(), WebAuthnError> {
        let Some(byte) = self.peek() else {
            return Err(WebAuthnError::InvalidClientDataJson);
        };
        self.pos += 1;
        match byte {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(()),
            b'u' => {
                for _ in 0..4 {
                    let Some(hex) = self.peek() else {
                        return Err(WebAuthnError::InvalidClientDataJson);
                    };
                    if !hex.is_ascii_hexdigit() {
                        return Err(WebAuthnError::InvalidClientDataJson);
                    }
                    self.pos += 1;
                }
                Ok(())
            }
            _ => Err(WebAuthnError::InvalidClientDataJson),
        }
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), WebAuthnError> {
        if depth > MAX_JSON_DEPTH {
            return Err(WebAuthnError::InvalidClientDataJson);
        }
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b'{') => self.skip_object(depth + 1),
            Some(b'[') => self.skip_array(depth + 1),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => Err(WebAuthnError::InvalidClientDataJson),
        }
    }

    fn skip_object(&mut self, depth: usize) -> Result<(), WebAuthnError> {
        self.expect(b'{')?;
        self.skip_ws();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            self.skip_ws();
            self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_value(depth)?;
            self.skip_ws();
            if self.consume(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn skip_array(&mut self, depth: usize) -> Result<(), WebAuthnError> {
        self.expect(b'[')?;
        self.skip_ws();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.skip_value(depth)?;
            self.skip_ws();
            if self.consume(b']') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), WebAuthnError> {
        if self.input.len().saturating_sub(self.pos) < literal.len() {
            return Err(WebAuthnError::InvalidClientDataJson);
        }
        if &self.input[self.pos..self.pos + literal.len()] != literal {
            return Err(WebAuthnError::InvalidClientDataJson);
        }
        self.pos += literal.len();
        Ok(())
    }

    fn skip_number(&mut self) -> Result<(), WebAuthnError> {
        let start = self.pos;
        while let Some(byte) = self.peek()
            && matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        {
            self.pos += 1;
        }
        if self.pos == start {
            Err(WebAuthnError::InvalidClientDataJson)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_base64url_matches_known_value() {
        let hash = PayloadHash::from_bytes([0; PayloadHash::LENGTH]);
        assert_eq!(
            base64url_32(hash.as_bytes()),
            *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
    }

    #[test]
    fn client_data_rejects_nested_challenge_injection() {
        let expected = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let attack =
            br#"{"type":"webauthn.get","challenge":"bad","extra":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;

        assert_eq!(
            validate_client_data_json(attack, &expected),
            Err(WebAuthnError::InvalidChallenge),
        );
    }
}
