//! Executable vectors for the kernel `WebAuthn` wire v1 contract.

#![cfg(feature = "test-support")]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use hellas_kernel::{
    Decode, Encode, WebAuthnAssertion, WebAuthnError,
    test_support::{
        SoftPasskey, negative_assertions, valid_mutual_close_assertion, valid_open_assertion,
    },
    verify_webauthn_assertion,
};

const AUTHENTICATOR_DATA_LENGTH: usize = 37;
const COMPONENT_LENGTH: usize = 32;
const ASSERTION_ENVELOPE_LENGTH: usize = 2;
const LIST_LENGTH_PREFIX: usize = 8;
const CLIENT_DATA_PREFIX: &[u8] = b"{\"type\":\"webauthn.get\",\"challenge\":\"";
const CLIENT_DATA_SUFFIX: &[u8] =
    b"\",\"origin\":\"https://wallet.example.invalid\",\"crossOrigin\":false}";

#[test]
fn named_positive_assertions_verify_for_open_and_mutual_close() {
    let open = valid_open_assertion().expect("valid open fixture builds");
    let close = valid_mutual_close_assertion().expect("valid close fixture builds");

    assert_eq!(open.name(), "valid_open_assertion");
    assert_eq!(close.name(), "valid_mutual_close_assertion");
    assert_ne!(open.payload_hash(), close.payload_hash());
    assert_eq!(
        verify_webauthn_assertion(open.assertion(), open.party_key(), open.payload_hash()),
        Ok(()),
    );
    assert_eq!(
        verify_webauthn_assertion(close.assertion(), close.party_key(), close.payload_hash()),
        Ok(()),
    );
}

#[test]
fn named_negative_assertions_pin_every_verifier_error() {
    let fixtures = negative_assertions().expect("negative fixtures build");
    let expected = [
        ("wrong_challenge", WebAuthnError::InvalidChallenge),
        ("high_s", WebAuthnError::HighS),
        ("wrong_signer_key", WebAuthnError::SignerMismatch),
        (
            "attested_credential_data",
            WebAuthnError::AttestedCredentialDataUnsupported,
        ),
        ("extension_data", WebAuthnError::ExtensionsUnsupported),
        (
            "missing_user_presence_and_verification",
            WebAuthnError::MissingUserPresence,
        ),
        (
            "nested_json_injection",
            WebAuthnError::InvalidClientDataJson,
        ),
        (
            "duplicate_required_field",
            WebAuthnError::DuplicateClientDataField,
        ),
        (
            "wrong_client_data_type",
            WebAuthnError::InvalidClientDataType,
        ),
    ];

    for (fixture, (name, error)) in fixtures.iter().zip(expected) {
        assert_eq!(fixture.name(), name);
        assert_eq!(fixture.expected_error(), error);
        assert_eq!(
            verify_webauthn_assertion(
                fixture.assertion(),
                fixture.party_key(),
                fixture.payload_hash(),
            ),
            Err(error),
            "fixture {name} changed verifier behavior",
        );
    }
}

#[test]
fn soft_passkey_derives_compressed_sec1_key_and_signs_payloads() {
    let passkey =
        SoftPasskey::from_secret_scalar([3; COMPONENT_LENGTH]).expect("fixture scalar is valid");
    let fixture = valid_open_assertion().expect("valid open fixture builds");
    let assertion = passkey
        .sign(fixture.payload_hash())
        .expect("soft signing succeeds");

    assert!(matches!(passkey.party_key().as_bytes()[0], 0x02 | 0x03));
    assert_eq!(assertion.pub_key_x(), passkey.pub_key_x());
    assert_eq!(assertion.pub_key_y(), passkey.pub_key_y());
    assert_eq!(
        verify_webauthn_assertion(&assertion, passkey.party_key(), fixture.payload_hash()),
        Ok(()),
    );
}

#[test]
fn helper_output_matches_the_documented_byte_layout() {
    let fixture = valid_open_assertion().expect("valid open fixture builds");
    let assertion = fixture.assertion();
    let webauthn_data = assertion.webauthn_data().as_slice();
    let (authenticator_data, client_data_json) = webauthn_data.split_at(AUTHENTICATOR_DATA_LENGTH);

    assert_eq!(
        &authenticator_data[..COMPONENT_LENGTH],
        &[0xaa; COMPONENT_LENGTH]
    );
    assert_eq!(authenticator_data[COMPONENT_LENGTH], 0x01);
    assert_eq!(&authenticator_data[COMPONENT_LENGTH + 1..], &[0; 4]);
    assert!(client_data_json.starts_with(CLIENT_DATA_PREFIX));
    assert!(client_data_json.ends_with(CLIENT_DATA_SUFFIX));
    let challenge_start = CLIENT_DATA_PREFIX.len();
    let challenge_end = challenge_start + 43;
    let challenge = &client_data_json[challenge_start..challenge_end];
    assert_eq!(challenge.len(), 43);
    assert!(!challenge.contains(&b'='));
    assert!(
        challenge
            .iter()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_') })
    );
    assert_eq!(&client_data_json[challenge_end..], CLIENT_DATA_SUFFIX);

    let mut encoded = [0_u8; WebAuthnAssertion::MAX_ENCODED_SIZE];
    let written = assertion.write_to(&mut encoded);
    let r_start = ASSERTION_ENVELOPE_LENGTH;
    let s_start = r_start + COMPONENT_LENGTH;
    let x_start = s_start + COMPONENT_LENGTH;
    let y_start = x_start + COMPONENT_LENGTH;
    let data_length_start = y_start + COMPONENT_LENGTH;
    let data_start = data_length_start + LIST_LENGTH_PREFIX;

    assert_eq!(&encoded[..ASSERTION_ENVELOPE_LENGTH], &[1, 9]);
    assert_eq!(&encoded[r_start..s_start], assertion.r());
    assert_eq!(&encoded[s_start..x_start], assertion.s());
    assert_eq!(&encoded[x_start..y_start], assertion.pub_key_x());
    assert_eq!(&encoded[y_start..data_length_start], assertion.pub_key_y());
    let mut length_bytes = [0_u8; LIST_LENGTH_PREFIX];
    length_bytes.copy_from_slice(&encoded[data_length_start..data_start]);
    assert_eq!(
        usize::try_from(u64::from_be_bytes(length_bytes)).expect("fixture length fits usize"),
        webauthn_data.len(),
    );
    assert_eq!(&encoded[data_start..written], webauthn_data);
    assert_eq!(
        WebAuthnAssertion::decode_exact(&encoded[..written]),
        Ok(assertion.clone()),
    );
}
