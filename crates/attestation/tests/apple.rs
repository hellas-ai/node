#![cfg(feature = "apple-app-attest")]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AppleVerdict, RegisteredAppleCredential,
    appraise_apple, register_apple, verify_apple_assertion,
};

const ATTESTATION: &str = "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";
const ASSERTION: &str = "omlzaWduYXR1cmVYSDBGAiEArgYZlV4ENGjcEL2VxZ+VV+AKIR4t0+CHtnQYsQGJaCQCIQDKtWNuxQ/aPsF2b9ofegvPA7BHZB3TQIWOKTEgefmXGHFhdXRoZW50aWNhdG9yRGF0YViZl3UZ9S7UG1oAfJ1f4CeSJqkc2TZAHMPIDLB1ASegE0tAAAAAAaN1YXBwbGVfY2RfaGFzaF9oYXNoXzAxWCDLkqiQkVRXsib+qb53j8aimZSixg36pgNx6eJk2FQTBnVhcHBsZV9jZF9oYXNoX3R5cGVfMDFBAngcYXBwbGVfdmFsaWRhdGlvbl9jYXRlZ29yeV8wMUQGAAAA";
const ROOT: &str = "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD";

fn bytes(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn credential() -> RegisteredAppleCredential {
    let credential = AppleCredential {
        attestation: bytes(ATTESTATION),
        client_data_hash: bytes("JsCMkdwVLNrsuBo6U4TbyH5FAsmW0fpK7mN1JdtJlzQ=")
            .try_into()
            .unwrap(),
    };
    register_apple(
        &credential,
        bytes("l3UZ9S7UG1oAfJ1f4CeSJqkc2TZAHMPIDLB1ASegE0s=")
            .try_into()
            .unwrap(),
        &bytes(ROOT),
        AnchorTime(1_784_384_387),
    )
    .unwrap()
}

#[test]
fn verifies_sanitized_mac_fixture() {
    let registered = credential();
    let hash: [u8; 32] = bytes("30u+eepBuE/GrsOTXpSfQGmNXHFGZ6oae+RG3pWVQco=")
        .try_into()
        .unwrap();
    let claims = verify_apple_assertion(&bytes(ASSERTION), &hash, &registered).unwrap();

    assert_eq!(claims.counter, 1);
    assert_eq!(
        appraise_apple(
            &claims,
            &ApplePolicy {
                allowed_cd_hashes: vec![claims.cd_hash]
            }
        ),
        AppleVerdict::Accepted
    );
}

#[test]
fn rejects_other_statement() {
    let registered = credential();
    assert!(verify_apple_assertion(&bytes(ASSERTION), &[0; 32], &registered).is_err());
}
