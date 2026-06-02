//! Compile-time-ish guards on `Tx` enum size.
//!
//! This file pins the resulting sizes so an accidental future field
//! addition surfaces as a test failure rather than a silent footprint
//! regression. Numbers are platform-dependent (alignment), so the assertions
//! cap rather than equal — bumping the cap deliberately is a one-line
//! review item, but a 2× regression would break the build.

use core::mem::size_of;
use hellas_kernel::{Funding, OpenAuth, Payout, Proof, Tx, WebAuthnAssertion};

#[test]
fn tx_size_within_envelope() {
    // The 5 KiB cap on `Tx` is a sanity guard, not a target. WebAuthn
    // open auth deliberately carries bounded browser assertion bytes, so
    // the old native-only 768-byte envelope no longer applies.
    // Stack frames for `List<Tx, N>` scale linearly here.
    assert!(
        size_of::<Tx>() <= 5 * 1024,
        "Tx size {} exceeds 5 KiB cap",
        size_of::<Tx>(),
    );
}

#[test]
fn component_sizes() {
    // Per-component sizes for visibility. Bumping any of these caps is a
    // deliberate review item.
    assert!(
        size_of::<Proof>() <= 384,
        "Proof size {}",
        size_of::<Proof>()
    );
    assert!(
        size_of::<OpenAuth>() <= 2304,
        "OpenAuth size {}",
        size_of::<OpenAuth>(),
    );
    assert!(
        size_of::<WebAuthnAssertion>() <= 2304,
        "WebAuthnAssertion size {}",
        size_of::<WebAuthnAssertion>(),
    );
    assert!(
        size_of::<Funding>() <= 320,
        "Funding size {}",
        size_of::<Funding>(),
    );
    assert!(
        size_of::<Payout>() <= 64,
        "Payout size {}",
        size_of::<Payout>(),
    );
}
