//! Compile-time-ish guards on `Tx` enum size.
//!
//! This file pins the resulting sizes so an accidental future field
//! addition surfaces as a test failure rather than a silent footprint
//! regression. Numbers are platform-dependent (alignment), so the assertions
//! cap rather than equal — bumping the cap deliberately is a one-line
//! review item, but a 2× regression would break the build.

#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src
use core::mem::size_of;
use hellas_kernel::{Auth, Funding, Payout, Proof, Terms, Tx, WebAuthnAssertion};

#[test]
fn tx_size_within_envelope() {
    // The 6 KiB cap on `Tx` is a sanity guard, not a target. Opens and
    // mutual closes deliberately carry bounded browser assertion bytes
    // inline. Stack frames for `List<Tx, N>` scale linearly here.
    //
    // The cap was 5 KiB until the work-channel terms landed: a work
    // payment carries a complete bond body inside its own, which is
    // also why the encoded `Terms` maximum moved from 335 to 555 bytes.
    // That is one deliberate step, pinned by the canonical goldens.
    assert!(
        size_of::<Tx>() <= 6 * 1024,
        "Tx size {} exceeds 6 KiB cap",
        size_of::<Tx>(),
    );
}

#[test]
fn component_sizes() {
    // Per-component sizes for visibility. Bumping any of these caps is a
    // deliberate review item.
    // Mutual carries two inline Auth witnesses, so Proof is sized by the
    // WebAuthn worst case just like Tx::Open.
    assert!(
        size_of::<Proof>() <= 2 * 2304 + 128,
        "Proof size {}",
        size_of::<Proof>()
    );
    assert!(size_of::<Auth>() <= 2304, "Auth size {}", size_of::<Auth>());
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
    // A work payment holds a whole bond body, so `Terms` is sized by
    // that nesting rather than by its own fields.
    assert!(
        size_of::<Terms>() <= 768,
        "Terms size {}",
        size_of::<Terms>()
    );
}
