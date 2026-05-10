//! Compile-time-ish guards on `Op` enum size.
//!
//! Several recent changes traded bytes for cycles by caching hashes
//! (`Open::terms_hash`, `Proof::Timeout/Claimant/Challenger::terms_hash`).
//! This file pins the resulting sizes so an accidental future field
//! addition surfaces as a test failure rather than a silent footprint
//! regression. Numbers are platform-dependent (alignment), so the assertions
//! cap rather than equal — bumping the cap deliberately is a one-line
//! review item, but a 2× regression would break the build.

use core::mem::size_of;
use hellas_kernel::{Funding, Op, Open, Payout, Proof, Resolve};

#[test]
fn op_size_within_envelope() {
    // Current sizes (Linux x86_64): Op=624, Open=616, Resolve=584, Proof=352,
    // Funding=272, Payout=48. The 768-byte cap on Op is a sanity guard, not a
    // target. Stack frames for `List<Op, N>` scale linearly here.
    assert!(
        size_of::<Op>() <= 768,
        "Op size {} exceeds 768-byte cap",
        size_of::<Op>(),
    );
}

#[test]
fn open_resolve_proof_sizes() {
    // Per-component sizes for visibility. Bumping any of these caps is a
    // deliberate review item: cached-hash fields trade 32 bytes per cache
    // for one BLAKE3 saved per apply call.
    assert!(size_of::<Open>() <= 720, "Open size {}", size_of::<Open>());
    assert!(
        size_of::<Resolve>() <= 720,
        "Resolve size {}",
        size_of::<Resolve>(),
    );
    assert!(
        size_of::<Proof>() <= 384,
        "Proof size {}",
        size_of::<Proof>()
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
