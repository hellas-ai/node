//! Mixed native/WebAuthn open authorization.
//!
//! This example opens one edge with:
//!
//! - maker authorization as a native secp256k1 signature over `Tx::open_hash`;
//! - taker authorization as a `WebAuthn` assertion whose challenge is the same
//!   canonical open hash.
//!
//! The bundled `Secp256k1Verifier` accepts this shape when both `secp256k1`
//! and `webauthn` are enabled. The example closes by timeout, because a
//! passkey-backed party does not have a portable raw close-signature path in
//! the bundled verifier.
//!
//! Build and run with:
//!
//! ```sh
//! cargo run --example mixed_open_auth --features secp256k1,webauthn
//! ```

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::similar_names)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]

mod support;

use hellas_kernel::{
    BlockHeight, Fees, Funding, Genesis, OpenAuth, Parties, Proof, ProtocolCode, Secp256k1Verifier,
    Terms, Tx,
};
use support::{
    apply_one, coin_id, context, context_fee, genesis, lifetime_fee, p256_public_key,
    p256_signing_key, party_one, payouts2, print_live_coins, schedule_fee, secp_keypair, secp_sign,
    summarize, webauthn_assertion,
};

const FEES: Fees = Fees::new(1, 1, 2, 1);
const PROTOCOL: ProtocolCode = ProtocolCode::new(1);

fn main() {
    let verifier = Secp256k1Verifier::new();
    let (maker_secret, maker_key) = secp_keypair(3);
    let taker_passkey = p256_signing_key(4);
    let (taker_key, _, _) = p256_public_key(&taker_passkey);

    let maker_coin = coin_id(0xc1);
    let taker_coin = coin_id(0xd1);
    let open_context = context(1, 0x30, FEES);
    let close_context = context(5, 0x31, FEES);
    let timeout = BlockHeight::new(5);
    let timeout_outputs = payouts2(maker_key, 30, taker_key, 16);
    let terms = Terms::basic(
        PROTOCOL,
        Parties::new(maker_key, taker_key),
        timeout,
        timeout_outputs.clone(),
    );
    let funding = Funding::new(party_one(maker_coin), party_one(taker_coin));
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(&funding, &terms);
    let (taker_assertion, assertion_key) =
        webauthn_assertion(&taker_passkey, open_hash, "https://wallet.example.invalid");
    assert_eq!(assertion_key, taker_key);

    let open = Tx::open_with_auth(
        funding,
        terms.clone(),
        OpenAuth::native(secp_sign(&maker_secret, open_hash)),
        OpenAuth::webauthn(taker_assertion),
    );
    let open_fee = context_fee(open_context, open.cost());
    let lifetime_fee = lifetime_fee(open_context, timeout);
    let mut state = genesis(&[
        Genesis::coin(maker_coin, maker_key, 40),
        Genesis::coin(taker_coin, taker_key, 20),
    ]);

    println!("== Hellas mixed open auth ==");
    println!("maker: native secp256k1 open auth");
    println!("taker: WebAuthn open auth with passkey P-256 key");

    let event = apply_one(&mut state, &verifier, open_context, open);
    let opened = state.store().edge(edge_id).expect("open inserted edge");
    println!();
    println!(
        "open @{}: {}",
        open_context.block_height().get(),
        summarize(&event),
    );
    println!(
        "  funding 60 -> principal {}, reserve {} (open fee {}, lifetime fee {})",
        opened.value(),
        opened.reserve(),
        open_fee,
        lifetime_fee,
    );

    let close = Tx::close(edge_id, Proof::timeout(terms), timeout_outputs);
    let close_fee = schedule_fee(opened.close_fees(), close.cost());
    let event = apply_one(&mut state, &verifier, close_context, close);
    println!(
        "timeout close @{}: {}",
        close_context.block_height().get(),
        summarize(&event),
    );
    println!("  close fee {close_fee} paid from reserve");
    print_live_coins(state.store());
}
