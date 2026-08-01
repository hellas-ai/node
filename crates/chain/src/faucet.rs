//! Dev faucet: bridges P-256 genesis funds to secp256k1 coins.
//!
//! Genesis allocations on a dev chain are owned by P-256 (WebAuthn)
//! settlement keys, but the staked payment/bond flow funds its edges
//! with secp256k1 kernel party keys. The kernel treats a coin owner and
//! a party key as opaque 33-byte values — no curve check — so a single
//! `Basic` edge bridges the two: the faucet's P-256 identity funds the
//! edge (authorising the open with a WebAuthn assertion), and the edge's
//! `timeout_outputs` pay an arbitrary secp256k1 `recipient`. The timeout
//! close needs no signature, so anyone can complete the bridge once the
//! timeout height passes — the recipient never signs anything.
//!
//! This is a development facility. It performs no kernel changes and
//! grants no value the genesis allocation did not already hold; it only
//! re-owns it under a secp256k1 key.

use hellas_kernel::{
    Auth, BlockHeight, CoinId, EdgeId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    Parties, Payout, ProtocolCode, Secp256k1Signer, SoftPasskey, SoftPasskeyError, Terms,
    Tx as KernelTx,
};

/// Protocol code for the faucet's `Basic` bridge edge.
pub const FAUCET_PROTOCOL: ProtocolCode = ProtocolCode::new(4);

/// A dev faucet: a P-256 genesis identity plus a secp256k1 party key,
/// minting secp256k1-owned coins from the genesis funds the P-256
/// identity holds.
#[derive(Debug)]
pub struct Faucet {
    /// P-256 identity that owns the genesis coins and authorises the
    /// bridge open (the edge maker).
    funder: SoftPasskey,
    /// The faucet's own secp256k1 key: the edge taker, contributing no
    /// funding but co-signing the open so the recipient need not.
    party: Secp256k1Signer,
}

impl Faucet {
    /// Creates a faucet from its P-256 funder and secp256k1 party key.
    #[must_use]
    pub const fn new(funder: SoftPasskey, party: Secp256k1Signer) -> Self {
        Self { funder, party }
    }

    /// The P-256 settlement key whose genesis coins this faucet spends.
    /// Fund the faucet by seeding a genesis allocation to this key.
    #[must_use]
    pub const fn funder_key(&self) -> Key {
        self.funder.party_key()
    }

    /// Builds the bridge open: a `Basic` edge funded by `genesis_coin`
    /// (owned by [`Self::funder_key`]) whose timeout refunds `value` to
    /// the secp256k1 `recipient`. `value` must equal the genesis coin's
    /// value (the edge locks it in full under the zero dev-fee
    /// schedule). Returns the open transaction, the revealed terms
    /// (needed to close), and the resulting edge id.
    ///
    /// # Errors
    ///
    /// Returns [`SoftPasskeyError::Assertion`] if the funder passkey cannot
    /// sign the canonical open hash.
    pub fn open(
        &self,
        genesis_coin: CoinId,
        recipient: Key,
        value: u64,
        timeout: BlockHeight,
    ) -> Result<(KernelTx, Terms, EdgeId), SoftPasskeyError> {
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(recipient, value);
        let terms = Terms::basic(
            FAUCET_PROTOCOL,
            Parties::new(self.funder.party_key(), self.party.party_key()),
            timeout,
            List::take(outputs, 1),
        );
        let funding = Funding::new(
            List::take([genesis_coin; MAX_PARTY_INPUTS], 1),
            List::take([genesis_coin; MAX_PARTY_INPUTS], 0),
        );
        let open_hash = KernelTx::open_hash(&funding, &terms);
        let assertion = self
            .funder
            .sign(open_hash)
            ?;
        let open = KernelTx::open(
            funding.clone(),
            terms.clone(),
            Auth::webauthn(assertion),
            Auth::native(self.party.sign(open_hash)),
        );
        let edge = KernelTx::edge_id_of(&funding, &terms);
        Ok((open, terms, edge))
    }
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;
    use crate::domain::{
        Coin, Object, SettlementKey, Transaction, coin_object_id, edge_object_id, genesis_object_id,
    };
    use crate::execution::store::{UtxoDatabase, utxo_db_config};
    use crate::execution::test_support::run_qmdb;
    use crate::execution::{ChainVerifier, execute_all};
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use hellas_kernel::{BlockHash, Context as KernelContext};

    const VALUE: u64 = 5_000;
    const TIMEOUT: u64 = 50;

    fn context(height: u64) -> KernelContext {
        KernelContext::with_fees(
            BlockHeight::new(height),
            BlockHash::from_bytes([0; BlockHash::LENGTH]),
            crate::domain::KERNEL_FEES,
        )
    }

    fn secp(seed: u8) -> Secp256k1Signer {
        let Ok(signer) = Secp256k1Signer::from_secret_scalar([seed; 32]) else {
            panic!("non-zero scalar");
        };
        signer
    }

    fn passkey(seed: u8) -> SoftPasskey {
        let Ok(passkey) = SoftPasskey::from_secret_scalar([seed; 32]) else {
            panic!("non-zero scalar");
        };
        passkey
    }

    /// The faucet bridges a P-256-owned genesis coin into a
    /// secp256k1-owned coin at consensus execution: the WebAuthn-signed
    /// open locks the genesis funds, and the unsigned timeout close mints
    /// the recipient's secp256k1 coin.
    #[test]
    fn faucet_bridges_p256_genesis_into_a_secp256k1_coin_at_consensus_execution() {
        run_qmdb(|runtime| async move {
            let recipient = secp(23).party_key();
            let faucet = Faucet::new(passkey(21), secp(22));
            let genesis_coin = CoinId::from_bytes(genesis_object_id(0).0);
            let (open, terms, edge) = faucet
                .open(genesis_coin, recipient, VALUE, BlockHeight::new(TIMEOUT))
                .expect("faucet builds the bridge open");
            // The genesis funds are owned by the faucet's P-256 identity.
            let allocations = vec![(SettlementKey::from(faucet.funder_key()), VALUE)];

            let verifier = ChainVerifier::new();
            let config = utxo_db_config(&runtime, "faucet_e2e", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let batches = execute_all(
                context(1),
                &verifier,
                &[Transaction::Kernel(open)],
                &allocations,
                database.new_batches().await,
            )
            .await
            .expect("the WebAuthn-signed bridge opens");
            let merkleized = batches.merkleize().await.expect("open merkleizes");
            database.finalize(merkleized).await;

            let close = KernelTx::timeout_close(edge, &terms);
            let batches = execute_all(
                context(TIMEOUT),
                &verifier,
                &[Transaction::Kernel(close)],
                &allocations,
                database.new_batches().await,
            )
            .await
            .expect("the unsigned timeout close mints the recipient coin");

            assert_eq!(
                batches.get(&edge_object_id(edge)).await.expect("edge read"),
                None,
            );
            let ids = KernelTx::close_output_ids(edge, terms.timeout_outputs());
            assert_eq!(
                batches
                    .get(&coin_object_id(ids.as_slice()[0]))
                    .await
                    .expect("recipient coin read"),
                Some(Object::Coin(Coin {
                    owner: SettlementKey::from(recipient),
                    value: VALUE,
                })),
            );
        });
    }
}
