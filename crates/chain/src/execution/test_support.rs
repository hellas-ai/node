use crate::HellasBlock;
use crate::domain::{Address, ObjectId, PrivateKey, SettlementKey, Transaction, genesis_object_id};
use crate::execution::store::UtxoSyncTarget;
use commonware_consensus::{
    CertifiableBlock, Heightable,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, Signer as _, ed25519};
use commonware_runtime::{Runner as _, tokio};
use commonware_storage::{merkle::Location, mmr};
use commonware_utils::non_empty_range;
use core::future::Future;
use hellas_kernel::test_support::{SoftPasskey, SoftPasskeyError};
use hellas_kernel::{
    Auth, BlockHeight, CloseKind, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, Parties, Payout, Proof, ProtocolCode, Terms, Tx,
};

pub(crate) fn run_qmdb<F, Fut, T>(test: F) -> T
where
    F: FnOnce(tokio::Context) -> Fut,
    Fut: Future<Output = T>,
{
    let directory = tempfile::tempdir().expect("QMDB tempdir");
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(test)
}

pub(crate) fn validator_key(seed: u64) -> PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

pub(crate) fn legacy_address(seed: u64) -> Address {
    Address::from(validator_key(seed).public_key())
}

pub(crate) fn index_genesis() -> HellasBlock {
    let sync_target = UtxoSyncTarget::new(
        commonware_cryptography::sha256::Digest::EMPTY,
        non_empty_range!(
            Location::<mmr::Family>::new(0),
            Location::<mmr::Family>::new(1)
        ),
    );
    HellasBlock::genesis(
        validator_key(0).public_key(),
        commonware_cryptography::sha256::Digest::EMPTY,
        sync_target,
    )
}

pub(crate) fn index_block(
    parent: &HellasBlock,
    state_root: commonware_cryptography::sha256::Digest,
    txs: Vec<Transaction>,
) -> HellasBlock {
    let height = parent.height().get() + 1;
    let sync_target = UtxoSyncTarget::new(
        state_root,
        non_empty_range!(
            Location::<mmr::Family>::new(0),
            Location::<mmr::Family>::new(1)
        ),
    );
    HellasBlock::new(
        Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: validator_key(0).public_key(),
            parent: (parent.context().round.view(), parent.digest()),
        },
        parent.digest(),
        Height::new(height),
        height,
        state_root,
        sync_target,
        txs,
    )
}

pub(crate) struct KernelFixture {
    pub(crate) allocations: Vec<(SettlementKey, u64)>,
    pub(crate) maker: SettlementKey,
    pub(crate) funding: Funding,
    pub(crate) terms: Terms,
    pub(crate) outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    pub(crate) edge: EdgeId,
    pub(crate) open: Tx,
    pub(crate) mutual_close: Tx,
    pub(crate) timeout_close: Tx,
    maker_passkey: SoftPasskey,
    taker_passkey: SoftPasskey,
}

impl KernelFixture {
    pub(crate) fn payout_ids(&self) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        Tx::close_output_ids(self.edge, &self.outputs)
    }

    pub(crate) fn bad_auth_open(&self) -> Result<Tx, SoftPasskeyError> {
        let hash = Tx::open_hash(&self.funding, &self.terms);
        let wrong_hash = Tx::payload_hash(
            self.edge,
            CloseKind::Mutual,
            self.terms.hash(),
            &self.outputs,
        );
        Ok(Tx::open(
            self.funding.clone(),
            self.terms.clone(),
            Auth::webauthn(self.maker_passkey.sign(wrong_hash)?),
            Auth::webauthn(self.taker_passkey.sign(hash)?),
        ))
    }
}

fn coin_id(id: ObjectId) -> CoinId {
    CoinId::from_bytes(id.0)
}

pub(crate) fn kernel_fixture(timeout: u64) -> Result<KernelFixture, SoftPasskeyError> {
    kernel_fixture_at(timeout, 0, 7, 8)
}

pub(crate) fn kernel_fixture_at(
    timeout: u64,
    first_allocation: u16,
    maker_secret: u8,
    taker_secret: u8,
) -> Result<KernelFixture, SoftPasskeyError> {
    let maker_passkey = SoftPasskey::from_secret_scalar([maker_secret; 32])?;
    let taker_passkey = SoftPasskey::from_secret_scalar([taker_secret; 32])?;
    let maker = SettlementKey::from(maker_passkey.party_key());
    let taker = SettlementKey::from(taker_passkey.party_key());
    let taker_allocation = first_allocation
        .checked_add(1)
        .expect("test fixture allocation index overflow");
    let maker_inputs = List::take(
        [coin_id(genesis_object_id(first_allocation)); MAX_PARTY_INPUTS],
        1,
    );
    let taker_inputs = List::take(
        [coin_id(genesis_object_id(taker_allocation)); MAX_PARTY_INPUTS],
        1,
    );
    let funding = Funding::new(maker_inputs, taker_inputs);
    let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
    if let Some(payout) = payout_values.first_mut() {
        *payout = Payout::new(maker_passkey.party_key(), 40);
    }
    if let Some(payout) = payout_values.get_mut(1) {
        *payout = Payout::new(taker_passkey.party_key(), 60);
    }
    let outputs = List::take(payout_values, 2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(maker_passkey.party_key(), taker_passkey.party_key()),
        BlockHeight::new(timeout),
        outputs.clone(),
    );
    let edge = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(&funding, &terms);
    let open = Tx::open(
        funding.clone(),
        terms.clone(),
        Auth::webauthn(maker_passkey.sign(open_hash)?),
        Auth::webauthn(taker_passkey.sign(open_hash)?),
    );
    let close_hash = Tx::payload_hash(edge, CloseKind::Mutual, terms.hash(), &outputs);
    let mutual_close = Tx::close(
        edge,
        Proof::mutual(
            Auth::webauthn(maker_passkey.sign(close_hash)?),
            Auth::webauthn(taker_passkey.sign(close_hash)?),
        ),
        outputs.clone(),
    );
    let timeout_close = Tx::close(edge, Proof::timeout(terms.clone()), outputs.clone());

    Ok(KernelFixture {
        allocations: vec![(maker, 40), (taker, 60)],
        maker,
        funding,
        terms,
        outputs,
        edge,
        open,
        mutual_close,
        timeout_close,
        maker_passkey,
        taker_passkey,
    })
}
