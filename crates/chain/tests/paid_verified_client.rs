#![cfg(all(feature = "client", feature = "server", feature = "work-watcher"))]

use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::types::{Finalization as SimplexFinalization, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, ordered::Set};
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::domain::{
    Coin, Digest, ObjectId, Scheme, SettlementKey, ThresholdVariant, Transaction,
};
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, EdgeLookup, FinalizedBlock, FinalizedBlockQuery,
    FinalizedWorkView, LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
    SubmitTxOutcome, WorkBlocks, WorkChannelQuery, WorkChannelSnapshot,
};
use hellas_work::work_close::FinalizedBlocks as _;
use rand::{SeedableRng as _, rngs::StdRng};

struct SigningFixture {
    schemes: Vec<Scheme>,
    assembler: Scheme,
    info: ConsensusInfo,
}

fn signing_fixture(seed: u64) -> SigningFixture {
    let private_keys = (0..4)
        .map(|offset| ed25519::PrivateKey::from_seed(seed + offset))
        .collect::<Vec<_>>();
    let leaders = private_keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>();
    let participants = Set::try_from(leaders.clone()).expect("unique participants");
    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants.clone())
            .expect("threshold deal");
    let polynomial = output.public().clone();
    let schemes = private_keys
        .iter()
        .map(|key| {
            let share = shares
                .get_value(&key.public_key())
                .expect("threshold share")
                .clone();
            Scheme::signer(
                hellas_chain::CONSENSUS_NAMESPACE,
                participants.clone(),
                polynomial.clone(),
                share,
            )
            .expect("consensus signer")
        })
        .collect::<Vec<_>>();
    let assembler = Scheme::verifier(hellas_chain::CONSENSUS_NAMESPACE, participants, polynomial);
    let info = ConsensusInfo {
        validators: (0..leaders.len())
            .map(|index| format!("ws://validator-{index}"))
            .collect(),
        threshold_identity: assembler.identity().encode().to_vec(),
        network_id: "paid-history-test".to_string(),
    };
    SigningFixture {
        schemes,
        assembler,
        info,
    }
}

fn signed_snapshot(fixture: &SigningFixture) -> LatestBlock {
    let payload = Digest::from([0x51; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::zero(), View::new(7)),
        View::new(6),
        payload,
    );
    let votes = fixture
        .schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize vote"))
        .collect::<Vec<_>>();
    let finalization = SimplexFinalization::from_finalizes(&fixture.assembler, &votes, &Sequential)
        .expect("finalization");
    LatestBlock {
        height: 7,
        payload,
        state_root: Digest::from([0x52; 32]),
        finalization: finalization.encode().to_vec(),
    }
}

#[derive(Clone)]
struct FinalizedHistory(LatestBlock);

impl LightClient for FinalizedHistory {
    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_proof(&self, _object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_coin(
        &self,
        _payload: Digest,
        _object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_edge(
        &self,
        _payload: Digest,
        _object_id: ObjectId,
    ) -> Result<Option<EdgeLookup>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_finalization(&self, _payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        Ok(Some(self.0.clone()))
    }

    async fn get_finalized_block(
        &self,
        _query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn submit_tx(&self, _tx: Transaction) -> Result<SubmitTxOutcome, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_coins_by_owner(
        &self,
        _owner: SettlementKey,
    ) -> Result<Option<OwnerCoins>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }

    async fn get_edges_by_owner(
        &self,
        _owner: SettlementKey,
    ) -> Result<Option<OwnerEdges>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }
}

impl FinalizedWorkView for FinalizedHistory {
    async fn work_channel_snapshot(
        &self,
        _query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        unreachable!("the test asks only for the latest finalized block")
    }
}

#[tokio::test]
async fn paid_block_source_rejects_history_signed_by_another_threshold() {
    let signing = signing_fixture(71);
    let configured = signing_fixture(710);
    assert_ne!(
        signing.info.threshold_identity, configured.info.threshold_identity,
        "the endpoint and the runner use different thresholds",
    );
    let snapshot = signed_snapshot(&signing);
    ConsensusVerifier::new(&signing.info)
        .expect("signing threshold identity")
        .verify_snapshot(&snapshot)
        .expect("the endpoint's history is genuinely signed");

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let addr = probe.local_addr().expect("probe address");
    drop(probe);
    let (activity_tx, _activity_rx) = tokio::sync::broadcast::channel(1);
    let server = hellas_chain::spawn_light_client_server(
        addr,
        FinalizedHistory(snapshot),
        activity_tx,
        hellas_chain::LightClientRpcState::default(),
    )
    .await
    .expect("serve fabricated history");
    let verifier = ConsensusVerifier::new(&configured.info).expect("configured threshold identity");
    let client = VerifiedRemoteLightClient::connect(format!("ws://{addr}"), verifier)
        .await
        .expect("connect paid block source");

    let error = WorkBlocks::new(client)
        .latest_height()
        .await
        .expect_err("a different threshold did not authenticate this history");
    assert!(
        error
            .to_string()
            .contains("finalization verification failed"),
        "unexpected rejection: {error}",
    );
    server.abort();
}
