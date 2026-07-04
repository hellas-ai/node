use hellas_rpc::mux::MethodSet;

pub const METHOD_GET_STATE_ROOT: u8 = 0;
pub const METHOD_GET_PROOF: u8 = 1;
pub const METHOD_GET_COIN: u8 = 2;
pub const METHOD_GET_FINALIZATION: u8 = 3;
pub const METHOD_GET_LATEST_BLOCK: u8 = 4;
pub const METHOD_GET_FINALIZED_BLOCK: u8 = 5;
pub const METHOD_SUBMIT_TX: u8 = 6;
pub const METHOD_SUBSCRIBE_ACTIVITY: u8 = 7;
pub const METHOD_GET_VALIDATORS: u8 = 8;
pub const METHOD_GET_COINS_BY_OWNER: u8 = 9;
pub const METHOD_GET_RELAY_INFO: u8 = 10;
pub const METHOD_GET_CONSENSUS_INFO: u8 = 11;

pub const METHOD_PATHS: [&str; 12] = [
    "/hellas.LightClient/GetStateRoot",
    "/hellas.LightClient/GetProof",
    "/hellas.LightClient/GetCoin",
    "/hellas.LightClient/GetFinalization",
    "/hellas.LightClient/GetLatestBlock",
    "/hellas.LightClient/GetFinalizedBlock",
    "/hellas.LightClient/SubmitTx",
    "/hellas.LightClient/SubscribeActivity",
    "/hellas.LightClient/GetValidators",
    "/hellas.LightClient/GetCoinsByOwner",
    "/hellas.LightClient/GetRelayInfo",
    "/hellas.LightClient/GetConsensusInfo",
];

pub const STREAMING_METHODS: [u8; 1] = [METHOD_SUBSCRIBE_ACTIVITY];
pub const LIGHT_CLIENT_METHODS: MethodSet = MethodSet::new(&METHOD_PATHS, &STREAMING_METHODS);
