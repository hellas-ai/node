use super::protocol::{BlockKey, ShardMessage, ZodaCommitment, ZodaShard};
use futures::channel::mpsc;
use hellas_types::PublicKey;
use std::future::Future;

pub(crate) trait ShardTransport: Send + Sync + 'static {
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage>;
    fn validator_count(&self) -> u16;
    fn validator_index(&self, public_key: &PublicKey) -> Option<u16>;

    fn broadcast_except<'a>(
        &'a self,
        sender: &'a PublicKey,
        message: ShardMessage,
    ) -> impl Future<Output = ()> + Send + 'a;

    fn distribute_shards<'a>(
        &'a self,
        proposer: &'a PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) -> impl Future<Output = ()> + Send + 'a;
}
