use super::{BlockKey, ShardMessage, ZodaCommitment, ZodaShard};
use futures::channel::mpsc;
use hellas_types::PublicKey;
use std::{future::Future, pin::Pin};

pub(crate) trait ShardTransport: Send + Sync + 'static {
    fn register(&self, public_key: &PublicKey) -> mpsc::UnboundedReceiver<ShardMessage>;
    fn validator_count(&self) -> u16;
    fn validator_index(&self, public_key: &PublicKey) -> Option<u16>;

    // Boxed futures keep this trait object-safe (`dyn ShardTransport` is used by
    // the application actor). `async fn` in traits would not be object-safe here.
    fn broadcast_except<'a>(
        &'a self,
        sender: &'a PublicKey,
        message: ShardMessage,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    fn distribute_shards<'a>(
        &'a self,
        proposer: &'a PublicKey,
        key: BlockKey,
        commitment: ZodaCommitment,
        shards: Vec<ZodaShard>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}
