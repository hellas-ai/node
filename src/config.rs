use crate::app::Mailbox;
use commonware_consensus::{elector::RoundRobin, minimmit, types::ViewDelta, Reporter as Rp};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_p2p::Blocker;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::PoolRef;
use commonware_utils::NZU16;
use hellas_types::{Activity, EPOCH, PublicKey, Scheme};
use std::{num::NonZeroUsize, time::Duration};

#[derive(Clone, Copy)]
pub struct Config {
    pub mailbox_size: usize,
    pub replay_buffer: usize,
    pub write_buffer: usize,
    pub buffer_page_size: u16,
    pub buffer_page_count: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub fetch_timeout: Duration,
    pub fetch_concurrent: usize,
}

impl Config {
    pub const fn mainnet() -> Self {
        Self {
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 64 * 1024,
            buffer_page_size: 4096,
            buffer_page_count: 1024,
            leader_timeout: Duration::from_secs(1),
            notarization_timeout: Duration::from_secs(2),
            nullify_retry: Duration::from_millis(500),
            activity_timeout: 10,
            skip_timeout: 5,
            fetch_timeout: Duration::from_secs(5),
            fetch_concurrent: 3,
        }
    }

    pub const fn test() -> Self {
        Self {
            mailbox_size: 1024,
            replay_buffer: 1024 * 1024,
            write_buffer: 64 * 1024,
            buffer_page_size: 4096,
            buffer_page_count: 1024,
            leader_timeout: Duration::from_millis(100),
            notarization_timeout: Duration::from_millis(200),
            nullify_retry: Duration::from_millis(50),
            activity_timeout: 10,
            skip_timeout: 5,
            fetch_timeout: Duration::from_millis(500),
            fetch_concurrent: 3,
        }
    }

    pub fn into_minimmit<B, R>(
        self,
        scheme: Scheme,
        blocker: B,
        automaton: Mailbox,
        relay: Mailbox,
        reporter: R,
        partition: &PublicKey,
    ) -> minimmit::Config<Scheme, RoundRobin<Sha256>, B, Digest, Mailbox, Mailbox, R, Sequential>
    where
        B: Blocker<PublicKey = PublicKey>,
        R: Rp<Activity = Activity>,
    {
        minimmit::Config {
            scheme,
            elector: RoundRobin::<Sha256>::default(),
            blocker,
            automaton,
            relay,
            reporter,
            strategy: Sequential,
            partition: partition.to_string(),
            mailbox_size: self.mailbox_size,
            epoch: EPOCH,
            replay_buffer: NonZeroUsize::new(self.replay_buffer).unwrap(),
            write_buffer: NonZeroUsize::new(self.write_buffer).unwrap(),
            buffer_pool: PoolRef::new(
                NZU16!(self.buffer_page_size),
                NonZeroUsize::new(self.buffer_page_count).unwrap(),
            ),
            leader_timeout: self.leader_timeout,
            notarization_timeout: self.notarization_timeout,
            nullify_retry: self.nullify_retry,
            activity_timeout: ViewDelta::new(self.activity_timeout),
            skip_timeout: ViewDelta::new(self.skip_timeout),
            fetch_timeout: self.fetch_timeout,
            fetch_concurrent: self.fetch_concurrent,
        }
    }
}
