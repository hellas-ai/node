//! Protobuf bindings for the Hellas protocol.
//!
//! Per-package message types are generated into `OUT_DIR` by the build
//! script (`prost-build` driven by `protox`). Each `.proto` package gets a
//! Rust module here with the matching nesting (`hellas::v1`,
//! `hellas::courtesy::v1`, …) so prost's `super::super::v1::Ticket`-style
//! cross-package references resolve.
//!
//! Service/method markers, typed client traits, and the server dispatchers
//! live in [`services`].

#[doc(hidden)]
pub mod hellas {
    #[cfg(feature = "execute")]
    #[allow(dead_code)]
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/hellas.v1.rs"));
    }

    #[cfg(feature = "courtesy")]
    #[allow(dead_code)]
    pub mod courtesy {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.courtesy.v1.rs"));
        }
    }

    #[cfg(feature = "fetch")]
    #[allow(dead_code)]
    pub mod fetch {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.fetch.v1.rs"));
        }
    }

    #[cfg(feature = "swarm")]
    #[allow(dead_code)]
    pub mod swarm {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.swarm.v1.rs"));
        }
    }

    #[cfg(feature = "evaluate")]
    #[allow(dead_code)]
    pub mod evaluate {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.evaluate.v1.rs"));
        }
    }

    #[cfg(feature = "chain")]
    #[allow(dead_code)]
    pub mod chain {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.chain.v1.rs"));
        }
    }
}

/// Re-exports of the Hellas core execution types (`hellas.v1`).
#[cfg(feature = "execute")]
pub mod execute {
    pub use crate::pb::hellas::v1::*;
}

/// Re-exports of `hellas.evaluate.v1`.
#[cfg(feature = "evaluate")]
pub mod evaluate {
    pub use crate::pb::hellas::evaluate::v1::*;
}

/// Re-exports of `hellas.fetch.v1`.
#[cfg(feature = "fetch")]
pub mod fetch {
    pub use crate::pb::hellas::fetch::v1::*;
}

/// Re-exports of `hellas.courtesy.v1`.
#[cfg(feature = "courtesy")]
pub mod courtesy {
    pub use crate::pb::hellas::courtesy::v1::*;
}

/// Re-exports of `hellas.swarm.v1`.
#[cfg(feature = "swarm")]
pub mod swarm {
    pub use crate::pb::hellas::swarm::v1::*;
}

/// Re-exports of `hellas.chain.v1`.
#[cfg(feature = "chain")]
pub mod chain {
    pub use crate::pb::hellas::chain::v1::*;
}

/// Service / method markers, typed client traits, and server dispatchers.
/// Emitted by `build.rs`. Each block is `#[cfg(feature = "<pkg>")]`-gated
/// so unused services don't compile.
#[allow(unused_imports, dead_code, clippy::all)]
pub mod services {
    include!(concat!(env!("OUT_DIR"), "/hellas_rpc_services.rs"));
}

/// Pinned wire IDs, end-to-end: proto file → descriptor walk → canonical
/// schema encoding → truncated blake3. If one of these assertions fails,
/// either the canonical encoding or the proto definition changed — both
/// rotate the ID, and deployed nodes will refuse this build's calls on
/// the affected methods. Update a pin only as a deliberate protocol break.
#[cfg(test)]
mod id_pins {
    #[allow(unused_imports)]
    use hellas_wire::{MethodMarker, ServiceMarker};

    #[cfg(feature = "execute")]
    #[test]
    fn execute_ids_are_stable() {
        use super::services::execute::{Execute, Receipt, RunTicket, Settle};
        assert_eq!(super::execute::Assurance::ProducerSigned as i32, 0);
        assert_eq!(super::execute::Assurance::AppleAppAttest as i32, 1);
        assert_eq!(<Execute as ServiceMarker>::SERVICE_ID, 0xa82c0f94);
        assert_eq!(<RunTicket as MethodMarker>::METHOD_ID, 0xd2d6478a);
        assert_eq!(<Receipt as MethodMarker>::METHOD_ID, 0xbbb5f3e6);
        assert_eq!(<Settle as MethodMarker>::METHOD_ID, 0xc678dd9f);
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn evaluate_ids_are_stable() {
        use super::services::evaluate::{CreateTicket, Evaluate};
        assert_eq!(<Evaluate as ServiceMarker>::SERVICE_ID, 0xbe10d224);
        assert_eq!(<CreateTicket as MethodMarker>::METHOD_ID, 0xee83d084);
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn fetch_ids_are_stable() {
        use super::services::fetch::{CreateTicket, Fetch, Open};
        assert_eq!(<Fetch as ServiceMarker>::SERVICE_ID, 0x8472b96a);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0x4c386ff8);
        assert_eq!(<CreateTicket as MethodMarker>::METHOD_ID, 0xb232c2a7);
    }

    #[cfg(feature = "courtesy")]
    #[test]
    fn courtesy_ids_are_stable() {
        use super::services::courtesy::{
            Courtesy, Open, QuoteChatPrompt, QuotePreparedText, QuotePrompt,
        };
        assert_eq!(<Courtesy as ServiceMarker>::SERVICE_ID, 0x360d5775);
        assert_eq!(<Open as MethodMarker>::METHOD_ID, 0xea3c6fa1);
        assert_eq!(<QuotePreparedText as MethodMarker>::METHOD_ID, 0x991a7eb2);
        assert_eq!(<QuotePrompt as MethodMarker>::METHOD_ID, 0xad5deb50);
        assert_eq!(<QuoteChatPrompt as MethodMarker>::METHOD_ID, 0x6d37221c);
    }

    #[cfg(feature = "chain")]
    #[test]
    fn chain_ids_are_stable() {
        use super::services::light_client::{GetStateRoot, LightClient};
        assert_eq!(<LightClient as ServiceMarker>::SERVICE_ID, 0xf750f32b);
        assert_eq!(<GetStateRoot as MethodMarker>::METHOD_ID, 0x4a19b4e6);
    }
}
