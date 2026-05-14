//! Protobuf bindings for the Hellas protocol.
//!
//! Per-package message types are generated into `OUT_DIR` by the build
//! script (`prost-build` driven by `protox`). Each `.proto` package gets a
//! Rust module here with the matching nesting (`hellas::v1`,
//! `hellas::courtesy::v1`, …) so prost's `super::super::v1::Ticket`-style
//! cross-package references resolve.
//!
//! Service/method markers, typed client traits, and the server dispatcher
//! stubs live in [`services`].

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

    #[cfg(feature = "opaque")]
    #[allow(dead_code)]
    pub mod opaque {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.opaque.v1.rs"));
        }
    }

    #[cfg(feature = "swarm")]
    #[allow(dead_code)]
    pub mod swarm {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.swarm.v1.rs"));
        }
    }

    #[cfg(feature = "symbolic")]
    #[allow(dead_code)]
    pub mod symbolic {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/hellas.symbolic.v1.rs"));
        }
    }
}

/// Re-exports of the Hellas core execution types (`hellas.v1`).
#[cfg(feature = "execute")]
pub mod execute {
    pub use crate::pb::hellas::v1::*;
}

/// Re-exports of `hellas.symbolic.v1`.
#[cfg(feature = "symbolic")]
pub mod symbolic {
    pub use crate::pb::hellas::symbolic::v1::*;
}

/// Re-exports of `hellas.opaque.v1`.
#[cfg(feature = "opaque")]
pub mod opaque {
    pub use crate::pb::hellas::opaque::v1::*;
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

/// Service / method markers, typed client traits, and server dispatcher
/// stubs. Emitted by `build.rs`. Each block is `#[cfg(feature = "<pkg>")]`-
/// gated so unused services don't compile.
#[allow(unused_imports, dead_code, clippy::all)]
pub mod services {
    include!(concat!(env!("OUT_DIR"), "/hellas_rpc_services.rs"));
}
