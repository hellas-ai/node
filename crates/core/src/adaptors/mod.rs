//! Hellas adaptors against the AXES.md pass 3 model.
//!
//! Each adaptor implements [`crate::protocol::Adaptor`] plus
//! [`crate::protocol::ProjectCall`] / [`crate::protocol::ProjectResult`]
//! to define how its typed wire request projects to a kernel-level
//! [`crate::protocol::Call`] / [`crate::protocol::CallResult`].

pub mod catgrad_text;
