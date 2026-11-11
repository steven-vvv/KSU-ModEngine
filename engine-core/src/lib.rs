//! Host-owned authorization and bounded fixture memory access.
//!
//! This preview is not an Android process attachment API. Linux process_vm_* and
//! /proc validation are separate kernel operations: a cooperative owned fixture
//! is required; mappings can otherwise change between validation and transfer.
pub mod manifest;
pub mod memory;

pub use manifest::{Authorization, Capability, Manifest, source_hash};
pub use memory::{MemorySession, TargetIdentity, parse_maps, validate_android_target};
pub use ipc_proto::MemoryRange;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("authorization denied: {0}")]
    Authorization(String),
    #[error("target rejected: {0}")]
    Target(String),
    #[error("memory request rejected: {0}")]
    Memory(String),
    #[error("short {operation}: transferred {actual} of {expected} bytes (writes may be partial)")]
    ShortTransfer { operation: &'static str, actual: usize, expected: usize },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
