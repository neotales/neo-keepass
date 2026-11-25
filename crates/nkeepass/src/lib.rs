//! Shared application boundary for CLI and future frontends.

#[allow(dead_code, reason = "shared with the CLI's mutation and save paths")]
pub(crate) mod automation;
pub mod env_file;
pub mod fs_safe;
pub mod glob;
pub mod hook;
#[allow(dead_code, reason = "shared interchange model boundary")]
pub(crate) mod interchange;
pub mod manifest;
pub mod password_generator;
pub mod private_file;
pub mod service;
pub(crate) mod sha256;
pub mod template;
pub mod trust;

pub use service::{
    AttachmentDescriptor, AttachmentMetadata, AttachmentRef, AutomationError,
    CustomFieldDescriptor, CustomFieldRef, EntryRef, ExportSnapshot, FieldMetadata, GroupRef,
    ImportOptions, ImportReport, ListCursor, ListPage, MAX_LIST_PATTERN_BYTES, ResolvedEntry,
    SearchCursor, SearchHit, SearchPage, SelectedEntry, SelectorError, ServiceError, SessionId,
    SyncOptions, SyncReport, SyncStrategy, TotpCode, TreeCursor, TreeGroup, TreePage, VaultService,
};

use neotales_keepass::KdbxReadLimits;

/// Pinned KDBX resource policy shared by all application frontends.
///
/// These values preserve the existing CLI policy while explicitly bounding
/// complete-file loading and KDF work.
pub const KDBX_LIMITS: KdbxReadLimits = KdbxReadLimits {
    max_input_bytes: 64 * 1024 * 1024,
    max_header_bytes: 1024 * 1024,
    max_aes_kdf_rounds: 100_000_000,
    max_argon2_memory_kib: 64 * 1024,
    max_argon2_time: 10,
    max_argon2_lanes: 16,
    // Alpha.3 bounds combined work as well; preserve the existing memory/time envelope.
    max_argon2_work_kib_passes: 64 * 1024 * 10,
    max_decompressed_bytes: 64 * 1024 * 1024,
    max_blocks: 1 << 20,
    max_block_bytes: 1024 * 1024,
    max_xml_chars: 64 * 1024 * 1024,
    max_xml_depth: 256,
    max_binary_bytes: 64 * 1024 * 1024,
    max_binary_records: 1 << 20,
};
