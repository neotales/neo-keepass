//! Application-service boundary for CLI reads and the initial field-edit slice.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;

use crate::glob::Glob;
use crate::{automation, interchange};
use neotales_keepass::{
    Entry, Field, Group, KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxUuid, KdbxWriteOptions,
    KeePassDatabase, KeePassXcOtp, OtpKind, OtpSecret, ProtectedValue, SecretBytes, Totp,
    TotpParameters,
};

const MAX_QUERY_BYTES: usize = 4096;
/// Maximum UTF-8 byte length accepted for a listing path glob.
pub const MAX_LIST_PATTERN_BYTES: usize = 1024;
const MAX_RESULTS: usize = 1_000;
const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_HIT_BYTES: usize = 16 * 1024;
const MAX_TREE_ROW_BYTES: usize = 16 * 1024;
const MAX_TREE_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TREE_PAGE_WORK: usize = 8 * 1024 * 1024;
const MAX_TREE_LABEL_BYTES: usize = 4 * 1024;
const MAX_METADATA_ITEMS: usize = 256;
const MAX_LOCATOR_DEPTH: usize = 256;
// Count the root group. Reserve eight XML levels for KeePassFile/Root,
// Entry, one History/Entry generation, and CustomData/Item/Value.
// Nested history needs the model-depth check; this reserve is not enough for it.
const MAX_CREATE_GROUPS: usize = {
    let xml_groups = crate::KDBX_LIMITS.max_xml_depth.saturating_sub(8);
    if xml_groups < MAX_LOCATOR_DEPTH {
        xml_groups
    } else {
        MAX_LOCATOR_DEPTH
    }
};
const MAX_PAGE_WORK: usize = 10_000;
const MAX_SEARCH_WORK: usize = 1_000_000;
const MAX_ACTIVE_CURSORS: usize = 8;
const MAX_PAGE_TEXT_WORK: usize = 8 * 1024 * 1024;
const MAX_SEARCH_TEXT_WORK: usize = 512 * 1024 * 1024;
const MAX_COMPLETION_NODES: usize = 10_000;
const MAX_COMPLETION_FIELD_VISITS: usize = 10_000;
// Conservative total text-work budget for completion; repeated queue/output
// path copies are intentionally charged again rather than estimated as live heap.
const MAX_COMPLETION_BYTES: usize = 2 * 1024 * 1024;
const MAX_COMPLETION_PATH_BYTES: usize = 16 * 1024;
const MAX_PAGE_GLOB_WORK: usize = 8 * 1024 * 1024;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Fixed, non-sensitive service failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    /// No unlocked vault is available.
    Locked,
    /// A request refers to a missing object or session.
    NotFound,
    /// A vault contains identifiers that cannot be selected uniquely.
    Ambiguous,
    /// A selector names the root group rather than an entry.
    RootGroup,
    /// A destructive group operation attempted to target the root group.
    RootGroupMutation,
    /// A reference belongs to an earlier session generation.
    Stale,
    /// Input does not satisfy a bounded service contract.
    InvalidInput,
    /// The model would exceed the KDBX XML depth policy.
    XmlDepth,
    /// The vault could not be opened.
    Io,
    /// The vault could not be unlocked or decoded.
    Unlock,
    /// A search exceeded a fixed node, text-work, or cursor-state ceiling.
    ResourceLimit,
    /// A listing exceeded a fixed node, matcher, text-work, or cursor-state ceiling.
    ListingIncomplete,
    /// A field selector is ambiguous or a requested standard field is unsupported.
    FieldConflict,
    /// Duplicate object identifiers make model selection unsafe.
    DuplicateIds,
    /// Duplicate field names make model selection unsafe.
    DuplicateFields,
    /// A selected field name occurs more than once.
    AmbiguousField,
    /// The selected entry does not contain a valid TOTP URI.
    InvalidOtp,
    /// Stateful HOTP generation requires an atomic counter transaction.
    HotpUnsupported,
    /// The field-name input is invalid.
    InvalidFieldName,
    /// A requested generated-password size is outside the accepted range.
    InvalidSize,
    /// Secure random password generation failed.
    RandomGeneration,
    /// A selected attachment name already exists exactly once.
    AttachmentExists,
    /// A sibling group with the requested name already exists.
    GroupExists,
    /// Attachment references cannot be safely pruned/remapped.
    InvalidAttachmentReference,
    /// The model could not be safely saved.
    Save,
    /// Staging or installation failed during the corresponding save phase.
    SaveStage,
    SaveSync,
    SaveReplace,
    SaveDurability,
    /// The parent directory for a new vault could not be created.
    CreateDirectory,
    /// A private staging file for a new vault could not be created.
    CreateStage,
    /// The new vault staging file could not be restricted to its owner.
    CreatePermissions,
    /// KDBX serialization or staging-file sync failed before installation.
    CreateWrite,
    /// The completed staging file could not be synced before installation.
    CreateSync,
    /// The target already exists or cannot be installed without replacement.
    CreateExists,
    /// The vault is installed but directory durability could not be confirmed.
    CreateDurability,
    /// The current platform cannot establish owner-only permissions safely.
    SecureFilePermissionsUnsupported,
}

/// Fixed, non-sensitive failure from a whole-vault interchange operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationError(String);

impl AutomationError {
    fn fixed(message: &'static str) -> Self {
        Self(message.to_owned())
    }

    fn owned(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Fixed diagnostic text that does not contain vault-controlled content.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// Whole-vault import authorization and execution policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportOptions {
    /// Explicitly authorize replacing a non-empty vault.
    pub replace: bool,
    /// Validate and report without changing the live service session.
    pub dry_run: bool,
}

/// Strategy used to resolve matching objects during whole-vault sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStrategy {
    /// Keep the object with the newer modification timestamp (source wins ties).
    Newest,
    /// Prefer the source object.
    Source,
    /// Keep the target object.
    Target,
}

impl From<SyncStrategy> for automation::SyncStrategy {
    fn from(strategy: SyncStrategy) -> Self {
        match strategy {
            SyncStrategy::Newest => Self::Newest,
            SyncStrategy::Source => Self::Source,
            SyncStrategy::Target => Self::Target,
        }
    }
}

impl SyncStrategy {
    /// Parse the CLI strategy spelling.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic when the spelling is not `newest`, `source`,
    /// or `target`.
    pub fn parse(value: &str) -> Result<Self, AutomationError> {
        match value {
            "newest" => Ok(Self::Newest),
            "source" => Ok(Self::Source),
            "target" => Ok(Self::Target),
            _ => Err(AutomationError::fixed("invalid sync strategy")),
        }
    }
}

/// Whole-vault sync execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncOptions {
    /// Conflict resolution strategy.
    pub strategy: SyncStrategy,
    /// Validate and report without changing the live service session.
    pub dry_run: bool,
}

/// Whole-vault import counts and password-directive outcomes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    pub replaced: bool,
    pub dry_run: bool,
    pub groups: usize,
    pub entries: usize,
    pub history_entries: usize,
    pub fields: usize,
    pub attachments: usize,
    pub protected_values: usize,
    pub binary_records: usize,
    pub binary_bytes: u64,
    pub passwords_generated: usize,
    pub passwords_kept: usize,
    pub passwords_pending: usize,
}

/// Whole-vault sync counts and password-directive outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncReport {
    pub dry_run: bool,
    pub strategy: SyncStrategy,
    pub groups_added: usize,
    pub groups_updated: usize,
    pub entries_added: usize,
    pub entries_updated: usize,
    pub passwords_generated: usize,
    pub passwords_kept: usize,
    pub passwords_pending: usize,
}

/// Lossless, bounded interchange export bytes. The sensitive buffer is zeroized
/// when dropped and is exposed only for explicit output by the caller.
pub struct ExportSnapshot(Zeroizing<Vec<u8>>);

impl ExportSnapshot {
    /// Serialized bytes for the caller's explicit output destination.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Selector failure details for a CLI-style entry lookup.
///
/// Ambiguous/missing path locations refer only to zero-based segments from the
/// caller's selector. No names or other model data cross the service boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorError {
    /// The selector is outside the slash-separated entry-path grammar.
    MalformedPath,
    /// The selector names the root group rather than an entry.
    RootGroup,
    /// More than one group matches this caller-supplied segment.
    AmbiguousGroup { segment_index: usize },
    /// More than one entry matches the caller-supplied final segment.
    AmbiguousEntry { segment_index: usize },
    /// No group matches this caller-supplied intermediate segment.
    MissingGroup {
        segment_index: usize,
        walked_start_index: usize,
    },
    /// The path is valid but no entry matches its final segment.
    NotFound,
    /// The service session is unavailable or stale.
    Service(ServiceError),
}

impl ServiceError {
    /// Fixed diagnostic text with no vault-controlled content.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Locked => "vault is locked",
            Self::NotFound => "not found",
            Self::Ambiguous => "ambiguous vault identifiers",
            Self::RootGroup => "that path names the root group, not an entry",
            Self::RootGroupMutation => "the root group cannot be removed",
            Self::Stale => "stale vault reference",
            Self::InvalidInput => "invalid service input",
            Self::XmlDepth => {
                "vault XML depth exceeds the limit; reduce group depth or nested entry history"
            }
            Self::Io => "cannot open vault",
            Self::Unlock => "cannot unlock vault",
            Self::ResourceLimit => "search incomplete: resource limit reached",
            Self::ListingIncomplete => "listing incomplete: resource limit reached",
            Self::FieldConflict => "field cannot be changed",
            Self::DuplicateIds => "vault contains duplicate object UUIDs",
            Self::DuplicateFields => "entry contains duplicate fields",
            Self::AmbiguousField => "ambiguous field name",
            Self::InvalidOtp => "invalid OTP field",
            Self::HotpUnsupported => "HOTP requires atomic counter persistence",
            Self::InvalidFieldName => "invalid field name",
            Self::InvalidSize => "invalid size",
            Self::RandomGeneration => "random generation failed",
            Self::AttachmentExists => "attachment already exists",
            Self::GroupExists => "group already exists",
            Self::InvalidAttachmentReference => "invalid attachment reference",
            Self::Save => "cannot save vault",
            Self::SaveStage | Self::CreateStage => "cannot create vault temporary file",
            Self::SaveSync | Self::CreateSync => "cannot sync vault",
            Self::SaveReplace => "cannot replace vault",
            Self::SaveDurability => "vault installed but directory durability is unconfirmed",
            Self::CreateDirectory => "cannot create vault directory",
            Self::CreatePermissions => "cannot set vault permissions",
            Self::CreateWrite => "cannot create vault",
            Self::CreateExists => "vault already exists or cannot be created",
            Self::CreateDurability => "vault created but directory durability is unconfirmed",
            Self::SecureFilePermissionsUnsupported => {
                "secure owner-only file writes are unsupported on this platform"
            }
        }
    }
}

fn permission_failure(cause: &'static str, fallback: ServiceError) -> ServiceError {
    if cause == "owner-only Windows ACL replacement is unsupported" {
        ServiceError::SecureFilePermissionsUnsupported
    } else {
        fallback
    }
}

/// Opaque identifier for one opened service session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(u64);

/// Opaque continuation for the next bounded page of a search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchCursor {
    session: SessionId,
    generation: u64,
    token: u64,
}

/// Opaque continuation for the next bounded page of a listing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListCursor {
    session: SessionId,
    generation: u64,
    token: u64,
}

/// Opaque handle for one group in the owning live vault session.
#[derive(Clone, Eq, PartialEq)]
pub struct GroupRef {
    session: SessionId,
    generation: u64,
    id: KdbxUuid,
    locator: Vec<usize>,
}

/// Single-use continuation for one direct-child group listing.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TreeCursor {
    session: SessionId,
    generation: u64,
    token: u64,
}

/// Safe direct child group projection and its opaque handle.
pub struct TreeGroup {
    label: String,
    reference: GroupRef,
}

impl TreeGroup {
    /// Safe group label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Session-bound opaque group handle.
    #[must_use]
    pub fn reference(&self) -> GroupRef {
        self.reference.clone()
    }
}

/// One bounded page of direct child groups and entry metadata.
///
/// Pages visit at most 128 direct rows, reserve only one page's projection
/// capacity, retain at most 2 MiB of measured metadata, and scan at most 8 MiB
/// of label/metadata text. Group depth is capped at 256 and ancestor context at
/// 16 KiB. Oversized or unsafe rows are withheld; work/path limits fail closed.
pub struct TreePage {
    /// Direct child groups (never descendants).
    pub groups: Vec<TreeGroup>,
    /// Direct child entries, in vault order.
    pub entries: Vec<SearchHit>,
    /// Present when the direct-child page has a continuation.
    pub next_cursor: Option<TreeCursor>,
    /// Unsafe rows withheld from the projection.
    pub withheld: usize,
}

struct TreeState {
    locator: Vec<usize>,
    group_id: KdbxUuid,
    offset: usize,
}

/// Opaque, session- and generation-scoped entry reference.
#[derive(Clone, Eq, PartialEq)]
pub struct EntryRef {
    session: SessionId,
    generation: u64,
    id: KdbxUuid,
    locator: Vec<usize>,
}

/// A path-resolved entry handle and its canonical root-prefixed path.
pub struct ResolvedEntry {
    reference: EntryRef,
    path: String,
}

/// One generated TOTP and the period used to produce it.
///
/// The code remains zeroizing and the OTP URI/seed never leaves the service.
pub struct TotpCode {
    code: Zeroizing<String>,
    period: u64,
}

impl TotpCode {
    /// Code generated for the caller-pinned timestamp.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Period used to generate this code, in seconds.
    #[must_use]
    pub const fn period(&self) -> u64 {
        self.period
    }
}

/// Owned, typed update data for one exact field in a setx batch.
/// Secret text remains zeroizing until the service transfers ownership to the
/// live `KeePass` model.
pub struct FieldUpdate {
    pub key: String,
    pub value: Zeroizing<String>,
    pub protected: Option<bool>,
    pub protect_in_memory: Option<bool>,
}

impl ResolvedEntry {
    /// Opaque handle for selecting this entry in the owning live session.
    #[must_use]
    pub fn reference(&self) -> EntryRef {
        self.reference.clone()
    }

    /// Canonical path projection using the actual vault group and entry names.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Exact handle to one custom field on a selected entry.
///
/// Handles are bound to the entry session and generation and retain the exact
/// field index/name pair so a changed or forged descriptor cannot select a
/// different field.
#[derive(Clone, Eq, PartialEq)]
pub struct CustomFieldRef {
    entry: EntryRef,
    index: usize,
    name: String,
}

/// Exact, session-bound handle for one attachment. The binary reference stays
/// private and is revalidated on reveal.
#[derive(Clone, Eq, PartialEq)]
pub struct AttachmentRef {
    entry: EntryRef,
    index: usize,
    name: String,
    binary_reference: usize,
}

/// Bounded allowlisted attachment metadata with an opaque explicit-read handle.
pub struct AttachmentDescriptor {
    name: String,
    size: usize,
    protected: bool,
    reference: AttachmentRef,
}

impl AttachmentDescriptor {
    /// Exact attachment name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Attachment byte length.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }
    /// Whether the binary is protected by the inner stream.
    #[must_use]
    pub const fn protected(&self) -> bool {
        self.protected
    }
    /// Opaque handle for explicitly revealing these bytes.
    #[must_use]
    pub fn reference(&self) -> AttachmentRef {
        self.reference.clone()
    }
}

/// Safe descriptor for a custom field; never contains its value.
pub struct CustomFieldDescriptor {
    name: String,
    protected: bool,
    protect_in_memory: bool,
    reference: CustomFieldRef,
}

impl CustomFieldDescriptor {
    /// Exact, case-sensitive field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether `KeePass` marks this field as protected on disk.
    #[must_use]
    pub const fn protected(&self) -> bool {
        self.protected
    }
    /// Whether the field is protected while the database is in memory.
    #[must_use]
    pub const fn protect_in_memory(&self) -> bool {
        self.protect_in_memory
    }
    /// Opaque handle for an explicit read of this field's value.
    #[must_use]
    pub fn reference(&self) -> CustomFieldRef {
        self.reference.clone()
    }
}

/// Allowlisted metadata for any field, including the standard fields.
pub struct FieldMetadata {
    name: String,
    protected: bool,
    protect_in_memory: bool,
}

impl FieldMetadata {
    /// Exact field name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether the field is protected on disk.
    #[must_use]
    pub const fn protected(&self) -> bool {
        self.protected
    }
    /// Whether the field is protected while the database is in memory.
    #[must_use]
    pub const fn protect_in_memory(&self) -> bool {
        self.protect_in_memory
    }
}

/// Allowlisted selected-entry view. No field values, protected values, OTP
/// seed/URI, history contents, or attachment bytes are included.
pub struct SelectedEntry {
    title: String,
    tags: Vec<String>,
    attachments: Vec<AttachmentMetadata>,
    fields: Vec<FieldMetadata>,
    custom_fields: Vec<CustomFieldDescriptor>,
    has_otp: bool,
    auto_type_enabled: bool,
    auto_type_associations: usize,
}

/// Allowlisted attachment name and byte length (never attachment data).
pub struct AttachmentMetadata {
    name: String,
    size: usize,
}

impl SelectedEntry {
    /// Entry title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    /// Entry tags.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    /// Attachment names and sizes.
    #[must_use]
    pub fn attachments(&self) -> &[AttachmentMetadata] {
        &self.attachments
    }
    /// Metadata descriptors for every field, including standard fields.
    #[must_use]
    pub fn fields(&self) -> &[FieldMetadata] {
        &self.fields
    }
    /// Exact custom-field descriptors, without values.
    #[must_use]
    pub fn custom_fields(&self) -> &[CustomFieldDescriptor] {
        &self.custom_fields
    }
    /// Whether the entry has a valid `KeePassXC` OTP configuration.
    #[must_use]
    pub const fn has_otp(&self) -> bool {
        self.has_otp
    }
    /// Whether entry auto-type is enabled.
    #[must_use]
    pub const fn auto_type_enabled(&self) -> bool {
        self.auto_type_enabled
    }
    /// Number of auto-type associations.
    #[must_use]
    pub const fn auto_type_associations(&self) -> usize {
        self.auto_type_associations
    }
}

impl AttachmentMetadata {
    /// Attachment filename.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Attachment byte length.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }
}

/// Allowlisted search metadata. No model object or secret value crosses the boundary.
pub struct SearchHit {
    reference: EntryRef,
    path: String,
    title: String,
    tags: Vec<String>,
    field_names: Vec<String>,
}

impl SearchHit {
    /// Opaque handle usable only in the owning live session.
    #[must_use]
    pub fn reference(&self) -> EntryRef {
        self.reference.clone()
    }

    /// Vault path projection.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Entry title projection.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Entry tag projection.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Custom-field name projection, never field values.
    #[must_use]
    pub fn field_names(&self) -> &[String] {
        &self.field_names
    }
}

/// Bounded search page and count of matching records withheld from projection.
///
/// A page contains at most 1,000 emitted safe hits and 2 MiB of measured,
/// service-retained projection data, including reserved hit-vector capacity and
/// item/vector overhead (serialized output bytes are not included).
/// Withheld matches do not consume visible slots. Each page visits at most
/// 10,000 groups/records and accounts at most 8 MiB of weighted text work,
/// including unmatched records; `next_cursor` is present whenever another
/// scan page is available.
pub struct SearchPage {
    /// Renderable allowlisted metadata hits, in vault order.
    pub hits: Vec<SearchHit>,
    /// Matching records withheld for unsafe labels or projection size limits.
    pub withheld: usize,
    /// Present when scanning stopped at a page bound. Pass this to
    /// [`VaultService::search_page`] to retrieve the next page.
    pub next_cursor: Option<SearchCursor>,
}

/// Bounded listing page and count of matching records withheld from projection.
pub struct ListPage {
    /// Renderable allowlisted metadata hits, in vault order.
    pub hits: Vec<SearchHit>,
    /// Entries matching the requested path glob that could not be projected safely.
    pub withheld: usize,
    /// Present when another bounded scan page is available.
    pub next_cursor: Option<ListCursor>,
}

/// Bounded completion metadata. Contains only group/entry paths and field names;
/// no field values, protected values, or attachments are projected.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CompletionMetadata {
    /// Root-prefixed group paths.
    pub groups: Vec<String>,
    /// Root-prefixed entry paths.
    pub entries: Vec<String>,
    /// Custom field names from entries.
    pub keys: Vec<String>,
}

struct LiveSession {
    id: SessionId,
    generation: u64,
    database: KeePassDatabase,
}

/// Application service owning the vault session and KDBX loading for this slice.
#[derive(Default)]
pub struct VaultService {
    generation: u64,
    session: Option<LiveSession>,
    searches: HashMap<u64, SearchState>,
    listings: HashMap<u64, ListState>,
    next_search_token: u64,
    trees: HashMap<u64, TreeState>,
}

impl VaultService {
    /// Creates and installs a new empty vault, optionally seeding one entry with
    /// a generated password. Installation never replaces an existing target.
    ///
    /// A durability error is reported only after installation has succeeded;
    /// callers must treat that result as partial success and must not retry by
    /// replacing the target.
    /// On Unix, success includes syncing the containing directory after
    /// installation. On non-Unix platforms, the file is synced before the
    /// atomic no-clobber install, but directory durability cannot be confirmed;
    /// success is therefore best-effort with respect to a sudden system crash.
    ///
    /// # Errors
    ///
    /// Returns phase-specific creation errors, [`ServiceError::InvalidSize`]
    /// for an unsupported generated-password size, or
    /// [`ServiceError::RandomGeneration`] if secure randomness fails.
    pub fn create(
        &self,
        path: &Path,
        credentials: &mut KdbxCredentials,
        write_options: KdbxWriteOptions,
        generated_password_size: Option<usize>,
    ) -> Result<(), ServiceError> {
        if generated_password_size.is_some_and(|size| size == 0 || size > 4096) {
            return Err(ServiceError::InvalidSize);
        }
        let valid_write_options = match write_options.kdf {
            neotales_keepass::KdbxKdf::Aes => {
                write_options.aes_kdf_rounds > 0
                    && write_options.aes_kdf_rounds <= crate::KDBX_LIMITS.max_aes_kdf_rounds
            }
            neotales_keepass::KdbxKdf::Argon2d | neotales_keepass::KdbxKdf::Argon2id => {
                write_options.argon2_time > 0
                    && write_options.argon2_time <= crate::KDBX_LIMITS.max_argon2_time
                    && write_options.argon2_memory_kib > 0
                    && write_options.argon2_memory_kib <= crate::KDBX_LIMITS.max_argon2_memory_kib
                    && write_options.argon2_lanes > 0
                    && write_options.argon2_lanes <= crate::KDBX_LIMITS.max_argon2_lanes
            }
        };
        if !valid_write_options {
            return Err(ServiceError::InvalidInput);
        }

        let mut database = KeePassDatabase::default();
        if let Some(size) = generated_password_size {
            let mut password = Zeroizing::new(generate_password(size)?);
            let mut entry = Entry::new("generated");
            entry.password = ProtectedValue::from_text(std::mem::take(&mut *password));
            database.add_entry(entry);
        }
        validate_save_model(&database)?;
        prepare_standard_fields_for_save(&mut database);

        install_new_vault(path, |staged| {
            KdbxFile::save(
                &database,
                staged,
                credentials,
                write_options,
                &crate::KDBX_LIMITS,
            )
            .map_err(|_| ServiceError::CreateWrite)
        })
    }

    /// Opens and loads a vault using the caller's pinned reader policy.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Io`] when the file cannot be opened, or
    /// [`ServiceError::Unlock`] when loading or unlocking it fails.
    pub fn open(
        &mut self,
        path: &Path,
        credentials: &mut KdbxCredentials,
        limits: &KdbxReadLimits,
    ) -> Result<SessionId, ServiceError> {
        let file = File::open(path).map_err(|_| ServiceError::Io)?;
        let database =
            KdbxFile::load(file, credentials, limits).map_err(|_| ServiceError::Unlock)?;
        self.generation = self.generation.wrapping_add(1).max(1);
        let id = SessionId(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed).max(1));
        self.session = Some(LiveSession {
            id,
            generation: self.generation,
            database,
        });
        self.searches.clear();
        self.listings.clear();
        self.trees.clear();
        Ok(id)
    }

    /// Projects bounded, non-secret metadata for dynamic shell completion.
    ///
    /// The traversal stops with [`ServiceError::ResourceLimit`] rather than
    /// returning a partial view when the tree, path length, or conservative
    /// weighted text-work budget exceeds its fixed limit. Path text is charged
    /// at queueing and projection time, so this is a work budget, not a claim
    /// about the exact bytes simultaneously retained.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Locked`] when no vault is open, or
    /// [`ServiceError::ResourceLimit`] when any fixed traversal or projection
    /// bound is exceeded.
    pub fn completion_metadata(&self) -> Result<CompletionMetadata, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        let mut result = CompletionMetadata::default();
        let mut pending = vec![(&live.database.root, String::new(), 0_usize)];
        let mut visited = 1_usize;
        let mut field_visits = 0_usize;
        let mut key_items = 0_usize;
        // This is deliberately a conservative weighted text-work counter, not
        // an exact live-heap measurement. Queue copies and projected strings
        // are charged when encountered; a path may therefore be charged more
        // than once as it moves through the traversal.
        let mut text_work = 0_usize;
        while let Some((group, parent, depth)) = pending.pop() {
            if depth > MAX_LOCATOR_DEPTH {
                return Err(ServiceError::ResourceLimit);
            }
            if group.name.is_empty() || group.name.contains('/') || !safe_metadata(&group.name) {
                continue;
            }
            let path_bytes = parent
                .len()
                .checked_add(usize::from(!parent.is_empty()))
                .and_then(|bytes| bytes.checked_add(group.name.len()))
                .ok_or(ServiceError::ResourceLimit)?;
            account_completion_text(&mut text_work, path_bytes)?;
            let path = if parent.is_empty() {
                group.name.clone()
            } else {
                format!("{parent}/{}", group.name)
            };
            result.groups.push(path.clone());
            for entry in &group.entries {
                visited = visited.checked_add(1).ok_or(ServiceError::ResourceLimit)?;
                if visited > MAX_COMPLETION_NODES {
                    return Err(ServiceError::ResourceLimit);
                }
                if entry.title.is_empty()
                    || entry.title.contains('/')
                    || !safe_metadata(&entry.title)
                {
                    continue;
                }
                let entry_path_bytes = path
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(entry.title.len()))
                    .ok_or(ServiceError::ResourceLimit)?;
                account_completion_text(&mut text_work, entry_path_bytes)?;
                let entry_path = format!("{path}/{}", entry.title);
                result.entries.push(entry_path);
                for field in &entry.fields {
                    field_visits = field_visits
                        .checked_add(1)
                        .ok_or(ServiceError::ResourceLimit)?;
                    if field_visits > MAX_COMPLETION_FIELD_VISITS {
                        return Err(ServiceError::ResourceLimit);
                    }
                    // KeePass's standard field names are not custom-key
                    // candidates. Never inspect or clone the field value.
                    if matches!(
                        field.key.as_str(),
                        "Title" | "UserName" | "Password" | "URL" | "Notes"
                    ) {
                        continue;
                    }
                    key_items = key_items
                        .checked_add(1)
                        .ok_or(ServiceError::ResourceLimit)?;
                    if key_items > MAX_COMPLETION_FIELD_VISITS {
                        return Err(ServiceError::ResourceLimit);
                    }
                    account_completion_text(&mut text_work, field.key.len())?;
                    result.keys.push(field.key.clone());
                }
            }
            for child in &group.groups {
                visited = visited.checked_add(1).ok_or(ServiceError::ResourceLimit)?;
                if visited > MAX_COMPLETION_NODES {
                    return Err(ServiceError::ResourceLimit);
                }
                if child.name.is_empty() || child.name.contains('/') || !safe_metadata(&child.name)
                {
                    continue;
                }
                let child_path_bytes = path
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(child.name.len()))
                    .ok_or(ServiceError::ResourceLimit)?;
                account_completion_text(&mut text_work, child_path_bytes)?;
                pending.push((child, path.clone(), depth + 1));
            }
        }
        Ok(result)
    }

    /// Drops the loaded vault and invalidates all handles from its generation.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Locked`] when no session is open, or
    /// [`ServiceError::Stale`] when the supplied session is not current.
    pub fn lock(&mut self, session: SessionId) -> Result<(), ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        self.session = None;
        self.searches.clear();
        self.listings.clear();
        self.trees.clear();
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }

    /// Generates a TOTP for an entry selected by an issued reference.
    /// The URI and seed remain inside the service boundary; only the
    /// zeroizing code is returned. The caller supplies one pinned timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Locked`] or [`ServiceError::Stale`] for an
    /// invalid session/reference, duplicate-model errors when the vault is
    /// malformed, [`ServiceError::AmbiguousField`] for duplicate `otp` fields,
    /// [`ServiceError::InvalidOtp`] for an invalid URI/secret, or
    /// [`ServiceError::HotpUnsupported`] for stateful HOTP.
    pub fn otp_code(
        &self,
        reference: &EntryRef,
        timestamp: u64,
    ) -> Result<Zeroizing<String>, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        if entry
            .fields
            .iter()
            .filter(|field| field.key == "otp")
            .count()
            > 1
        {
            return Err(ServiceError::AmbiguousField);
        }
        validate_unique_field_names(&live.database)?;
        let uri = KeePassXcOtp::read(entry).map_err(|_| ServiceError::InvalidOtp)?;
        let secret = OtpSecret::from_base32(&uri.secret).map_err(|_| ServiceError::InvalidOtp)?;
        match uri.kind {
            OtpKind::Hotp => Err(ServiceError::HotpUnsupported),
            OtpKind::Totp => Ok(Zeroizing::new(Totp::generate(
                &TotpParameters {
                    secret: secret.expose(),
                    algorithm: uri.algorithm,
                    digits: uri.digits,
                    period: uri.period.unwrap_or(30),
                },
                timestamp,
            ))),
        }
    }

    /// Generates a TOTP and returns its period for an expiry warning.
    ///
    /// This CLI-facing result keeps URI and seed parsing inside the service and
    /// returns only the zeroizing code plus non-sensitive timing metadata.
    /// Unlike [`Self::otp_code`], this applies the same narrow OTP-field
    /// validation as the CLI binding path.
    ///
    /// # Errors
    ///
    /// Returns session, ambiguous-field, invalid-OTP, and HOTP errors. An
    /// unrelated duplicate object ID or field elsewhere in the vault is not
    /// inspected by this CLI binding operation.
    pub fn totp_code_with_period(
        &self,
        reference: &EntryRef,
        timestamp: u64,
    ) -> Result<TotpCode, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        if entry
            .fields
            .iter()
            .filter(|field| field.key == "otp")
            .count()
            > 1
        {
            return Err(ServiceError::AmbiguousField);
        }
        let uri = KeePassXcOtp::read(entry).map_err(|_| ServiceError::InvalidOtp)?;
        let secret = OtpSecret::from_base32(&uri.secret).map_err(|_| ServiceError::InvalidOtp)?;
        match uri.kind {
            OtpKind::Hotp => Err(ServiceError::HotpUnsupported),
            OtpKind::Totp => {
                let period = uri.period.unwrap_or(30);
                Ok(TotpCode {
                    code: Zeroizing::new(Totp::generate(
                        &TotpParameters {
                            secret: secret.expose(),
                            algorithm: uri.algorithm,
                            digits: uri.digits,
                            period,
                        },
                        timestamp,
                    )),
                    period,
                })
            }
        }
    }

    /// Changes one selected field without exposing a `KeePass` model reference.
    /// The full tree is checked for duplicate UUIDs and field names before any
    /// mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::DuplicateIds`] or [`ServiceError::DuplicateFields`] when
    /// the vault is malformed, and [`ServiceError::FieldConflict`] for `Title`.
    pub fn set_field(
        &mut self,
        reference: &EntryRef,
        name: &str,
        value: &str,
    ) -> Result<(), ServiceError> {
        self.mutate_field(reference, name, value, false)
    }

    /// Replaces the selected entry's password with a freshly generated value,
    /// using the exact bounded alphabet and rejection policy used by `ensure`.
    /// The generated value never leaves the service.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidSize`] outside `1..=4096`,
    /// [`ServiceError::RandomGeneration`] if secure randomness fails, or the
    /// same stale/model-validation errors as [`Self::set_field`].
    pub fn generate_entry_password(
        &mut self,
        reference: &EntryRef,
        size: usize,
    ) -> Result<(), ServiceError> {
        if size == 0 || size > 4096 {
            return Err(ServiceError::InvalidSize);
        }
        let password = Zeroizing::new(generate_password(size)?);
        self.mutate_field(reference, "Password", &password, false)?;
        Ok(())
    }

    /// Changes one custom field, rejecting standard-field selectors.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`VaultService::set_field`], plus
    /// [`ServiceError::FieldConflict`] for a standard field name.
    pub fn set_custom_field(
        &mut self,
        reference: &EntryRef,
        name: &str,
        value: &str,
    ) -> Result<(), ServiceError> {
        self.mutate_field(reference, name, value, true)
    }

    /// Applies one bounded setx batch after validating every field and the
    /// selected model before the first mutation. Keys are exact and
    /// case-sensitive; standard field projections are updated consistently.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for an empty batch,
    /// [`ServiceError::InvalidFieldName`] for invalid or repeated update keys,
    /// [`ServiceError::FieldConflict`] when a batch attempts to change `Title`,
    /// [`ServiceError::Stale`] for an expired handle, and duplicate-model
    /// errors when any entry or history snapshot is malformed.
    pub fn set_fields(
        &mut self,
        reference: &EntryRef,
        updates: Vec<FieldUpdate>,
    ) -> Result<usize, ServiceError> {
        self.apply_field_updates(reference, updates, false)
    }

    /// Applies a field batch and creates missing custom fields, matching the
    /// CLI `set` behavior. All update keys and the target model are validated
    /// before mutation; an empty batch is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for an empty batch,
    /// [`ServiceError::InvalidFieldName`] for invalid or repeated update keys,
    /// [`ServiceError::FieldConflict`] when a batch attempts to change `Title`,
    /// [`ServiceError::Stale`] for an expired handle, and duplicate-model
    /// errors when any entry or history snapshot is malformed.
    pub fn set_fields_creating_custom(
        &mut self,
        reference: &EntryRef,
        updates: Vec<FieldUpdate>,
    ) -> Result<usize, ServiceError> {
        self.apply_field_updates(reference, updates, true)
    }

    fn apply_field_updates(
        &mut self,
        reference: &EntryRef,
        updates: Vec<FieldUpdate>,
        create_missing_custom: bool,
    ) -> Result<usize, ServiceError> {
        if updates.is_empty() {
            return Err(ServiceError::InvalidInput);
        }
        let mut names = BTreeSet::new();
        for update in &updates {
            if update.key.is_empty()
                || update.key.chars().any(char::is_control)
                || !names.insert(update.key.as_str())
            {
                return Err(ServiceError::InvalidFieldName);
            }
        }
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        resolve_locator(&live.database, &reference.locator, reference.id)?;
        if updates.iter().any(|update| update.key == "Title") {
            return Err(ServiceError::FieldConflict);
        }
        let count = updates.len();
        normalize_standard_projections(&mut live.database);
        let entry = resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?;
        for mut update in updates {
            let key = update.key;
            let standard = matches!(key.as_str(), "Password" | "UserName" | "URL" | "Notes");
            let present = entry.fields.iter().any(|field| field.key == key);
            let protected = update
                .protected
                .unwrap_or(!matches!(key.as_str(), "UserName" | "URL" | "Notes"));
            let protect_in_memory = update.protect_in_memory.unwrap_or(protected);
            match key.as_str() {
                "Password" => {
                    let mut projection = Zeroizing::new(update.value.as_str().to_owned());
                    entry.password = ProtectedValue::from_text(std::mem::take(&mut *projection));
                }
                "UserName" => update.value.as_str().clone_into(&mut entry.username),
                "URL" => update.value.as_str().clone_into(&mut entry.url),
                "Notes" => update.value.as_str().clone_into(&mut entry.notes),
                _ => {}
            }
            if standard || present || create_missing_custom {
                entry.set_field(Field {
                    key,
                    value: ProtectedValue::from_text(std::mem::take(&mut *update.value)),
                    protected,
                    protect_in_memory,
                });
            }
        }
        self.invalidate_references();
        Ok(count)
    }

    /// Ensures an entry exists at a full root-prefixed or implicit-root path.
    /// Creates missing parent groups. Dry runs
    /// validate and report whether creation would occur without generating a
    /// password or changing the live model.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for malformed paths,
    /// [`ServiceError::InvalidSize`] for an invalid generation size,
    /// [`ServiceError::XmlDepth`] when the current model exceeds the XML depth policy,
    /// [`ServiceError::Ambiguous`] when a group or entry name is ambiguous,
    /// [`ServiceError::RootGroup`] when the path names the root, and duplicate
    /// model errors when identifiers or fields are malformed.
    pub fn ensure_entry(
        &mut self,
        session: SessionId,
        path: &str,
        size: Option<usize>,
        dry_run: bool,
    ) -> Result<bool, ServiceError> {
        let (group_locator, title) = split_entry_path(path)?;
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        if group_locator.is_empty() && title.eq_ignore_ascii_case(&live.database.root.name) {
            return Err(ServiceError::RootGroup);
        }
        validate_xml_depth(&live.database.root)?;
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        let segments = path.split('/').collect::<Vec<_>>();
        if let Some(_existing) = existing_entry_candidate(&live.database.root, &segments)? {
            return Ok(false);
        }
        let plan = plan_group_path(&live.database.root, &group_locator)?;
        if plan.path_bytes + 1 + title.len() > MAX_HIT_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        if let Some(size) = size
            && (size == 0 || size > 4096)
        {
            return Err(ServiceError::InvalidSize);
        }
        if dry_run {
            return Ok(true);
        }
        let mut entry = Entry::new(title);
        if let Some(size) = size {
            let mut password = Zeroizing::new(generate_password(size)?);
            entry.password = ProtectedValue::from_text(std::mem::take(&mut *password));
        }
        let group = apply_group_plan(&mut live.database.root, &plan);
        group.add_entry(entry);
        self.invalidate_references();
        Ok(true)
    }

    /// Removes one selected entry and prunes/remaps attachment binaries exactly
    /// as the CLI mutation path does. All entry handles are invalidated.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::DuplicateIds`] or [`ServiceError::DuplicateFields`] for
    /// malformed model identifiers/fields, and [`ServiceError::NotFound`] for
    /// a dangling attachment reference.
    pub fn remove_entry(&mut self, reference: &EntryRef) -> Result<(), ServiceError> {
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        validate_attachment_references(&live.database)?;
        remove_locator(&mut live.database, &reference.locator, reference.id)?;
        prune_attachments(&mut live.database)?;
        self.invalidate_references();
        Ok(())
    }

    /// Returns the safe root-prefixed path for one current group handle.
    ///
    /// # Errors
    /// Returns [`ServiceError::Locked`] without an open vault, or
    /// [`ServiceError::Stale`] for a handle from an earlier generation.
    pub fn group_path(&self, reference: &GroupRef) -> Result<String, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        resolve_group_locator(&live.database, &reference.locator, reference.id)?;
        group_path_context(&live.database, &reference.locator)
    }

    /// Resolves a safe root-prefixed group path to a session-bound handle.
    ///
    /// # Errors
    /// Returns [`ServiceError::Locked`] without an open vault;
    /// [`ServiceError::Stale`] for a non-current session;
    /// [`ServiceError::InvalidInput`] for an empty or malformed path;
    /// [`ServiceError::NotFound`] when no group matches; and
    /// [`ServiceError::Ambiguous`] when the path is not unique.
    pub fn resolve_group(&self, session: SessionId, path: &str) -> Result<GroupRef, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        if path.len() > MAX_HIT_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        let segments = path.split('/').collect::<Vec<_>>();
        if path.is_empty()
            || segments.len() > MAX_LOCATOR_DEPTH
            || segments.iter().any(|part| {
                part.is_empty()
                    || part.len() > MAX_TREE_LABEL_BYTES
                    || matches!(*part, "." | "..")
                    || !safe_metadata(part)
            })
        {
            return Err(ServiceError::InvalidInput);
        }
        let selected = resolve_group_path(&live.database.root, &segments)?;
        let mut locator = Vec::new();
        if !find_group_locator(&live.database.root, selected, &mut locator, 0)? {
            return Err(ServiceError::NotFound);
        }
        Ok(GroupRef {
            session,
            generation: live.generation,
            id: selected.id,
            locator,
        })
    }

    /// Adds a group beneath a selected group. Names are single safe path
    /// components; handles are invalidated after mutation.
    ///
    /// # Errors
    /// Returns [`ServiceError::InvalidInput`] for an unsafe name,
    /// [`ServiceError::GroupExists`] for a case-insensitive sibling collision,
    /// [`ServiceError::Locked`] without an open vault, or
    /// [`ServiceError::Stale`] for an outdated parent handle.
    pub fn add_group(&mut self, parent: &GroupRef, name: &str) -> Result<(), ServiceError> {
        if name.is_empty()
            || name.len() > MAX_TREE_LABEL_BYTES
            || name.contains('/')
            || matches!(name, "." | "..")
            || !safe_metadata(name)
        {
            return Err(ServiceError::InvalidInput);
        }
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != parent.session || live.generation != parent.generation {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        let group = resolve_group_locator(&live.database, &parent.locator, parent.id)?;
        if group
            .groups
            .iter()
            .any(|child| child.name.eq_ignore_ascii_case(name))
        {
            return Err(ServiceError::GroupExists);
        }
        resolve_group_locator_mut(&mut live.database, &parent.locator, parent.id)?
            .add_group(Group::new(name));
        self.invalidate_references();
        Ok(())
    }

    /// Creates missing groups in a root-prefixed or implicit-root path.
    /// Returns the number of new groups. A dry run does not change the vault.
    ///
    /// # Errors
    /// Returns a session error, a model validation error, or
    /// [`ServiceError::InvalidInput`] for an unsafe path and
    /// [`ServiceError::Ambiguous`] for a non-unique parent path, or
    /// [`ServiceError::XmlDepth`] when the current model exceeds the XML depth policy.
    pub fn ensure_group(
        &mut self,
        session: SessionId,
        path: &str,
        dry_run: bool,
    ) -> Result<usize, ServiceError> {
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        validate_xml_depth(&live.database.root)?;
        validate_unique_object_ids(&live.database)?;
        if path.len() > MAX_HIT_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        let segments = path.split('/').collect::<Vec<_>>();
        let plan = plan_group_path(&live.database.root, &segments)?;
        let count = plan.missing.len();
        if count > 0 && !dry_run {
            apply_group_plan(&mut live.database.root, &plan);
            self.invalidate_references();
        }
        Ok(count)
    }

    /// Removes a selected non-root group and prunes binaries no longer
    /// referenced anywhere in the database. Handles are invalidated.
    ///
    /// # Errors
    /// Returns [`ServiceError::RootGroupMutation`] for the root group,
    /// [`ServiceError::Locked`] without an open vault,
    /// [`ServiceError::Stale`] for an outdated handle, or a validation error
    /// when object IDs, fields, or attachment references are unsafe.
    pub fn remove_group(&mut self, reference: &GroupRef) -> Result<(), ServiceError> {
        if reference.locator.is_empty() {
            return Err(ServiceError::RootGroupMutation);
        }
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        validate_attachment_references(&live.database)?;
        remove_group_locator(&mut live.database, &reference.locator, reference.id)?;
        prune_attachments(&mut live.database)?;
        self.invalidate_references();
        Ok(())
    }

    /// Adds protected binary data under an exact, case-sensitive attachment
    /// name. Input remains zeroizing until validation succeeds, then its
    /// allocation is moved into the live `KeePass` model's binary pool. The
    /// model retains that plaintext allocation for the lifetime of the open
    /// vault; this does not promise that the model's pool is zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for an unsafe name,
    /// [`ServiceError::AttachmentExists`] when the exact name already exists,
    /// [`ServiceError::Ambiguous`] when it is duplicated, or
    /// [`ServiceError::Stale`] for an expired entry handle,
    /// [`ServiceError::DuplicateIds`] or [`ServiceError::DuplicateFields`] for
    /// an invalid model, or [`ServiceError::InvalidAttachmentReference`] for a
    /// dangling existing attachment reference.
    pub fn add_attachment(
        &mut self,
        reference: &EntryRef,
        name: &str,
        mut data: Zeroizing<Vec<u8>>,
    ) -> Result<(), ServiceError> {
        if name.is_empty() || name.contains('/') || name.chars().any(char::is_control) {
            return Err(ServiceError::InvalidInput);
        }
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_save_model(&live.database)?;
        let mut found = false;
        for attachment in
            &resolve_locator(&live.database, &reference.locator, reference.id)?.attachments
        {
            if attachment.name == name {
                if found {
                    return Err(ServiceError::Ambiguous);
                }
                found = true;
            }
        }
        if found {
            return Err(ServiceError::AttachmentExists);
        }
        // Resolve before taking ownership out of the zeroizing wrapper. This
        // completes every fallible validation before the allocation moves.
        resolve_locator(&live.database, &reference.locator, reference.id)?;
        let binary_reference = live
            .database
            .binary_pool
            .add(std::mem::take(&mut *data), true);
        let entry = resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?;
        entry.attachments.push(neotales_keepass::Attachment {
            name: name.to_owned(),
            reference: binary_reference,
        });
        self.invalidate_references();
        Ok(())
    }

    /// Removes one exact-name attachment and prunes/remaps the binary pool,
    /// including attachments retained in entry history.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::NotFound`] when the name is absent,
    /// [`ServiceError::Ambiguous`] when the name is duplicated,
    /// [`ServiceError::InvalidAttachmentReference`] for a dangling retained
    /// binary reference, or [`ServiceError::Stale`] for an expired handle.
    pub fn remove_attachment(
        &mut self,
        reference: &EntryRef,
        name: &str,
    ) -> Result<(), ServiceError> {
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        validate_save_model(&live.database)?;
        let entry = resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?;
        let mut found = None;
        for (index, attachment) in entry.attachments.iter().enumerate() {
            if attachment.name == name && found.replace(index).is_some() {
                return Err(ServiceError::Ambiguous);
            }
        }
        let index = found.ok_or(ServiceError::NotFound)?;
        let removed = entry.attachments.remove(index);
        if let Err(error) = prune_attachments(&mut live.database) {
            resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?
                .attachments
                .insert(index, removed);
            return Err(error);
        }
        self.invalidate_references();
        Ok(())
    }

    /// Removes one exact custom field from the selected entry.
    /// Standard fields are never removable through this operation.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::FieldConflict`] for a standard field,
    /// [`ServiceError::NotFound`] when the exact field is absent,
    /// [`ServiceError::Ambiguous`] for a duplicated exact name, or
    /// [`ServiceError::DuplicateIds`] or [`ServiceError::DuplicateFields`] for
    /// malformed model identifiers/fields.
    pub fn remove_custom_field(
        &mut self,
        reference: &EntryRef,
        name: &str,
    ) -> Result<(), ServiceError> {
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        if is_standard_field(name) {
            return Err(ServiceError::FieldConflict);
        }
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        let entry = resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?;
        let index = unique_field_index(entry, name)?;
        entry.fields.remove(index);
        self.invalidate_references();
        Ok(())
    }

    /// Imports a complete bounded interchange snapshot into the live session.
    /// A non-empty vault requires explicit replacement authorization. Password
    /// ensure directives are applied only to the candidate snapshot; dry-runs
    /// never generate randomness or mutate the live session.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic when the session is locked, replacement is
    /// not authorized, the live model is malformed, or the bounded interchange
    /// document or one of its ensure directives is invalid.
    pub fn import_snapshot(
        &mut self,
        input: &[u8],
        options: ImportOptions,
    ) -> Result<ImportReport, AutomationError> {
        let live = self
            .session
            .as_ref()
            .ok_or_else(|| AutomationError::fixed("vault is locked"))?;
        validate_unique_object_ids(&live.database)
            .map_err(|error| AutomationError::fixed(error.message()))?;
        validate_unique_field_names(&live.database)
            .map_err(|error| AutomationError::fixed(error.message()))?;
        let mut incoming =
            interchange::decode(input).map_err(|error| AutomationError::fixed(error.message()))?;
        if !options.replace && !automation::tree_is_empty(&live.database) {
            return Err(AutomationError::fixed(
                "target vault is not empty; use --replace to authorize replacement",
            ));
        }
        let stats = interchange::stats(&incoming.database);
        carry_ensured_passwords(&live.database, &mut incoming.database, &incoming.directives)?;
        let plan = plan_ensure(&incoming.database, &incoming.directives)?;
        let outcome = if options.dry_run {
            plan.dry_run()
        } else {
            apply_ensure(&mut incoming.database, &plan)?
        };
        if !options.dry_run {
            self.session
                .as_mut()
                .ok_or_else(|| AutomationError::fixed("vault is locked"))?
                .database = incoming.database;
            self.invalidate_references();
        }
        Ok(ImportReport {
            replaced: options.replace,
            dry_run: options.dry_run,
            groups: stats.groups,
            entries: stats.entries,
            history_entries: stats.history_entries,
            fields: stats.fields,
            attachments: stats.attachments,
            protected_values: stats.protected_values,
            binary_records: stats.binary_records,
            binary_bytes: stats.binary_bytes,
            passwords_generated: outcome.generated,
            passwords_kept: outcome.kept,
            passwords_pending: outcome.pending,
        })
    }

    /// Exports the complete live vault, refusing any model that cannot be
    /// represented losslessly and enforcing the interchange byte/resource
    /// budgets before returning a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic when the session is locked, the model cannot
    /// be represented losslessly, or interchange limits are exceeded.
    pub fn export_snapshot(&self) -> Result<ExportSnapshot, AutomationError> {
        let live = self
            .session
            .as_ref()
            .ok_or_else(|| AutomationError::fixed("vault is locked"))?;
        let bytes = interchange::encode(&live.database)
            .map_err(|error| AutomationError::fixed(error.message()))?;
        Ok(ExportSnapshot(bytes))
    }

    /// Merges a complete bounded interchange snapshot into the live session
    /// without deleting target-only objects. Dry-runs use a detached candidate
    /// and cannot alter the open session.
    ///
    /// # Errors
    ///
    /// Returns a fixed diagnostic when the session is locked, the live model is
    /// malformed, source UUIDs collide, the bounded interchange is invalid, or
    /// an ensure directive is invalid.
    pub fn sync_snapshot(
        &mut self,
        input: &[u8],
        options: SyncOptions,
    ) -> Result<SyncReport, AutomationError> {
        let live = self
            .session
            .as_ref()
            .ok_or_else(|| AutomationError::fixed("vault is locked"))?;
        validate_unique_object_ids(&live.database)
            .map_err(|error| AutomationError::fixed(error.message()))?;
        validate_unique_field_names(&live.database)
            .map_err(|error| AutomationError::fixed(error.message()))?;
        let source =
            interchange::decode(input).map_err(|error| AutomationError::fixed(error.message()))?;
        let mut candidate = live.database.clone();
        let plan = automation::sync(&mut candidate, &source.database, options.strategy.into())
            .map_err(AutomationError::fixed)?;
        automation::normalize_standard_projections(&mut candidate);
        let ensure = plan_ensure(&candidate, &source.directives)?;
        let outcome = if options.dry_run {
            ensure.dry_run()
        } else {
            apply_ensure(&mut candidate, &ensure)?
        };
        let changed = plan != automation::SyncPlan::default() || outcome.generated > 0;
        if !options.dry_run && changed {
            self.session
                .as_mut()
                .ok_or_else(|| AutomationError::fixed("vault is locked"))?
                .database = candidate;
            self.invalidate_references();
        }
        Ok(SyncReport {
            dry_run: options.dry_run,
            strategy: options.strategy,
            groups_added: plan.groups_added,
            groups_updated: plan.groups_updated,
            entries_added: plan.entries_added,
            entries_updated: plan.entries_updated,
            passwords_generated: outcome.generated,
            passwords_kept: outcome.kept,
            passwords_pending: outcome.pending,
        })
    }

    fn invalidate_references(&mut self) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let live = self
            .session
            .as_mut()
            .expect("session retained during mutation");
        live.generation = self.generation;
        self.searches.clear();
        self.listings.clear();
        self.trees.clear();
    }

    fn mutate_field(
        &mut self,
        reference: &EntryRef,
        name: &str,
        value: &str,
        custom_only: bool,
    ) -> Result<(), ServiceError> {
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(ServiceError::InvalidFieldName);
        }
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        if custom_only && is_standard_field(name) {
            return Err(ServiceError::FieldConflict);
        }
        if name == "Title" {
            return Err(ServiceError::FieldConflict);
        }
        validate_unique_object_ids(&live.database)?;
        validate_unique_field_names(&live.database)?;
        normalize_standard_projections(&mut live.database);
        let entry = resolve_locator_mut(&mut live.database, &reference.locator, reference.id)?;
        set_entry_field(entry, name, value)?;

        // Mutations invalidate every entry handle and every cursor. Keep the
        // session identity but advance its generation so pre-edit references
        // cannot be used against the changed model.
        self.invalidate_references();
        Ok(())
    }

    /// Persists the live database using the CLI's private atomic replacement
    /// contract. Credentials are borrowed only for the KDBX save operation.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Locked`] without a live vault,
    /// [`ServiceError::XmlDepth`] when the model exceeds the XML depth policy,
    /// [`ServiceError::DuplicateIds`] or [`ServiceError::DuplicateFields`] for
    /// an unsafe model, or a save-phase error if staging, encoding, syncing, or
    /// atomic replacement fails. A model that cannot be saved losslessly or has
    /// dangling attachment references is rejected before save preparation.
    pub fn save(
        &mut self,
        path: &Path,
        credentials: &mut KdbxCredentials,
    ) -> Result<(), ServiceError> {
        let live = self.session.as_mut().ok_or(ServiceError::Locked)?;
        validate_save_model(&live.database)?;
        prepare_standard_fields_for_save(&mut live.database);
        let parent = save_parent(path);
        let mut temp =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| ServiceError::SaveStage)?;
        crate::private_file::set_owner_only(temp.path(), "cannot set vault permissions")
            .map_err(|cause| permission_failure(cause, ServiceError::SaveStage))?;
        KdbxFile::save(
            &live.database,
            &mut temp,
            credentials,
            KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .map_err(|_| ServiceError::Save)?;
        temp.as_file()
            .sync_all()
            .map_err(|_| ServiceError::SaveSync)?;
        // NamedTempFile::persist replaces atomically on the same filesystem;
        // its restrictive staging-file permissions are retained at the target.
        temp.persist(path).map_err(|_| ServiceError::SaveReplace)?;
        #[cfg(unix)]
        confirm_durable(parent)?;
        #[cfg(not(unix))]
        confirm_durable();
        Ok(())
    }

    /// Resolves a root-prefixed or implicit-root entry path case-insensitively.
    /// Malformed slash-containing siblings are ignored because they cannot be
    /// addressed by this path grammar; duplicate matching names fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Locked`] without an open session,
    /// [`ServiceError::Stale`] for a foreign session, [`ServiceError::InvalidInput`]
    /// for malformed or unsafe paths, [`ServiceError::Ambiguous`] when a path
    /// segment matches duplicate names ignoring case, or
    /// [`ServiceError::NotFound`] when no entry matches.
    pub fn resolve_entry(
        &self,
        session: SessionId,
        path: &str,
    ) -> Result<ResolvedEntry, ServiceError> {
        if path.is_empty()
            || path.chars().any(char::is_control)
            || path.starts_with('/')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(ServiceError::InvalidInput);
        }
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        let segments = path.split('/').collect::<Vec<_>>();
        let mut group = &live.database.root;
        let mut locator = Vec::new();
        let mut projected = vec![group.name.as_str()];
        let start = entry_path_start(group, &segments)?;
        if segments.len() == 1 && segments[0].eq_ignore_ascii_case(&group.name) {
            return Err(ServiceError::RootGroup);
        }
        for segment in &segments[start..segments.len() - 1] {
            let mut found = None;
            for (index, child) in group.groups.iter().enumerate() {
                if child.name.is_empty() || child.name.contains('/') {
                    continue;
                }
                if child.name.eq_ignore_ascii_case(segment) {
                    if found.is_some() {
                        return Err(ServiceError::Ambiguous);
                    }
                    found = Some((index, child));
                }
            }
            let (index, child) = found.ok_or(ServiceError::NotFound)?;
            locator.push(index);
            projected.push(child.name.as_str());
            group = child;
        }
        let title = segments[segments.len() - 1];
        let mut found = None;
        for (index, entry) in group.entries.iter().enumerate() {
            if entry.title.is_empty() || entry.title.contains('/') {
                continue;
            }
            if entry.title.eq_ignore_ascii_case(title) {
                if found.is_some() {
                    return Err(ServiceError::Ambiguous);
                }
                found = Some((index, entry));
            }
        }
        let (entry_index, entry) = found.ok_or(ServiceError::NotFound)?;
        locator.push(entry_index);
        projected.push(entry.title.as_str());
        let path = projected.join("/");
        if !safe_metadata(&path) || path.len() > MAX_HIT_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        Ok(ResolvedEntry {
            reference: EntryRef {
                session: live.id,
                generation: live.generation,
                id: entry.id,
                locator,
            },
            path,
        })
    }

    /// Resolves an entry while retaining the caller-path category needed by
    /// the OTP CLI diagnostics. Unlike [`Self::resolve_entry`], this reports
    /// group/entry ambiguity and missing intermediate groups separately.
    /// Segment indexes refer to the original selector, including a root prefix.
    ///
    /// # Errors
    ///
    /// Returns a [`SelectorError`] category describing the caller-path failure,
    /// or [`SelectorError::Service`] for a locked/stale session or unsafe
    /// resolved projection.
    pub fn resolve_entry_for_otp(
        &self,
        session: SessionId,
        path: &str,
    ) -> Result<ResolvedEntry, SelectorError> {
        if path.is_empty()
            || path.chars().any(char::is_control)
            || path.starts_with('/')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(SelectorError::MalformedPath);
        }
        let live = self
            .session
            .as_ref()
            .ok_or(SelectorError::Service(ServiceError::Locked))?;
        if live.id != session {
            return Err(SelectorError::Service(ServiceError::Stale));
        }
        let segments = path.split('/').collect::<Vec<_>>();
        let mut group = &live.database.root;
        let mut locator = Vec::new();
        let mut projected = vec![group.name.as_str()];
        let start = match entry_path_start(group, &segments) {
            Ok(start) => start,
            Err(ServiceError::NotFound) => {
                let fallback_start = usize::from(
                    segments.len() > 1 && segments[0].eq_ignore_ascii_case(&group.name),
                );
                if has_ambiguous_group_prefix(group, &segments[fallback_start..segments.len() - 1])
                {
                    return Err(SelectorError::NotFound);
                }
                fallback_start
            }
            Err(ServiceError::Ambiguous) => {
                return Err(SelectorError::AmbiguousGroup { segment_index: 0 });
            }
            Err(error) => return Err(SelectorError::Service(error)),
        };
        if segments.len() == 1 && segments[0].eq_ignore_ascii_case(&group.name) {
            return Err(SelectorError::RootGroup);
        }
        for (relative_index, segment) in segments[start..segments.len() - 1].iter().enumerate() {
            let segment_index = start + relative_index;
            let mut found = None;
            for (index, child) in group.groups.iter().enumerate() {
                if child.name.is_empty() || child.name.contains('/') {
                    continue;
                }
                if child.name.eq_ignore_ascii_case(segment) {
                    if found.is_some() {
                        return Err(SelectorError::AmbiguousGroup { segment_index });
                    }
                    found = Some((index, child));
                }
            }
            let Some((index, child)) = found else {
                return Err(SelectorError::MissingGroup {
                    segment_index,
                    walked_start_index: start,
                });
            };
            locator.push(index);
            projected.push(child.name.as_str());
            group = child;
        }
        let title = segments[segments.len() - 1];
        let mut found = None;
        for (index, entry) in group.entries.iter().enumerate() {
            if entry.title.is_empty() || entry.title.contains('/') {
                continue;
            }
            if entry.title.eq_ignore_ascii_case(title) {
                if found.is_some() {
                    return Err(SelectorError::AmbiguousEntry {
                        segment_index: segments.len() - 1,
                    });
                }
                found = Some((index, entry));
            }
        }
        let Some((entry_index, entry)) = found else {
            return Err(SelectorError::NotFound);
        };
        locator.push(entry_index);
        projected.push(entry.title.as_str());
        let resolved_path = projected.join("/");
        if !safe_metadata(&resolved_path) || resolved_path.len() > MAX_HIT_BYTES {
            return Err(SelectorError::Service(ServiceError::InvalidInput));
        }
        Ok(ResolvedEntry {
            reference: EntryRef {
                session: live.id,
                generation: live.generation,
                id: entry.id,
                locator,
            },
            path: resolved_path,
        })
    }

    /// Searches only title, parent path/group labels, tags, username, and URL.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for empty or oversized queries,
    /// [`ServiceError::Locked`] when no session is open, or [`ServiceError::Stale`]
    /// when the supplied session is not current.
    pub fn search(&mut self, session: SessionId, query: &str) -> Result<SearchPage, ServiceError> {
        self.search_page(session, query, None)
    }

    /// Searches one bounded page, optionally continuing from a previous page.
    ///
    /// `search` is equivalent to calling this with no cursor. Matches are
    /// consumed in vault order. Each page visits at most 10,000 entries/groups,
    /// including unmatched records, and resumes without rescanning. Group-label
    /// matches are cached per visited group. Text work is weighted conservatively
    /// by candidate UTF-8 bytes and candidate count: at most 8 MiB per page and
    /// 512 MiB per search. A single record/group exceeding a page text-work limit
    /// fails explicitly rather than being skipped. Continuations are stateful,
    /// query-bound, and single-use. At most eight continuations may be active;
    /// total node work per search is capped at 1,000,000 visits.
    /// Deeper subtrees beyond 256 group levels are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for an empty or oversized query,
    /// [`ServiceError::Locked`] without a live session, or [`ServiceError::Stale`]
    /// for a foreign session/cursor or query-mismatched/replayed cursor, and
    /// [`ServiceError::ResourceLimit`] when the total work ceiling is reached.
    pub fn search_page(
        &mut self,
        session: SessionId,
        query: &str,
        cursor: Option<SearchCursor>,
    ) -> Result<SearchPage, ServiceError> {
        if query.is_empty() || query.len() > MAX_QUERY_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        let mut state = if let Some(cursor) = cursor {
            if cursor.session != live.id || cursor.generation != live.generation {
                return Err(ServiceError::Stale);
            }
            let state = self
                .searches
                .get(&cursor.token)
                .ok_or(ServiceError::Stale)?;
            if state.query != query {
                return Err(ServiceError::Stale);
            }
            self.searches
                .remove(&cursor.token)
                .ok_or(ServiceError::Stale)?
        } else {
            SearchState::new(query, live.id, live.generation)
        };
        let page = scan_page(&live.database.root, &mut state)?;
        if state.has_more() {
            if self.searches.len() >= MAX_ACTIVE_CURSORS {
                return Err(ServiceError::ResourceLimit);
            }
            let token = self.next_search_token.wrapping_add(1).max(1);
            self.next_search_token = token;
            self.searches.insert(token, state);
            Ok(SearchPage {
                next_cursor: Some(SearchCursor {
                    session: live.id,
                    generation: live.generation,
                    token,
                }),
                ..page
            })
        } else {
            Ok(page)
        }
    }

    /// Releases an unused search continuation so abandoned UI searches do not
    /// consume the bounded active-cursor budget.
    pub fn release_search_cursor(&mut self, cursor: SearchCursor) -> bool {
        if self
            .session
            .as_ref()
            .is_some_and(|live| live.id == cursor.session && live.generation == cursor.generation)
        {
            self.searches.remove(&cursor.token).is_some()
        } else {
            false
        }
    }

    /// Lists all entries, optionally filtering full root-prefixed paths with a glob.
    ///
    /// `pattern` is compiled and bounded by the service; glob semantics match
    /// the `secrets ls` CLI contract. Pages are bounded by work and projection
    /// memory, not by the search result count. Every continuation advances the
    /// same iterative traversal without rescanning earlier entries.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::InvalidInput`] for a glob longer than 1,024
    /// bytes, [`ServiceError::Locked`] without a live session, [`ServiceError::Stale`]
    /// for an invalid cursor, or [`ServiceError::ResourceLimit`] when traversal
    /// exceeds its explicit work ceilings.
    pub fn list_page(
        &mut self,
        session: SessionId,
        pattern: Option<&str>,
        cursor: Option<ListCursor>,
    ) -> Result<ListPage, ServiceError> {
        if pattern.is_some_and(|pattern| pattern.len() > MAX_LIST_PATTERN_BYTES) {
            return Err(ServiceError::InvalidInput);
        }
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        let mut state = if let Some(cursor) = cursor {
            if cursor.session != live.id || cursor.generation != live.generation {
                return Err(ServiceError::Stale);
            }
            self.listings
                .remove(&cursor.token)
                .ok_or(ServiceError::Stale)?
        } else {
            ListState::new(pattern, live.id, live.generation)
        };
        if state.pattern.as_deref() != pattern {
            return Err(ServiceError::Stale);
        }
        let page = scan_list_page(&live.database.root, &mut state).map_err(|error| {
            if error == ServiceError::ResourceLimit {
                ServiceError::ListingIncomplete
            } else {
                error
            }
        })?;
        if state.has_more() {
            if self.listings.len() >= MAX_ACTIVE_CURSORS {
                return Err(ServiceError::ListingIncomplete);
            }
            let token = self.next_search_token.wrapping_add(1).max(1);
            self.next_search_token = token;
            self.listings.insert(token, state);
            Ok(ListPage {
                next_cursor: Some(ListCursor {
                    session: live.id,
                    generation: live.generation,
                    token,
                }),
                ..page
            })
        } else {
            Ok(page)
        }
    }

    /// Releases an unused listing continuation.
    pub fn release_list_cursor(&mut self, cursor: ListCursor) -> bool {
        if self
            .session
            .as_ref()
            .is_some_and(|live| live.id == cursor.session && live.generation == cursor.generation)
        {
            self.listings.remove(&cursor.token).is_some()
        } else {
            false
        }
    }

    /// Returns an opaque handle for the root group without projecting its model.
    ///
    /// # Errors
    /// Returns [`ServiceError::Locked`] without an open vault or
    /// [`ServiceError::Stale`] for a non-current session.
    pub fn root_group(&self, session: SessionId) -> Result<GroupRef, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if live.id != session {
            return Err(ServiceError::Stale);
        }
        Ok(GroupRef {
            session,
            generation: live.generation,
            id: live.database.root.id,
            locator: Vec::new(),
        })
    }

    /// Lists one bounded page of a group's direct child groups and entries.
    /// Display paths are projections only; handles carry verified locators and UUIDs.
    ///
    /// # Errors
    /// Returns [`ServiceError::Locked`] without an open vault,
    /// [`ServiceError::Stale`] for a foreign, stale, or replayed handle/cursor,
    /// [`ServiceError::InvalidInput`] for unsafe ancestor context, or
    /// [`ServiceError::ResourceLimit`] when all continuation slots are occupied.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps a bounded projection at the service trust boundary"
    )]
    pub fn tree_page(
        &mut self,
        parent: &GroupRef,
        cursor: Option<TreeCursor>,
    ) -> Result<TreePage, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Locked)?;
        if parent.session != live.id || parent.generation != live.generation {
            return Err(ServiceError::Stale);
        }
        if parent.locator.len() > MAX_LOCATOR_DEPTH {
            return Err(ServiceError::ResourceLimit);
        }
        let group = resolve_group_locator(&live.database, &parent.locator, parent.id)?;
        let offset = if let Some(cursor) = cursor {
            if cursor.session != live.id || cursor.generation != live.generation {
                return Err(ServiceError::Stale);
            }
            let state = self
                .trees
                .remove(&cursor.token)
                .ok_or(ServiceError::Stale)?;
            if state.locator != parent.locator || state.group_id != parent.id {
                return Err(ServiceError::Stale);
            }
            state.offset
        } else {
            0
        };
        const PAGE: usize = 128;
        let total = group.groups.len().saturating_add(group.entries.len());
        let end = offset.saturating_add(PAGE).min(total);
        let page_capacity = end.saturating_sub(offset);
        let mut groups = Vec::with_capacity(page_capacity);
        let mut entries = Vec::with_capacity(page_capacity);
        let mut withheld = 0;
        let mut projected_bytes = std::mem::size_of::<TreePage>()
            .saturating_add(page_capacity.saturating_mul(std::mem::size_of::<TreeGroup>()))
            .saturating_add(page_capacity.saturating_mul(std::mem::size_of::<SearchHit>()));
        let mut text_work = 0usize;
        let base_path = group_path_context(&live.database, &parent.locator)?;
        for index in offset..end {
            if index < group.groups.len() {
                let child = &group.groups[index];
                if child.name.is_empty()
                    || child.name.len() > MAX_TREE_LABEL_BYTES
                    || child.name.contains('/')
                {
                    withheld += 1;
                    continue;
                }
                text_work = text_work
                    .checked_add(child.name.len())
                    .ok_or(ServiceError::ResourceLimit)?;
                if text_work > MAX_TREE_PAGE_WORK {
                    return Err(ServiceError::ResourceLimit);
                }
                if !safe_metadata(&child.name) {
                    withheld += 1;
                    continue;
                }
                let cost = std::mem::size_of::<TreeGroup>()
                    .saturating_add(child.name.len())
                    .saturating_add(std::mem::size_of::<GroupRef>())
                    .saturating_add(
                        parent
                            .locator
                            .len()
                            .saturating_add(1)
                            .saturating_mul(std::mem::size_of::<usize>()),
                    );
                if cost > MAX_TREE_ROW_BYTES
                    || projected_bytes.saturating_add(cost) > MAX_TREE_PAGE_BYTES
                {
                    withheld += 1;
                    continue;
                }
                projected_bytes += cost;
                let mut locator = parent.locator.clone();
                locator.push(index);
                groups.push(TreeGroup {
                    label: child.name.clone(),
                    reference: GroupRef {
                        session: live.id,
                        generation: live.generation,
                        id: child.id,
                        locator,
                    },
                });
            } else {
                let entry_index = index - group.groups.len();
                let entry = &group.entries[entry_index];
                if entry.title.is_empty()
                    || entry.title.len() > MAX_TREE_LABEL_BYTES
                    || entry.title.contains('/')
                    || !safe_metadata(&entry.title)
                {
                    withheld += 1;
                    continue;
                }
                if entry.fields.len() > MAX_METADATA_ITEMS || entry.tags.len() > MAX_METADATA_ITEMS
                {
                    withheld += 1;
                    continue;
                }
                let too_long = entry
                    .fields
                    .iter()
                    .any(|field| field.key.len() > MAX_TREE_LABEL_BYTES)
                    || entry
                        .tags
                        .iter()
                        .any(|tag| tag.len() > MAX_TREE_LABEL_BYTES);
                if too_long {
                    withheld += 1;
                    continue;
                }
                let row_text_work = std::iter::once(entry.title.len())
                    .chain(entry.fields.iter().map(|field| field.key.len()))
                    .chain(entry.tags.iter().map(String::len))
                    .try_fold(0usize, usize::checked_add)
                    .ok_or(ServiceError::ResourceLimit)?;
                text_work = text_work
                    .checked_add(row_text_work)
                    .ok_or(ServiceError::ResourceLimit)?;
                if text_work > MAX_TREE_PAGE_WORK {
                    return Err(ServiceError::ResourceLimit);
                }
                let path = if base_path.is_empty() {
                    entry.title.clone()
                } else {
                    format!("{base_path}/{}", entry.title)
                };
                if path.len() > MAX_HIT_BYTES {
                    withheld += 1;
                    continue;
                }
                let visible_fields = entry
                    .fields
                    .iter()
                    .filter(|field| safe_metadata(&field.key))
                    .collect::<Vec<_>>();
                let visible_tags = entry
                    .tags
                    .iter()
                    .filter(|tag| safe_metadata(tag))
                    .collect::<Vec<_>>();
                let row_cost = std::iter::once(path.len())
                    .chain(visible_fields.iter().map(|field| field.key.len()))
                    .chain(visible_tags.iter().map(|tag| tag.len()))
                    .try_fold(std::mem::size_of::<SearchHit>(), usize::checked_add)
                    .unwrap_or(usize::MAX)
                    .saturating_add(
                        visible_fields
                            .len()
                            .saturating_mul(std::mem::size_of::<String>()),
                    )
                    .saturating_add(
                        visible_tags
                            .len()
                            .saturating_mul(std::mem::size_of::<String>()),
                    )
                    .saturating_add(
                        parent
                            .locator
                            .len()
                            .saturating_add(1)
                            .saturating_mul(std::mem::size_of::<usize>()),
                    );
                if row_cost > MAX_TREE_ROW_BYTES
                    || projected_bytes.saturating_add(row_cost) > MAX_TREE_PAGE_BYTES
                {
                    withheld += 1;
                    continue;
                }
                projected_bytes += row_cost;
                let field_names = visible_fields
                    .into_iter()
                    .map(|field| field.key.clone())
                    .collect();
                entries.push(SearchHit {
                    reference: EntryRef {
                        session: live.id,
                        generation: live.generation,
                        id: entry.id,
                        locator: {
                            let mut l = parent.locator.clone();
                            l.push(entry_index);
                            l
                        },
                    },
                    path,
                    title: entry.title.clone(),
                    tags: visible_tags.into_iter().cloned().collect(),
                    field_names,
                });
            }
        }
        let next_cursor = if end < total {
            if self.trees.len() >= MAX_ACTIVE_CURSORS {
                return Err(ServiceError::ResourceLimit);
            }
            let token = self.next_search_token.wrapping_add(1).max(1);
            self.next_search_token = token;
            self.trees.insert(
                token,
                TreeState {
                    locator: parent.locator.clone(),
                    group_id: parent.id,
                    offset: end,
                },
            );
            Some(TreeCursor {
                session: live.id,
                generation: live.generation,
                token,
            })
        } else {
            None
        };
        Ok(TreePage {
            groups,
            entries,
            next_cursor,
            withheld,
        })
    }

    /// Releases an unused direct-child continuation.
    pub fn release_tree_cursor(&mut self, cursor: TreeCursor) -> bool {
        if self
            .session
            .as_ref()
            .is_some_and(|live| live.id == cursor.session && live.generation == cursor.generation)
        {
            self.trees.remove(&cursor.token).is_some()
        } else {
            false
        }
    }

    /// Validates that a handle is still part of its owning live session.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] if the session, generation, locator, or
    /// UUID no longer identifies the entry.
    pub fn validate_entry(&self, reference: &EntryRef) -> Result<(), ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        resolve_locator(&live.database, &reference.locator, reference.id).map(|_| ())
    }

    /// Returns bounded metadata for the fields of one previously selected entry.
    /// Only field names and their protection flags are inspected; unrelated
    /// entry metadata and attachment binaries are deliberately not projected.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::InvalidInput`] for an unsafe field name, or
    /// [`ServiceError::ResourceLimit`] when the field projection exceeds its
    /// fixed metadata bounds.
    pub fn field_metadata(&self, reference: &EntryRef) -> Result<Vec<FieldMetadata>, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        if entry.fields.len() > MAX_METADATA_ITEMS {
            return Err(ServiceError::ResourceLimit);
        }
        let mut retained_bytes = 0usize;
        for field in &entry.fields {
            if !safe_metadata(&field.key) {
                return Err(ServiceError::InvalidInput);
            }
            retained_bytes = retained_bytes
                .checked_add(field.key.len())
                .ok_or(ServiceError::ResourceLimit)?;
        }
        let projection_bytes = entry
            .fields
            .len()
            .checked_mul(std::mem::size_of::<FieldMetadata>())
            .and_then(|bytes| bytes.checked_add(retained_bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<FieldMetadata>>()))
            .ok_or(ServiceError::ResourceLimit)?;
        if projection_bytes > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        Ok(entry
            .fields
            .iter()
            .map(|field| FieldMetadata {
                name: field.key.clone(),
                protected: field.protected,
                protect_in_memory: field.protect_in_memory,
            })
            .collect())
    }

    /// Returns bounded attachment metadata for an entry, never attachment bytes.
    /// Names must be safe and unique because callers use them as selectors.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired entry, [`ServiceError::Ambiguous`]
    /// for duplicate names, [`ServiceError::InvalidInput`] for unsafe metadata,
    /// [`ServiceError::NotFound`] for a dangling binary, or
    /// [`ServiceError::ResourceLimit`] when the projection exceeds its bounds.
    pub fn attachment_metadata(
        &self,
        reference: &EntryRef,
    ) -> Result<Vec<AttachmentDescriptor>, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        if entry.attachments.len() > MAX_METADATA_ITEMS {
            return Err(ServiceError::ResourceLimit);
        }
        let mut retained_bytes = 0usize;
        let locator_bytes = reference
            .locator
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(ServiceError::ResourceLimit)?;
        for (index, attachment) in entry.attachments.iter().enumerate() {
            if !safe_metadata(&attachment.name) {
                return Err(ServiceError::InvalidInput);
            }
            if entry.attachments[..index]
                .iter()
                .any(|prior| prior.name == attachment.name)
            {
                return Err(ServiceError::Ambiguous);
            }
            retained_bytes = retained_bytes
                .checked_add(
                    attachment
                        .name
                        .len()
                        .checked_mul(2)
                        .ok_or(ServiceError::ResourceLimit)?,
                )
                .and_then(|bytes| bytes.checked_add(locator_bytes))
                .ok_or(ServiceError::ResourceLimit)?;
            if live
                .database
                .binary_pool
                .get(attachment.reference)
                .is_none()
            {
                return Err(ServiceError::NotFound);
            }
        }
        let projected = entry
            .attachments
            .len()
            .checked_mul(std::mem::size_of::<AttachmentDescriptor>())
            .and_then(|bytes| bytes.checked_add(retained_bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<AttachmentDescriptor>>()))
            .ok_or(ServiceError::ResourceLimit)?;
        if projected > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        let mut descriptors = Vec::with_capacity(entry.attachments.len());
        for (index, attachment) in entry.attachments.iter().enumerate() {
            let binary = live
                .database
                .binary_pool
                .get(attachment.reference)
                .ok_or(ServiceError::NotFound)?;
            descriptors.push(AttachmentDescriptor {
                name: attachment.name.clone(),
                size: binary.data.len(),
                protected: binary.protected,
                reference: AttachmentRef {
                    entry: reference.clone(),
                    index,
                    name: attachment.name.clone(),
                    binary_reference: attachment.reference,
                },
            });
        }
        Ok(descriptors)
    }

    /// Returns metadata for one exact attachment name, failing only when that
    /// selected name is duplicated. This preserves named-read selection even if
    /// unrelated legacy duplicates exist in the entry.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired entry,
    /// [`ServiceError::Ambiguous`] for a duplicate selected name,
    /// [`ServiceError::InvalidInput`] for unsafe metadata,
    /// [`ServiceError::NotFound`] for a missing attachment or binary, or
    /// [`ServiceError::ResourceLimit`] when the projection exceeds its bounds.
    pub fn attachment_metadata_for(
        &self,
        reference: &EntryRef,
        name: &str,
    ) -> Result<AttachmentDescriptor, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        if name.len() > MAX_HIT_BYTES || !safe_metadata(name) {
            return Err(ServiceError::InvalidInput);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        let mut found = None;
        for (index, attachment) in entry.attachments.iter().enumerate() {
            if attachment.name == name {
                if found.is_some() {
                    return Err(ServiceError::Ambiguous);
                }
                found = Some((index, attachment));
            }
        }
        let (index, attachment) = found.ok_or(ServiceError::NotFound)?;
        let binary = live
            .database
            .binary_pool
            .get(attachment.reference)
            .ok_or(ServiceError::NotFound)?;
        let size = std::mem::size_of::<AttachmentDescriptor>()
            .checked_add(
                attachment
                    .name
                    .len()
                    .checked_mul(2)
                    .ok_or(ServiceError::ResourceLimit)?,
            )
            .and_then(|bytes| {
                reference
                    .locator
                    .len()
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|locator_bytes| bytes.checked_add(locator_bytes))
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<AttachmentDescriptor>>()))
            .ok_or(ServiceError::ResourceLimit)?;
        if size > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        Ok(AttachmentDescriptor {
            name: attachment.name.clone(),
            size: binary.data.len(),
            protected: binary.protected,
            reference: AttachmentRef {
                entry: reference.clone(),
                index,
                name: attachment.name.clone(),
                binary_reference: attachment.reference,
            },
        })
    }

    /// Explicitly reveals one attachment into zeroizing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired or mismatched handle,
    /// [`ServiceError::Ambiguous`] for duplicate selected names, or
    /// [`ServiceError::NotFound`] for a dangling binary.
    pub fn reveal_attachment(
        &self,
        reference: &AttachmentRef,
    ) -> Result<SecretBytes, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        let entry_ref = &reference.entry;
        if live.id != entry_ref.session || live.generation != entry_ref.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &entry_ref.locator, entry_ref.id)?;
        if entry
            .attachments
            .iter()
            .filter(|item| item.name == reference.name)
            .count()
            > 1
        {
            return Err(ServiceError::Ambiguous);
        }
        let attachment = entry
            .attachments
            .get(reference.index)
            .ok_or(ServiceError::Stale)?;
        if attachment.name != reference.name || attachment.reference != reference.binary_reference {
            return Err(ServiceError::Stale);
        }
        let binary = live
            .database
            .binary_pool
            .get(attachment.reference)
            .ok_or(ServiceError::NotFound)?;
        Ok(SecretBytes::from_vec(binary.data.clone()))
    }

    /// Returns a bounded, safe projection for one previously selected entry.
    ///
    /// The selector is an [`EntryRef`] emitted by search/list; this deliberately
    /// does not duplicate or guess the CLI's path/alias selector grammar.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::NotFound`] for a missing attachment binary, or
    /// [`ServiceError::ResourceLimit`] when the projection exceeds its fixed
    /// metadata bounds.
    #[allow(clippy::too_many_lines)]
    pub fn selected_entry(&self, reference: &EntryRef) -> Result<SelectedEntry, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        let custom_field_count = entry
            .fields
            .iter()
            .filter(|field| !is_standard_field(&field.key))
            .count();
        let item_count = entry
            .tags
            .len()
            .checked_add(entry.attachments.len())
            .and_then(|count| count.checked_add(entry.fields.len()))
            .and_then(|count| count.checked_add(custom_field_count))
            .ok_or(ServiceError::ResourceLimit)?;
        if item_count > MAX_METADATA_ITEMS {
            return Err(ServiceError::ResourceLimit);
        }
        let mut retained_bytes = entry.title.len();
        for text in entry
            .tags
            .iter()
            .map(String::as_str)
            .chain(
                entry
                    .attachments
                    .iter()
                    .map(|attachment| attachment.name.as_str()),
            )
            .chain(entry.fields.iter().map(|field| field.key.as_str()))
        {
            retained_bytes = retained_bytes
                .checked_add(text.len())
                .ok_or(ServiceError::ResourceLimit)?;
            if !safe_metadata(text) {
                return Err(ServiceError::InvalidInput);
            }
        }
        if !safe_metadata(&entry.title) || retained_bytes > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        // Include owned vectors, field handles and their copied locators in the
        // projection limit, and account for each custom name twice (descriptor
        // plus its exact handle), before creating any output allocations.
        let locator_bytes = reference
            .locator
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_mul(custom_field_count))
            .ok_or(ServiceError::ResourceLimit)?;
        let structure_bytes = entry
            .tags
            .len()
            .checked_mul(std::mem::size_of::<String>())
            .and_then(|bytes| {
                bytes.checked_add(
                    entry
                        .attachments
                        .len()
                        .checked_mul(std::mem::size_of::<AttachmentMetadata>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    custom_field_count.checked_mul(std::mem::size_of::<CustomFieldDescriptor>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    entry
                        .fields
                        .len()
                        .checked_mul(std::mem::size_of::<FieldMetadata>())?,
                )
            })
            .and_then(|bytes| bytes.checked_add(locator_bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SelectedEntry>()))
            .ok_or(ServiceError::ResourceLimit)?;
        let custom_name_bytes = entry
            .fields
            .iter()
            .filter(|field| !is_standard_field(&field.key))
            .try_fold(0usize, |total, field| {
                total
                    .checked_add(field.key.len())
                    .ok_or(ServiceError::ResourceLimit)
            })?;
        let projection_bytes = structure_bytes
            .checked_add(retained_bytes)
            .and_then(|bytes| bytes.checked_add(custom_name_bytes))
            .ok_or(ServiceError::ResourceLimit)?;
        if projection_bytes > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        let custom_fields = custom_field_descriptors(entry, reference);
        let fields = entry
            .fields
            .iter()
            .map(|field| FieldMetadata {
                name: field.key.clone(),
                protected: field.protected,
                protect_in_memory: field.protect_in_memory,
            })
            .collect();
        let mut attachments = Vec::with_capacity(entry.attachments.len());
        for attachment in &entry.attachments {
            let binary = live
                .database
                .binary_pool
                .get(attachment.reference)
                .ok_or(ServiceError::NotFound)?;
            attachments.push(AttachmentMetadata {
                name: attachment.name.clone(),
                size: binary.data.len(),
            });
        }
        Ok(SelectedEntry {
            title: entry.title.clone(),
            tags: entry.tags.clone(),
            attachments,
            fields,
            custom_fields,
            has_otp: KeePassXcOtp::read(entry).is_ok(),
            auto_type_enabled: entry.auto_type.enabled == Some(true),
            auto_type_associations: entry.auto_type.associations.len(),
        })
    }

    /// Explicitly reveals one selected custom field as zeroizing bytes.
    ///
    /// The field name is matched exactly and duplicate exact names fail closed.
    /// Neither projection nor descriptor access reads field values.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired/mismatched handle,
    /// [`ServiceError::Ambiguous`] for duplicate exact names,
    /// [`ServiceError::NotFound`] if the field disappeared, or
    /// [`ServiceError::Unlock`] if the protected value cannot be revealed.
    pub fn reveal_custom_field(
        &self,
        reference: &CustomFieldRef,
    ) -> Result<SecretBytes, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        let entry_ref = &reference.entry;
        if live.id != entry_ref.session || live.generation != entry_ref.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &entry_ref.locator, entry_ref.id)?;
        let index = unique_field_index(entry, &reference.name)?;
        if index != reference.index {
            return Err(ServiceError::Stale);
        }
        entry.fields[index]
            .value
            .reveal_bytes()
            .map_err(|_| ServiceError::Unlock)
    }

    /// Explicitly reveals one exact standard or custom field as zeroizing bytes.
    ///
    /// Duplicate exact field names anywhere in the entry fail closed, including
    /// duplicates of standard field names. The returned value is the sole
    /// reveal result; projections and diagnostics never include field values.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::Ambiguous`] for duplicate exact names,
    /// [`ServiceError::NotFound`] for an unknown field, or
    /// [`ServiceError::Unlock`] if a protected value cannot be revealed.
    pub fn reveal_field(
        &self,
        reference: &EntryRef,
        field_name: &str,
    ) -> Result<SecretBytes, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        let mut index = None;
        for (field_index, field) in entry.fields.iter().enumerate() {
            if field.key == field_name && index.replace(field_index).is_some() {
                return Err(ServiceError::Ambiguous);
            }
        }
        match field_name {
            "Password" => match index {
                Some(index) => entry.fields[index]
                    .value
                    .reveal_bytes()
                    .map_err(|_| ServiceError::Unlock),
                None => entry
                    .password
                    .reveal_bytes()
                    .map_err(|_| ServiceError::Unlock),
            },
            "Title" => Ok(SecretBytes::from_vec(entry.title.as_bytes().to_vec())),
            "UserName" | "URL" | "Notes" => {
                if let Some(index) = index {
                    entry.fields[index]
                        .value
                        .reveal_bytes()
                        .map_err(|_| ServiceError::Unlock)
                } else {
                    let value = match field_name {
                        "UserName" => &entry.username,
                        "URL" => &entry.url,
                        "Notes" => &entry.notes,
                        _ => unreachable!("the match arm enumerates the standard text fields"),
                    };
                    Ok(SecretBytes::from_vec(value.as_bytes().to_vec()))
                }
            }
            _ => entry
                .fields
                .get(index.ok_or(ServiceError::NotFound)?)
                .ok_or(ServiceError::NotFound)?
                .value
                .reveal_bytes()
                .map_err(|_| ServiceError::Unlock),
        }
    }

    /// Reveals the native `KeePass` projection for one exact selected field.
    ///
    /// The duplicate-name check matches the explicit CLI read contract, but
    /// standard fields return their native projection rather than a serialized
    /// same-named custom field. This distinction is needed by `secrets env`;
    /// `exec` deliberately uses [`Self::reveal_field`] after projection
    /// normalization instead.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired handle,
    /// [`ServiceError::Ambiguous`] for duplicate exact names,
    /// [`ServiceError::NotFound`] for an unknown custom field, or
    /// [`ServiceError::Unlock`] if a protected value cannot be revealed.
    pub fn reveal_native_field(
        &self,
        reference: &EntryRef,
        field_name: &str,
    ) -> Result<neotales_keepass::SecretBytes, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        let mut index = None;
        for (field_index, field) in entry.fields.iter().enumerate() {
            if field.key == field_name && index.replace(field_index).is_some() {
                return Err(ServiceError::Ambiguous);
            }
        }
        match field_name {
            "Password" => entry
                .password
                .reveal_bytes()
                .map_err(|_| ServiceError::Unlock),
            "Title" => Ok(neotales_keepass::SecretBytes::from_vec(
                entry.title.as_bytes().to_vec(),
            )),
            "UserName" => Ok(neotales_keepass::SecretBytes::from_vec(
                entry.username.as_bytes().to_vec(),
            )),
            "URL" => Ok(neotales_keepass::SecretBytes::from_vec(
                entry.url.as_bytes().to_vec(),
            )),
            "Notes" => Ok(neotales_keepass::SecretBytes::from_vec(
                entry.notes.as_bytes().to_vec(),
            )),
            _ => entry
                .fields
                .get(index.ok_or(ServiceError::NotFound)?)
                .ok_or(ServiceError::NotFound)?
                .value
                .reveal_bytes()
                .map_err(|_| ServiceError::Unlock),
        }
    }

    /// Reveals the entry's default password binding as zeroizing bytes.
    ///
    /// This matches the KDBX standard-field projection used by `exec` without
    /// exposing the entry model. If malformed input repeats `Password`, the
    /// first serialized value remains authoritative, as in the CLI's former
    /// projection-normalization path.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Stale`] for an expired reference and
    /// [`ServiceError::Unlock`] if the selected protected value cannot be
    /// revealed.
    pub fn reveal_password(
        &self,
        reference: &EntryRef,
    ) -> Result<neotales_keepass::SecretBytes, ServiceError> {
        let live = self.session.as_ref().ok_or(ServiceError::Stale)?;
        if live.id != reference.session || live.generation != reference.generation {
            return Err(ServiceError::Stale);
        }
        let entry = resolve_locator(&live.database, &reference.locator, reference.id)?;
        entry
            .fields
            .iter()
            .find(|field| field.key == "Password")
            .map_or_else(
                || {
                    entry
                        .password
                        .reveal_bytes()
                        .map_err(|_| ServiceError::Unlock)
                },
                |field| field.value.reveal_bytes().map_err(|_| ServiceError::Unlock),
            )
    }
}

fn install_new_vault(
    path: &Path,
    write: impl FnOnce(&mut tempfile::NamedTempFile) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    install_new_vault_with_durability(path, write, |parent| {
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ServiceError::CreateDurability)?;
        #[cfg(not(unix))]
        let _ = parent;
        Ok(())
    })
}

fn install_new_vault_with_durability(
    path: &Path,
    write: impl FnOnce(&mut tempfile::NamedTempFile) -> Result<(), ServiceError>,
    confirm_durability: impl FnOnce(&Path) -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .map_err(|_| ServiceError::CreateDirectory)?;
    }

    let mut staged =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| ServiceError::CreateStage)?;
    crate::private_file::set_owner_only(staged.path(), "cannot set vault permissions")
        .map_err(|cause| permission_failure(cause, ServiceError::CreatePermissions))?;
    write(&mut staged)?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| ServiceError::CreateSync)?;
    staged
        .persist_noclobber(path)
        .map_err(|_| ServiceError::CreateExists)?;
    confirm_durability(parent)?;
    Ok(())
}

fn custom_field_descriptors(entry: &Entry, reference: &EntryRef) -> Vec<CustomFieldDescriptor> {
    let mut fields = Vec::new();
    for (index, field) in entry.fields.iter().enumerate() {
        if is_standard_field(&field.key) {
            continue;
        }
        fields.push(CustomFieldDescriptor {
            name: field.key.clone(),
            protected: field.protected,
            protect_in_memory: field.protect_in_memory,
            reference: CustomFieldRef {
                entry: reference.clone(),
                index,
                name: field.key.clone(),
            },
        });
    }
    fields
}

fn unique_field_index(entry: &Entry, name: &str) -> Result<usize, ServiceError> {
    let mut found = None;
    for (index, field) in entry.fields.iter().enumerate() {
        if field.key == name && found.replace(index).is_some() {
            return Err(ServiceError::Ambiguous);
        }
    }
    found.ok_or(ServiceError::NotFound)
}

fn is_standard_field(name: &str) -> bool {
    matches!(name, "Title" | "UserName" | "Password" | "URL" | "Notes")
}

fn split_entry_path(path: &str) -> Result<(Vec<&str>, &str), ServiceError> {
    if path.is_empty()
        || path.len() > MAX_HIT_BYTES
        || path.starts_with('/')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ServiceError::InvalidInput);
    }
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() > MAX_CREATE_GROUPS + 1
        || segments
            .iter()
            .any(|part| part.len() > MAX_TREE_LABEL_BYTES)
    {
        return Err(ServiceError::InvalidInput);
    }
    let (title, groups) = segments.split_last().ok_or(ServiceError::InvalidInput)?;
    Ok((groups.to_vec(), title))
}

struct GroupPlan<'a> {
    locator: Vec<usize>,
    missing: Vec<&'a str>,
    path_bytes: usize,
}

fn plan_group_path<'a>(root: &Group, segments: &[&'a str]) -> Result<GroupPlan<'a>, ServiceError> {
    if segments.len() > MAX_CREATE_GROUPS
        || segments.iter().map(|name| name.len() + 1).sum::<usize>() > MAX_HIT_BYTES
        || segments.iter().any(|name| {
            name.is_empty()
                || name.len() > MAX_TREE_LABEL_BYTES
                || matches!(*name, "." | "..")
                || !safe_metadata(name)
        })
    {
        return Err(ServiceError::InvalidInput);
    }
    let start = if segments
        .first()
        .is_some_and(|name| name.eq_ignore_ascii_case(&root.name))
    {
        // Keep a unique existing parent route. Do not guess a missing parent route.
        if root
            .groups
            .iter()
            .any(|child| child.name.eq_ignore_ascii_case(&root.name))
        {
            match group_path_start(root, segments) {
                Ok(start) => start,
                Err(ServiceError::NotFound) => return Err(ServiceError::Ambiguous),
                Err(error) => return Err(error),
            }
        } else {
            1
        }
    } else {
        0
    };
    if segments.len() - start + 1 > MAX_CREATE_GROUPS {
        return Err(ServiceError::InvalidInput);
    }
    let path_bytes = root.name.len()
        + segments[start..]
            .iter()
            .map(|name| name.len() + 1)
            .sum::<usize>();
    if path_bytes > MAX_HIT_BYTES {
        return Err(ServiceError::InvalidInput);
    }
    let mut group = root;
    let mut locator = Vec::new();
    for (offset, segment) in segments[start..].iter().enumerate() {
        let mut matches = group
            .groups
            .iter()
            .enumerate()
            .filter(|(_, child)| child.name.eq_ignore_ascii_case(segment));
        let found = matches.next();
        if matches.next().is_some() {
            return Err(ServiceError::Ambiguous);
        }
        let Some((index, child)) = found else {
            return Ok(GroupPlan {
                locator,
                missing: segments[start + offset..].to_vec(),
                path_bytes,
            });
        };
        locator.push(index);
        group = child;
    }
    Ok(GroupPlan {
        locator,
        missing: Vec::new(),
        path_bytes,
    })
}

fn apply_group_plan<'a>(root: &'a mut Group, plan: &GroupPlan<'_>) -> &'a mut Group {
    let mut group = root;
    for &index in &plan.locator {
        group = &mut group.groups[index];
    }
    for &name in &plan.missing {
        group.add_group(Group::new(name));
        let index = group.groups.len() - 1;
        group = &mut group.groups[index];
    }
    group
}

fn resolve_group_path<'a>(root: &'a Group, segments: &[&str]) -> Result<&'a Group, ServiceError> {
    let start = group_path_start(root, segments)?;
    resolve_group_path_relative(root, &segments[start..])
}

fn resolve_group_path_relative<'a>(
    root: &'a Group,
    segments: &[&str],
) -> Result<&'a Group, ServiceError> {
    let mut group = root;
    for segment in segments {
        let mut found = None;
        for (index, child) in group.groups.iter().enumerate() {
            if child.name.is_empty() || child.name.contains('/') {
                continue;
            }
            if child.name.eq_ignore_ascii_case(segment) {
                if found.is_some() {
                    return Err(ServiceError::Ambiguous);
                }
                found = Some(index);
            }
        }
        group = group
            .groups
            .get(found.ok_or(ServiceError::NotFound)?)
            .ok_or(ServiceError::NotFound)?;
    }
    Ok(group)
}

fn group_path_start(root: &Group, segments: &[&str]) -> Result<usize, ServiceError> {
    if segments.is_empty() {
        return Ok(0);
    }
    if !segments[0].eq_ignore_ascii_case(&root.name) {
        return match resolve_group_path_candidates(root, segments).as_slice() {
            [] => Err(ServiceError::NotFound),
            [_] => Ok(0),
            _ => Err(ServiceError::Ambiguous),
        };
    }
    let implicit = resolve_group_path_candidates(root, segments);
    let explicit = resolve_group_path_candidates(root, &segments[1..]);
    let mut candidates = Vec::new();
    for candidate in implicit.iter().chain(&explicit).copied() {
        if !candidates
            .iter()
            .any(|existing| std::ptr::eq(*existing, candidate))
        {
            candidates.push(candidate);
        }
    }
    match candidates.as_slice() {
        [] => Err(ServiceError::NotFound),
        [candidate]
            if explicit
                .iter()
                .any(|group| std::ptr::eq(*group, *candidate)) =>
        {
            Ok(1)
        }
        [_] => Ok(0),
        _ => Err(ServiceError::Ambiguous),
    }
}

fn entry_path_start(root: &Group, segments: &[&str]) -> Result<usize, ServiceError> {
    if segments.len() < 2 {
        return Ok(0);
    }
    if !segments[0].eq_ignore_ascii_case(&root.name) {
        return if entry_path_candidates(root, segments).is_empty() {
            Err(ServiceError::NotFound)
        } else {
            Ok(0)
        };
    }
    let implicit = entry_path_candidates(root, segments);
    let explicit = entry_path_candidates(root, &segments[1..]);
    match (implicit.is_empty(), explicit.is_empty()) {
        (false, false) => Err(ServiceError::Ambiguous),
        (false, true) => Ok(0),
        (true, false) => Ok(1),
        (true, true) => Err(ServiceError::NotFound),
    }
}

fn resolve_group_path_candidates<'a>(root: &'a Group, segments: &[&str]) -> Vec<&'a Group> {
    let mut groups = vec![root];
    for segment in segments {
        groups = groups
            .into_iter()
            .flat_map(|group| {
                group.groups.iter().filter(move |child| {
                    !child.name.is_empty()
                        && !child.name.contains('/')
                        && child.name.eq_ignore_ascii_case(segment)
                })
            })
            .collect();
        if groups.is_empty() {
            break;
        }
    }
    groups
}

fn has_ambiguous_group_prefix(root: &Group, segments: &[&str]) -> bool {
    let mut groups = vec![root];
    for segment in segments {
        let mut next = Vec::new();
        for group in groups {
            let mut matches = group.groups.iter().filter(|child| {
                !child.name.is_empty()
                    && !child.name.contains('/')
                    && child.name.eq_ignore_ascii_case(segment)
            });
            if let Some(first) = matches.next() {
                if matches.next().is_some() {
                    return true;
                }
                next.push(first);
            }
        }
        if next.is_empty() {
            break;
        }
        if next.len() > 1 {
            return true;
        }
        groups = next;
    }
    false
}

fn entry_path_candidates<'a>(root: &'a Group, segments: &[&str]) -> Vec<&'a Entry> {
    let Some((title, groups)) = segments.split_last() else {
        return Vec::new();
    };
    resolve_group_path_candidates(root, groups)
        .into_iter()
        .flat_map(|group| {
            group.entries.iter().filter(move |entry| {
                !entry.title.is_empty()
                    && !entry.title.contains('/')
                    && entry.title.eq_ignore_ascii_case(title)
            })
        })
        .collect()
}

fn existing_entry_candidate<'a>(
    root: &'a Group,
    segments: &[&str],
) -> Result<Option<&'a Entry>, ServiceError> {
    let start = match entry_path_start(root, segments) {
        Ok(start) => start,
        Err(ServiceError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if has_ambiguous_group_prefix(root, &segments[start..segments.len() - 1]) {
        return Err(ServiceError::Ambiguous);
    }
    let path_bytes = root.name.len()
        + segments[start..]
            .iter()
            .map(|part| part.len() + 1)
            .sum::<usize>();
    if path_bytes > MAX_HIT_BYTES {
        return Err(ServiceError::InvalidInput);
    }
    let candidates = entry_path_candidates(root, &segments[start..]);
    let mut unique: Vec<&Entry> = Vec::new();
    for candidate in candidates {
        if !unique
            .iter()
            .any(|existing| std::ptr::eq(*existing, candidate))
        {
            unique.push(candidate);
        }
    }
    match unique.as_slice() {
        [] => Ok(None),
        [entry] => Ok(Some(*entry)),
        _ => Err(ServiceError::Ambiguous),
    }
}

struct EnsureFill {
    id: KdbxUuid,
    size: usize,
}

struct EnsurePlan {
    fills: Vec<EnsureFill>,
    kept: usize,
}

#[derive(Default)]
struct EnsureOutcome {
    generated: usize,
    kept: usize,
    pending: usize,
}

impl EnsurePlan {
    fn dry_run(&self) -> EnsureOutcome {
        EnsureOutcome {
            kept: self.kept,
            pending: self.fills.len(),
            ..EnsureOutcome::default()
        }
    }
}

fn entry_by_id(database: &KeePassDatabase, id: KdbxUuid) -> Option<&Entry> {
    fn walk(group: &Group, id: KdbxUuid) -> Option<&Entry> {
        group
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .or_else(|| group.groups.iter().find_map(|child| walk(child, id)))
    }
    walk(&database.root, id)
}

fn entry_by_id_mut(database: &mut KeePassDatabase, id: KdbxUuid) -> Option<&mut Entry> {
    fn walk(group: &mut Group, id: KdbxUuid) -> Option<&mut Entry> {
        if let Some(entry) = group.entries.iter_mut().find(|entry| entry.id == id) {
            return Some(entry);
        }
        group.groups.iter_mut().find_map(|child| walk(child, id))
    }
    walk(&mut database.root, id)
}

fn carry_ensured_passwords(
    target: &KeePassDatabase,
    incoming: &mut KeePassDatabase,
    directives: &[interchange::EnsureDirective],
) -> Result<(), AutomationError> {
    for directive in directives {
        let Some(held) = entry_by_id(target, directive.id) else {
            continue;
        };
        if held.password.is_empty() {
            continue;
        }
        if let Some(entry) = entry_by_id_mut(incoming, directive.id)
            && entry.password.is_empty()
        {
            set_ensured_password(entry, held.password.clone())?;
        }
    }
    Ok(())
}

fn plan_ensure(
    database: &KeePassDatabase,
    directives: &[interchange::EnsureDirective],
) -> Result<EnsurePlan, AutomationError> {
    let mut plan = EnsurePlan {
        fills: Vec::with_capacity(directives.len()),
        kept: 0,
    };
    for directive in directives {
        let size = usize::try_from(directive.size)
            .ok()
            .filter(|size| (1..=4096).contains(size))
            .ok_or_else(|| {
                AutomationError::owned(format!(
                    "ensure size is {} characters; the allowed range is 1 to 4096",
                    directive.size
                ))
            })?;
        let entry = entry_by_id(database, directive.id)
            .ok_or_else(|| AutomationError::fixed("ensure directive does not name an entry"))?;
        if entry.password.is_empty() {
            plan.fills.push(EnsureFill {
                id: directive.id,
                size,
            });
        } else {
            plan.kept += 1;
        }
    }
    Ok(plan)
}

fn apply_ensure(
    database: &mut KeePassDatabase,
    plan: &EnsurePlan,
) -> Result<EnsureOutcome, AutomationError> {
    let mut outcome = EnsureOutcome {
        kept: plan.kept,
        ..EnsureOutcome::default()
    };
    for fill in &plan.fills {
        let entry = entry_by_id_mut(database, fill.id)
            .ok_or_else(|| AutomationError::fixed("ensure directive does not name an entry"))?;
        if !entry.password.is_empty() {
            outcome.kept += 1;
            continue;
        }
        let mut password = Zeroizing::new(
            generate_password(fill.size)
                .map_err(|error| AutomationError::fixed(error.message()))?,
        );
        set_ensured_password(
            entry,
            ProtectedValue::from_text(std::mem::take(&mut *password)),
        )?;
        outcome.generated += 1;
    }
    Ok(outcome)
}

fn set_ensured_password(entry: &mut Entry, value: ProtectedValue) -> Result<(), AutomationError> {
    if entry
        .fields
        .iter()
        .filter(|field| field.key == "Password")
        .count()
        > 1
    {
        return Err(AutomationError::fixed("entry contains duplicate fields"));
    }
    entry.password = value.clone();
    if let Some(field) = entry
        .fields
        .iter_mut()
        .find(|field| field.key == "Password")
    {
        field.value = value;
        field.protected = true;
        field.protect_in_memory = true;
    }
    Ok(())
}

fn generate_password(size: usize) -> Result<String, ServiceError> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut password = Zeroizing::new(String::with_capacity(size));
    while password.len() < size {
        let mut random = Zeroizing::new(vec![0_u8; size - password.len()]);
        getrandom::fill(&mut random).map_err(|_| ServiceError::RandomGeneration)?;
        for byte in random.iter().copied().filter(|byte| *byte < 248) {
            password.push(ALPHABET[usize::from(byte) % ALPHABET.len()] as char);
            if password.len() == size {
                break;
            }
        }
    }
    Ok(std::mem::take(&mut *password))
}

fn account_completion_text(text_work: &mut usize, bytes: usize) -> Result<(), ServiceError> {
    if bytes > MAX_COMPLETION_PATH_BYTES {
        return Err(ServiceError::ResourceLimit);
    }
    *text_work = text_work
        .checked_add(bytes)
        .ok_or(ServiceError::ResourceLimit)?;
    if *text_work > MAX_COMPLETION_BYTES {
        return Err(ServiceError::ResourceLimit);
    }
    Ok(())
}

// Standard fields have redundant fields-model projections in this application.
// Keep their load/save reconciliation inside the service for the routed slice.
fn normalize_standard_projections(database: &mut KeePassDatabase) {
    fn visit_entry(entry: &mut Entry) {
        if let Some(field) = entry.field("Password") {
            entry.password = field.value.clone();
        }
        let standard_text = ["UserName", "URL", "Notes"].map(|name| {
            entry
                .field(name)
                .and_then(|field| field.value.reveal_text().ok())
                .map(|value| value.as_str().to_owned())
        });
        if let Some(value) = &standard_text[0] {
            entry.username.clone_from(value);
        }
        if let Some(value) = &standard_text[1] {
            entry.url.clone_from(value);
        }
        if let Some(value) = &standard_text[2] {
            entry.notes.clone_from(value);
        }
        for snapshot in &mut entry.history {
            visit_entry(snapshot);
        }
    }
    fn visit_group(group: &mut Group) {
        for entry in &mut group.entries {
            visit_entry(entry);
        }
        for child in &mut group.groups {
            visit_group(child);
        }
    }
    visit_group(&mut database.root);
}

fn prepare_standard_fields_for_save(database: &mut KeePassDatabase) {
    fn visit_entry(entry: &mut Entry) {
        if entry.field("Password").is_some() {
            entry.password = ProtectedValue::from_text(String::new());
        }
        for snapshot in &mut entry.history {
            visit_entry(snapshot);
        }
    }
    fn visit_group(group: &mut Group) {
        for entry in &mut group.entries {
            visit_entry(entry);
        }
        for child in &mut group.groups {
            visit_group(child);
        }
    }
    visit_group(&mut database.root);
}

fn validate_unique_object_ids(database: &KeePassDatabase) -> Result<(), ServiceError> {
    fn visit_entry(item: &Entry, ids: &mut BTreeSet<KdbxUuid>) -> Result<(), ServiceError> {
        if !ids.insert(item.id) {
            return Err(ServiceError::DuplicateIds);
        }
        for snapshot in &item.history {
            visit_entry(snapshot, ids)?;
        }
        Ok(())
    }
    fn visit_group(item: &Group, ids: &mut BTreeSet<KdbxUuid>) -> Result<(), ServiceError> {
        if !ids.insert(item.id) {
            return Err(ServiceError::DuplicateIds);
        }
        for entry in &item.entries {
            visit_entry(entry, ids)?;
        }
        for child in &item.groups {
            visit_group(child, ids)?;
        }
        Ok(())
    }
    visit_group(&database.root, &mut BTreeSet::new())
}

fn validate_unique_field_names(database: &KeePassDatabase) -> Result<(), ServiceError> {
    fn visit_entry(item: &Entry) -> Result<(), ServiceError> {
        let mut names = BTreeSet::new();
        for field in &item.fields {
            if !names.insert(field.key.as_str()) {
                return Err(ServiceError::DuplicateFields);
            }
        }
        for snapshot in &item.history {
            visit_entry(snapshot)?;
        }
        Ok(())
    }
    fn visit_group(item: &Group) -> Result<(), ServiceError> {
        for entry in &item.entries {
            visit_entry(entry)?;
        }
        for child in &item.groups {
            visit_group(child)?;
        }
        Ok(())
    }
    visit_group(&database.root)
}

// The pinned serializer emits Times with child values at every group and entry.
// CustomData items and auto-type associations add three levels below an entry;
// each nested History/Entry pair adds two more levels.
fn validate_xml_depth(root: &Group) -> Result<(), ServiceError> {
    fn entry_depth(entry: &Entry, depth: usize, limit: usize) -> Result<(), ServiceError> {
        let fields =
            if entry.custom_data.items().is_empty() && entry.auto_type.associations.is_empty() {
                2
            } else {
                3
            };
        if depth + fields > limit {
            return Err(ServiceError::XmlDepth);
        }
        for snapshot in &entry.history {
            entry_depth(snapshot, depth + 2, limit)?;
        }
        Ok(())
    }

    fn group_depth(group: &Group, depth: usize, limit: usize) -> Result<(), ServiceError> {
        let fields = if group.custom_data.items().is_empty() {
            2
        } else {
            3
        };
        if depth + fields > limit {
            return Err(ServiceError::XmlDepth);
        }
        for entry in &group.entries {
            entry_depth(entry, depth + 1, limit)?;
        }
        for child in &group.groups {
            group_depth(child, depth + 1, limit)?;
        }
        Ok(())
    }

    // KeePassFile/Root precede the root Group. Checks bound recursion before descent.
    group_depth(root, 3, crate::KDBX_LIMITS.max_xml_depth)
}

fn validate_save_model(database: &KeePassDatabase) -> Result<(), ServiceError> {
    validate_xml_depth(&database.root)?;
    validate_unique_object_ids(database)?;
    validate_unique_field_names(database)?;
    if !database.can_save_losslessly {
        return Err(ServiceError::Save);
    }
    validate_attachment_references(database).map_err(|_| ServiceError::InvalidAttachmentReference)
}

fn set_entry_field(entry: &mut Entry, name: &str, value: &str) -> Result<(), ServiceError> {
    if entry
        .fields
        .iter()
        .filter(|field| field.key == name)
        .count()
        > 1
    {
        return Err(ServiceError::AmbiguousField);
    }
    match name {
        "Password" => {
            let protected = ProtectedValue::from_text(value.to_owned());
            entry.password = protected.clone();
            if entry.fields.iter().any(|field| field.key == name) {
                entry.set_field(Field {
                    key: name.to_owned(),
                    value: protected,
                    protected: true,
                    protect_in_memory: true,
                });
            }
        }
        "UserName" => {
            value.clone_into(&mut entry.username);
            if entry.fields.iter().any(|field| field.key == name) {
                entry.set_field(Field::new(name, value.to_owned()));
            }
        }
        "URL" => {
            value.clone_into(&mut entry.url);
            if entry.fields.iter().any(|field| field.key == name) {
                entry.set_field(Field::new(name, value.to_owned()));
            }
        }
        "Notes" => {
            value.clone_into(&mut entry.notes);
            if entry.fields.iter().any(|field| field.key == name) {
                entry.set_field(Field::new(name, value.to_owned()));
            }
        }
        "Title" => return Err(ServiceError::FieldConflict),
        _ => entry.set_field(Field {
            key: name.to_owned(),
            value: ProtectedValue::from_text(value.to_owned()),
            protected: true,
            protect_in_memory: true,
        }),
    }
    Ok(())
}

#[cfg(unix)]
fn confirm_durable(parent: &Path) -> Result<(), ServiceError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ServiceError::SaveDurability)
}

#[cfg(not(unix))]
fn confirm_durable() {}

fn save_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn resolve_locator_mut<'a>(
    database: &'a mut KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<&'a mut Entry, ServiceError> {
    let (entry_index, group_indices) = locator.split_last().ok_or(ServiceError::NotFound)?;
    fn descend<'a>(group: &'a mut Group, indices: &[usize]) -> Result<&'a mut Group, ServiceError> {
        let Some((&index, rest)) = indices.split_first() else {
            return Ok(group);
        };
        descend(
            group.groups.get_mut(index).ok_or(ServiceError::Stale)?,
            rest,
        )
    }
    let group = descend(&mut database.root, group_indices)?;
    let entry = group
        .entries
        .get_mut(*entry_index)
        .ok_or(ServiceError::Stale)?;
    if entry.id != id {
        return Err(ServiceError::Stale);
    }
    Ok(entry)
}

fn remove_locator(
    database: &mut KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<(), ServiceError> {
    let (entry_index, group_indices) = locator.split_last().ok_or(ServiceError::NotFound)?;
    fn descend_mut<'a>(
        group: &'a mut Group,
        indices: &[usize],
    ) -> Result<&'a mut Group, ServiceError> {
        let Some((&index, rest)) = indices.split_first() else {
            return Ok(group);
        };
        descend_mut(
            group.groups.get_mut(index).ok_or(ServiceError::Stale)?,
            rest,
        )
    }
    let group = descend_mut(&mut database.root, group_indices)?;
    let entry = group.entries.get(*entry_index).ok_or(ServiceError::Stale)?;
    if entry.id != id {
        return Err(ServiceError::Stale);
    }
    group.entries.remove(*entry_index);
    Ok(())
}

fn prune_attachments(database: &mut KeePassDatabase) -> Result<(), ServiceError> {
    fn collect_entry(entry: &Entry, used: &mut BTreeSet<usize>) {
        for attachment in &entry.attachments {
            used.insert(attachment.reference);
        }
        for past in &entry.history {
            collect_entry(past, used);
        }
    }
    fn collect_group(group: &Group, used: &mut BTreeSet<usize>) {
        for entry in &group.entries {
            collect_entry(entry, used);
        }
        for child in &group.groups {
            collect_group(child, used);
        }
    }
    fn remap_entry(entry: &mut Entry, mapping: &HashMap<usize, usize>) {
        for attachment in &mut entry.attachments {
            attachment.reference = mapping[&attachment.reference];
        }
        for past in &mut entry.history {
            remap_entry(past, mapping);
        }
    }
    fn remap_group(group: &mut Group, mapping: &HashMap<usize, usize>) {
        for entry in &mut group.entries {
            remap_entry(entry, mapping);
        }
        for child in &mut group.groups {
            remap_group(child, mapping);
        }
    }

    let mut used = BTreeSet::new();
    collect_group(&database.root, &mut used);
    let mut pool = neotales_keepass::BinaryPool::default();
    let mut mapping = HashMap::new();
    for old in used {
        let record = database
            .binary_pool
            .get(old)
            .ok_or(ServiceError::InvalidAttachmentReference)?;
        mapping.insert(old, pool.add(record.data.clone(), record.protected));
    }
    remap_group(&mut database.root, &mapping);
    database.binary_pool = pool;
    database.meta.legacy_binaries.clear();
    Ok(())
}

fn validate_attachment_references(database: &KeePassDatabase) -> Result<(), ServiceError> {
    fn entry_references_valid(
        database: &KeePassDatabase,
        entry: &Entry,
    ) -> Result<(), ServiceError> {
        for attachment in &entry.attachments {
            database
                .binary_pool
                .get(attachment.reference)
                .ok_or(ServiceError::NotFound)?;
        }
        for past in &entry.history {
            entry_references_valid(database, past)?;
        }
        Ok(())
    }
    fn group_references_valid(
        database: &KeePassDatabase,
        group: &Group,
    ) -> Result<(), ServiceError> {
        for entry in &group.entries {
            entry_references_valid(database, entry)?;
        }
        for child in &group.groups {
            group_references_valid(database, child)?;
        }
        Ok(())
    }
    group_references_valid(database, &database.root)
}

fn resolve_group_locator<'a>(
    database: &'a KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<&'a Group, ServiceError> {
    let mut group = &database.root;
    for &index in locator {
        group = group.groups.get(index).ok_or(ServiceError::Stale)?;
    }
    if group.id != id {
        return Err(ServiceError::Stale);
    }
    Ok(group)
}

fn resolve_group_locator_mut<'a>(
    database: &'a mut KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<&'a mut Group, ServiceError> {
    fn descend<'a>(group: &'a mut Group, locator: &[usize]) -> Result<&'a mut Group, ServiceError> {
        let Some((&index, rest)) = locator.split_first() else {
            return Ok(group);
        };
        descend(
            group.groups.get_mut(index).ok_or(ServiceError::Stale)?,
            rest,
        )
    }
    let group = descend(&mut database.root, locator)?;
    if group.id != id {
        return Err(ServiceError::Stale);
    }
    Ok(group)
}

fn find_group_locator(
    current: &Group,
    target: &Group,
    locator: &mut Vec<usize>,
    depth: usize,
) -> Result<bool, ServiceError> {
    if std::ptr::eq(current, target) {
        return Ok(true);
    }
    if depth >= MAX_LOCATOR_DEPTH {
        return Err(ServiceError::ResourceLimit);
    }
    for (index, child) in current.groups.iter().enumerate() {
        locator.push(index);
        if find_group_locator(child, target, locator, depth + 1)? {
            return Ok(true);
        }
        locator.pop();
    }
    Ok(false)
}

fn remove_group_locator(
    database: &mut KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<(), ServiceError> {
    let Some((&group_index, parent_locator)) = locator.split_last() else {
        return Err(ServiceError::RootGroup);
    };
    fn descend<'a>(group: &'a mut Group, locator: &[usize]) -> Result<&'a mut Group, ServiceError> {
        let Some((&index, rest)) = locator.split_first() else {
            return Ok(group);
        };
        descend(
            group.groups.get_mut(index).ok_or(ServiceError::Stale)?,
            rest,
        )
    }
    let parent = descend(&mut database.root, parent_locator)?;
    if parent
        .groups
        .get(group_index)
        .ok_or(ServiceError::Stale)?
        .id
        != id
    {
        return Err(ServiceError::Stale);
    }
    parent.groups.remove(group_index);
    Ok(())
}

fn group_path_context(
    database: &KeePassDatabase,
    locator: &[usize],
) -> Result<String, ServiceError> {
    let mut group = &database.root;
    let mut path = String::new();
    if !group.name.is_empty() {
        if group.name.len() > MAX_TREE_LABEL_BYTES || group.name.len() > MAX_HIT_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        if !safe_metadata(&group.name) {
            return Err(ServiceError::InvalidInput);
        }
        path.push_str(&group.name);
    }
    for &index in locator {
        group = group.groups.get(index).ok_or(ServiceError::Stale)?;
        if group.name.is_empty() || group.name.len() > MAX_TREE_LABEL_BYTES {
            return Err(ServiceError::InvalidInput);
        }
        let path_len = path
            .len()
            .saturating_add(usize::from(!path.is_empty()))
            .saturating_add(group.name.len());
        if path_len > MAX_HIT_BYTES {
            return Err(ServiceError::ResourceLimit);
        }
        if !safe_metadata(&group.name) {
            return Err(ServiceError::InvalidInput);
        }
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(&group.name);
    }
    Ok(path)
}

fn resolve_locator<'a>(
    database: &'a KeePassDatabase,
    locator: &[usize],
    id: KdbxUuid,
) -> Result<&'a Entry, ServiceError> {
    let (entry_index, group_indices) = locator.split_last().ok_or(ServiceError::NotFound)?;
    let mut group = &database.root;
    for &group_index in group_indices {
        group = group.groups.get(group_index).ok_or(ServiceError::Stale)?;
    }
    let entry = group.entries.get(*entry_index).ok_or(ServiceError::Stale)?;
    if entry.id != id {
        return Err(ServiceError::Stale);
    }
    Ok(entry)
}

#[derive(Clone, Copy)]
struct GroupFrame {
    group_index: Option<usize>,
    next_entry: usize,
    next_child: usize,
    entered: bool,
    path_matches: bool,
    path_safe: bool,
    path_bytes: usize,
}

struct SearchState {
    query: String,
    needle: Vec<char>,
    failure: Vec<usize>,
    stack: Vec<GroupFrame>,
    session: SessionId,
    generation: u64,
    total_work: usize,
    total_text_work: usize,
}

struct ListState {
    pattern: Option<String>,
    glob: Option<Glob>,
    stack: Vec<GroupFrame>,
    session: SessionId,
    generation: u64,
    total_work: usize,
    total_text_work: usize,
    total_glob_work: usize,
}

impl ListState {
    fn new(pattern: Option<&str>, session: SessionId, generation: u64) -> Self {
        Self {
            pattern: pattern.map(str::to_owned),
            glob: pattern.map(Glob::new),
            stack: vec![GroupFrame {
                group_index: None,
                next_entry: 0,
                next_child: 0,
                entered: false,
                path_matches: false,
                path_safe: true,
                path_bytes: 0,
            }],
            session,
            generation,
            total_work: 0,
            total_text_work: 0,
            total_glob_work: 0,
        }
    }

    fn has_more(&self) -> bool {
        !self.stack.is_empty()
    }
}

impl SearchState {
    fn new(query: &str, session: SessionId, generation: u64) -> Self {
        let needle = query.to_lowercase().chars().collect::<Vec<_>>();
        let failure = failure_table(&needle);
        Self {
            query: query.to_owned(),
            needle,
            failure,
            stack: vec![GroupFrame {
                group_index: None,
                next_entry: 0,
                next_child: 0,
                entered: false,
                path_matches: false,
                path_safe: true,
                path_bytes: 0,
            }],
            session,
            generation,
            total_work: 0,
            total_text_work: 0,
        }
    }

    fn has_more(&self) -> bool {
        !self.stack.is_empty()
    }
}

fn group_at<'a>(root: &'a Group, stack: &[GroupFrame]) -> &'a Group {
    let mut group = root;
    for frame in stack.iter().skip(1) {
        group = &group.groups[frame.group_index.expect("non-root frame")];
    }
    group
}

// Keep the iterative traversal and its budget accounting together so every
// cursor transition is visible in one place.
#[allow(clippy::too_many_lines)]
fn scan_page(root: &Group, state: &mut SearchState) -> Result<SearchPage, ServiceError> {
    let hit_capacity_bytes = MAX_RESULTS
        .checked_mul(std::mem::size_of::<SearchHit>())
        .and_then(|size| size.checked_add(std::mem::size_of::<Vec<SearchHit>>()))
        .ok_or(ServiceError::ResourceLimit)?;
    if hit_capacity_bytes > MAX_PAGE_BYTES {
        return Err(ServiceError::ResourceLimit);
    }
    let mut hits = Vec::new();
    hits.try_reserve_exact(MAX_RESULTS)
        .map_err(|_| ServiceError::ResourceLimit)?;
    let mut page = SearchPage {
        hits,
        withheld: 0,
        next_cursor: None,
    };
    // Includes the page's preallocated hit vector; hit estimates also count
    // their inline structure, intentionally conservative for partial pages.
    let mut bytes = hit_capacity_bytes;
    let mut work = 0usize;
    let mut text_work = 0usize;
    while !state.stack.is_empty() && work < MAX_PAGE_WORK {
        if state.total_work >= MAX_SEARCH_WORK {
            return Err(ServiceError::ResourceLimit);
        }
        let group = group_at(root, &state.stack);
        let frame_index = state.stack.len() - 1;
        if !state.stack[frame_index].entered {
            let cost = text_candidate_cost(group.name.len(), 1)?;
            if cost > MAX_PAGE_TEXT_WORK
                || cost > MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_text_work)
            {
                return Err(ServiceError::ResourceLimit);
            }
            if text_work.saturating_add(cost) > MAX_PAGE_TEXT_WORK {
                break;
            }
            text_work += cost;
            state.total_text_work += cost;
            let parent_matches = state.stack[..frame_index]
                .last()
                .is_some_and(|parent| parent.path_matches);
            let parent_path_safe = state.stack[..frame_index]
                .last()
                .is_none_or(|parent| parent.path_safe);
            state.stack[frame_index].path_matches =
                parent_matches || contains_lowercase(&group.name, &state.needle, &state.failure);
            // Validate each vault-controlled path component once, when its
            // frame is entered. This is covered by the group's existing text
            // work charge and avoids rescanning shared ancestors per entry.
            state.stack[frame_index].path_safe = parent_path_safe && safe_metadata(&group.name);
            let parent_path_bytes = state.stack[..frame_index]
                .last()
                .map_or(0, |parent| parent.path_bytes);
            state.stack[frame_index].path_bytes = parent_path_bytes
                .checked_add(usize::from(frame_index > 0))
                .and_then(|bytes| bytes.checked_add(group.name.len()))
                .ok_or(ServiceError::ResourceLimit)?;
            state.stack[frame_index].entered = true;
            work += 1;
            state.total_work += 1;
        } else if state.stack[frame_index].next_entry < group.entries.len() {
            let entry_index = state.stack[frame_index].next_entry;
            let entry = &group.entries[entry_index];
            let cost = entry_candidate_cost(
                entry,
                state.stack.len(),
                MAX_PAGE_TEXT_WORK.saturating_sub(text_work),
                MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_text_work),
            )?;
            let Some(cost) = cost else { break };
            text_work += cost;
            state.total_text_work += cost;
            state.stack[frame_index].next_entry += 1;
            work += 1;
            state.total_work += 1;
            let path_matches = state.stack[frame_index].path_matches;
            let matched = path_matches
                || [&entry.title, &entry.username, &entry.url]
                    .into_iter()
                    .chain(entry.tags.iter())
                    .any(|candidate| contains_lowercase(candidate, &state.needle, &state.failure));
            if !matched {
                continue;
            }
            let path = path_for(
                root,
                &state.stack,
                state.stack[frame_index].path_bytes,
                state.stack[frame_index].path_safe,
            );
            let mut locator = Vec::with_capacity(state.stack.len().saturating_sub(1));
            locator.extend(
                state
                    .stack
                    .iter()
                    .skip(1)
                    .filter_map(|frame| frame.group_index),
            );
            let remaining = MAX_PAGE_BYTES.saturating_sub(bytes);
            let Some((mut hit, hit_bytes)) = project_hit(
                entry,
                &path,
                &locator,
                state.session,
                state.generation,
                remaining,
            ) else {
                page.withheld += 1;
                continue;
            };
            bytes += hit_bytes;
            hit.reference.locator.push(entry_index);
            page.hits.push(hit);
            if page.hits.len() == MAX_RESULTS {
                break;
            }
        } else if state.stack[frame_index].next_child < group.groups.len()
            && state.stack.len() < MAX_LOCATOR_DEPTH
        {
            let child_index = state.stack[frame_index].next_child;
            state.stack[frame_index].next_child += 1;
            state.stack.push(GroupFrame {
                group_index: Some(child_index),
                next_entry: 0,
                next_child: 0,
                entered: false,
                path_matches: false,
                path_safe: true,
                path_bytes: 0,
            });
        } else {
            state.stack.pop();
        }
    }
    while let Some(frame) = state.stack.last().copied() {
        let group = group_at(root, &state.stack);
        if frame.entered
            && frame.next_entry == group.entries.len()
            && frame.next_child >= group.groups.len()
        {
            state.stack.pop();
        } else {
            break;
        }
    }
    Ok(page)
}

// Listing shares the iterative frame walk, cost accounting, safe projection,
// and page-memory bound with search, but deliberately has no result-count cap.
#[allow(clippy::too_many_lines)]
fn scan_list_page(root: &Group, state: &mut ListState) -> Result<ListPage, ServiceError> {
    let mut page = ListPage {
        hits: Vec::new(),
        withheld: 0,
        next_cursor: None,
    };
    let mut bytes = std::mem::size_of::<Vec<SearchHit>>();
    let mut work = 0usize;
    let mut text_work = 0usize;
    let mut glob_work = 0usize;
    while !state.stack.is_empty() && work < MAX_PAGE_WORK {
        if state.total_work >= MAX_SEARCH_WORK {
            return Err(ServiceError::ResourceLimit);
        }
        let group = group_at(root, &state.stack);
        let frame_index = state.stack.len() - 1;
        if !state.stack[frame_index].entered {
            let cost = text_candidate_cost(group.name.len(), 1)?;
            if cost > MAX_PAGE_TEXT_WORK
                || cost > MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_text_work)
            {
                return Err(ServiceError::ResourceLimit);
            }
            if text_work.saturating_add(cost) > MAX_PAGE_TEXT_WORK {
                break;
            }
            text_work += cost;
            state.total_text_work += cost;
            let parent_path_safe = state.stack[..frame_index]
                .last()
                .is_none_or(|parent| parent.path_safe);
            let parent_path_bytes = state.stack[..frame_index]
                .last()
                .map_or(0, |parent| parent.path_bytes);
            state.stack[frame_index].path_safe = parent_path_safe && safe_metadata(&group.name);
            state.stack[frame_index].path_bytes = parent_path_bytes
                .checked_add(usize::from(frame_index > 0))
                .and_then(|size| size.checked_add(group.name.len()))
                .ok_or(ServiceError::ResourceLimit)?;
            state.stack[frame_index].entered = true;
            work += 1;
            state.total_work += 1;
        } else if state.stack[frame_index].next_entry < group.entries.len() {
            let entry_index = state.stack[frame_index].next_entry;
            let entry = &group.entries[entry_index];
            let path_bytes = state.stack[frame_index]
                .path_bytes
                .checked_add(1)
                .and_then(|size| size.checked_add(entry.title.len()))
                .ok_or(ServiceError::ResourceLimit)?;
            let cost = entry_candidate_cost(
                entry,
                state.stack.len(),
                MAX_PAGE_TEXT_WORK.saturating_sub(text_work),
                MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_text_work),
            )?;
            let Some(cost) = cost else { break };
            // `render_path` allocates/copies the complete path for each row.
            // Account for all ancestor labels and the title, not just depth.
            let render_cost = text_candidate_cost(path_bytes, 1)?;
            let combined_cost = cost
                .checked_add(render_cost)
                .ok_or(ServiceError::ResourceLimit)?;
            if combined_cost > MAX_PAGE_TEXT_WORK || combined_cost > MAX_SEARCH_TEXT_WORK {
                return Err(ServiceError::ResourceLimit);
            }
            if combined_cost > MAX_PAGE_TEXT_WORK.saturating_sub(text_work)
                || combined_cost > MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_text_work)
            {
                break;
            }
            let glob_cost = state
                .glob
                .as_ref()
                .map(|glob| {
                    glob.work_bound(path_bytes)
                        .ok_or(ServiceError::ResourceLimit)
                })
                .transpose()?
                .unwrap_or(0);
            if glob_cost > MAX_PAGE_GLOB_WORK
                || glob_cost > MAX_SEARCH_TEXT_WORK.saturating_sub(state.total_glob_work)
            {
                return Err(ServiceError::ResourceLimit);
            }
            if glob_cost > MAX_PAGE_GLOB_WORK.saturating_sub(glob_work) {
                break;
            }
            text_work += combined_cost;
            state.total_text_work += combined_cost;
            glob_work += glob_cost;
            state.total_glob_work += glob_cost;
            state.stack[frame_index].next_entry += 1;
            work += 1;
            state.total_work += 1;

            let path = path_for(
                root,
                &state.stack,
                state.stack[frame_index].path_bytes,
                state.stack[frame_index].path_safe,
            );
            let candidate_path = render_path(&path, &entry.title);
            if state
                .glob
                .as_ref()
                .is_some_and(|glob| !glob.is_match(&candidate_path))
            {
                continue;
            }
            let mut locator = Vec::with_capacity(state.stack.len().saturating_sub(1));
            locator.extend(
                state
                    .stack
                    .iter()
                    .skip(1)
                    .filter_map(|frame| frame.group_index),
            );
            let projected = project_hit(
                entry,
                &path,
                &locator,
                state.session,
                state.generation,
                MAX_PAGE_BYTES.saturating_sub(bytes),
            );
            let Some((mut hit, hit_bytes)) = projected else {
                if project_hit(
                    entry,
                    &path,
                    &locator,
                    state.session,
                    state.generation,
                    MAX_PAGE_BYTES,
                )
                .is_some()
                {
                    // This safe projection belongs on the next page; it is not
                    // a withheld row merely because this page is full.
                    state.stack[frame_index].next_entry -= 1;
                    break;
                }
                page.withheld += 1;
                continue;
            };
            hit.reference.locator.push(entry_index);
            bytes += hit_bytes;
            page.hits
                .try_reserve_exact(1)
                .map_err(|_| ServiceError::ResourceLimit)?;
            page.hits.push(hit);
            if bytes >= MAX_PAGE_BYTES {
                break;
            }
        } else if state.stack[frame_index].next_child < group.groups.len() {
            if state.stack.len() >= MAX_LOCATOR_DEPTH {
                return Err(ServiceError::ResourceLimit);
            }
            let child_index = state.stack[frame_index].next_child;
            state.stack[frame_index].next_child += 1;
            state.stack.push(GroupFrame {
                group_index: Some(child_index),
                next_entry: 0,
                next_child: 0,
                entered: false,
                path_matches: false,
                path_safe: true,
                path_bytes: 0,
            });
        } else {
            state.stack.pop();
        }
    }
    while let Some(frame) = state.stack.last().copied() {
        let group = group_at(root, &state.stack);
        if frame.entered
            && frame.next_entry == group.entries.len()
            && frame.next_child >= group.groups.len()
        {
            state.stack.pop();
        } else {
            break;
        }
    }
    Ok(page)
}

fn text_candidate_cost(bytes: usize, count: usize) -> Result<usize, ServiceError> {
    bytes
        .checked_mul(8)
        .and_then(|cost| cost.checked_add(count.checked_mul(16)?))
        .ok_or(ServiceError::ResourceLimit)
}

fn entry_candidate_cost(
    entry: &Entry,
    path_depth: usize,
    page_remaining: usize,
    search_remaining: usize,
) -> Result<Option<usize>, ServiceError> {
    let count = entry
        .tags
        .len()
        .checked_add(3)
        .ok_or(ServiceError::ResourceLimit)?;
    let fixed = count.checked_mul(16).ok_or(ServiceError::ResourceLimit)?;
    let path_cost = path_depth
        .checked_mul(16)
        .ok_or(ServiceError::ResourceLimit)?;
    let minimum = fixed
        .checked_add(path_cost)
        .ok_or(ServiceError::ResourceLimit)?;
    if minimum > MAX_PAGE_TEXT_WORK || minimum > MAX_SEARCH_TEXT_WORK {
        return Err(ServiceError::ResourceLimit);
    }
    if minimum > search_remaining {
        return Err(ServiceError::ResourceLimit);
    }
    if minimum > page_remaining {
        return Ok(None);
    }
    let bytes = [&entry.title, &entry.username, &entry.url]
        .into_iter()
        .chain(entry.tags.iter())
        .try_fold(0usize, |sum, candidate| {
            sum.checked_add(candidate.len())
                .ok_or(ServiceError::ResourceLimit)
        })?;
    let projection_label_bytes = if count - 3 + entry.fields.len() <= MAX_METADATA_ITEMS {
        let labels = entry.fields.iter().try_fold(0usize, |sum, field| {
            sum.checked_add(field.key.len())
                .ok_or(ServiceError::ResourceLimit)
        })?;
        labels
            .checked_add(
                entry
                    .fields
                    .len()
                    .checked_mul(16)
                    .ok_or(ServiceError::ResourceLimit)?,
            )
            .ok_or(ServiceError::ResourceLimit)?
    } else {
        0
    };
    let cost = text_candidate_cost(bytes, count)?
        .checked_add(
            projection_label_bytes
                .checked_mul(8)
                .ok_or(ServiceError::ResourceLimit)?,
        )
        .and_then(|cost| cost.checked_add(path_cost))
        .ok_or(ServiceError::ResourceLimit)?;
    if cost > MAX_PAGE_TEXT_WORK || cost > MAX_SEARCH_TEXT_WORK {
        return Err(ServiceError::ResourceLimit);
    }
    if cost > search_remaining {
        return Err(ServiceError::ResourceLimit);
    }
    if cost > page_remaining {
        return Ok(None);
    }
    Ok(Some(cost))
}

struct GroupPath<'a> {
    parts: Vec<&'a str>,
    bytes: usize,
    safe: bool,
}

fn path_for<'a>(root: &'a Group, stack: &[GroupFrame], bytes: usize, safe: bool) -> GroupPath<'a> {
    let mut path = Vec::with_capacity(stack.len());
    let mut group = root;
    path.push(group.name.as_str());
    for frame in stack.iter().skip(1) {
        group = &group.groups[frame.group_index.expect("non-root frame")];
        path.push(group.name.as_str());
    }
    GroupPath {
        parts: path,
        bytes,
        safe,
    }
}

fn render_path(path: &GroupPath<'_>, title: &str) -> String {
    let mut rendered =
        String::with_capacity(path.bytes.saturating_add(1).saturating_add(title.len()));
    for part in path.parts.iter().copied().chain(std::iter::once(title)) {
        if !rendered.is_empty() {
            rendered.push('/');
        }
        rendered.push_str(part);
    }
    rendered
}

fn project_hit(
    entry: &Entry,
    path: &GroupPath<'_>,
    locator: &[usize],
    session: SessionId,
    generation: u64,
    max_bytes: usize,
) -> Option<(SearchHit, usize)> {
    let path_bytes = path.bytes.checked_add(1)?.checked_add(entry.title.len())?;
    let item_count = entry.tags.len().checked_add(entry.fields.len())?;
    if item_count > MAX_METADATA_ITEMS || locator.len() >= MAX_LOCATOR_DEPTH {
        return None;
    }
    let metadata_bytes = entry
        .tags
        .iter()
        .map(String::len)
        .chain(entry.fields.iter().map(|field| field.key.len()))
        .try_fold(0usize, usize::checked_add)?;
    let structure_bytes = entry
        .tags
        .len()
        .checked_mul(std::mem::size_of::<String>())?
        .checked_add(
            entry
                .fields
                .len()
                .checked_mul(std::mem::size_of::<String>())?,
        )?
        .checked_add((locator.len() + 1).checked_mul(std::mem::size_of::<usize>())?)?
        .checked_add(std::mem::size_of::<SearchHit>())?;
    let hit_bytes = path_bytes
        .checked_add(entry.title.len())?
        .checked_add(metadata_bytes)?
        .checked_add(structure_bytes)?;
    if hit_bytes > MAX_HIT_BYTES || hit_bytes > max_bytes {
        return None;
    }
    // The rendered path contains every vault-controlled group name as well as
    // the title. Check its complete components before allocating/copying the
    // projection; checking the title alone leaves group labels as an output
    // injection path. The inserted `/` separators are fixed safe bytes.
    // `group_path_safe` represents every group-name component in the complete
    // rendered path; those components were checked once at frame entry.
    if !path.safe
        || !safe_metadata(&entry.title)
        || entry.tags.iter().any(|tag| !safe_metadata(tag))
        || entry.fields.iter().any(|field| !safe_metadata(&field.key))
    {
        return None;
    }
    let rendered_path = render_path(path, &entry.title);
    Some((
        SearchHit {
            reference: EntryRef {
                session,
                generation,
                id: entry.id,
                locator: {
                    let mut owned = Vec::with_capacity(locator.len());
                    owned.extend_from_slice(locator);
                    owned
                },
            },
            path: rendered_path,
            title: entry.title.clone(),
            tags: {
                let mut owned = Vec::with_capacity(entry.tags.len());
                owned.extend(entry.tags.iter().cloned());
                owned
            },
            field_names: {
                let mut owned = Vec::with_capacity(entry.fields.len());
                owned.extend(entry.fields.iter().map(|field| field.key.clone()));
                owned
            },
        },
        hit_bytes,
    ))
}

fn failure_table(needle: &[char]) -> Vec<usize> {
    let mut table = vec![0; needle.len()];
    let mut prefix = 0;
    for index in 1..needle.len() {
        while prefix > 0 && needle[index] != needle[prefix] {
            prefix = table[prefix - 1];
        }
        if needle[index] == needle[prefix] {
            prefix += 1;
            table[index] = prefix;
        }
    }
    table
}

fn contains_lowercase(candidate: &str, needle: &[char], failure: &[usize]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut matched = 0;
    for lowered in candidate.chars().flat_map(char::to_lowercase) {
        while matched > 0 && lowered != needle[matched] {
            matched = failure[matched - 1];
        }
        if lowered == needle[matched] {
            matched += 1;
            if matched == needle.len() {
                return true;
            }
        }
    }
    false
}

fn safe_metadata(value: &str) -> bool {
    !value.chars().any(|character| {
        let code = character as u32;
        code <= 0x1f || (0x7f..=0x9f).contains(&code)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use neotales_keepass::{Entry, Field, KdbxKdf, KdbxWriteOptions};

    #[test]
    fn create_installs_generated_entry_with_custom_reader_bounded_kdf() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("created.kdbx");
        let service = VaultService::default();
        let options = KdbxWriteOptions {
            kdf: KdbxKdf::Argon2id,
            argon2_memory_kib: 1024,
            argon2_time: 1,
            argon2_lanes: 1,
            ..Default::default()
        };
        service
            .create(&path, &mut credentials(), options, Some(32))
            .unwrap();

        let mut database = KdbxFile::open(File::open(&path).unwrap(), "service-test-password")
            .expect("created vault should reopen");
        let entry = &database.root.entries[0];
        assert_eq!(entry.title, "generated");
        let password = entry.password.reveal_text().unwrap();
        assert_eq!(password.as_str().len(), 32);
        assert!(
            password
                .as_str()
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        );
        let bytes = std::fs::read(&path).unwrap();
        const ARGON2ID_UUID_FIELD: &[u8] =
            b"\x42\x05\x00\x00\x00$UUID\x10\x00\x00\x00\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6";
        assert!(
            bytes
                .windows(ARGON2ID_UUID_FIELD.len())
                .any(|window| window == ARGON2ID_UUID_FIELD)
        );
        // Keep the loaded secret from escaping this assertion's scope.
        database.root.entries.clear();
    }

    #[test]
    fn create_refuses_existing_target_without_modifying_it() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("existing.kdbx");
        let original = b"keep this file";
        std::fs::write(&path, original).unwrap();
        let error = VaultService::default()
            .create(&path, &mut credentials(), KdbxWriteOptions::default(), None)
            .unwrap_err();
        assert_eq!(error, ServiceError::CreateExists);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn create_failures_before_install_leave_no_target() {
        let temp = tempfile::tempdir().unwrap();
        let blocker = temp.path().join("not-a-directory");
        std::fs::write(&blocker, b"blocker").unwrap();
        let path = blocker.join("new.kdbx");
        assert_eq!(
            VaultService::default().create(
                &path,
                &mut credentials(),
                KdbxWriteOptions::default(),
                None,
            ),
            Err(ServiceError::CreateDirectory)
        );
        assert!(!path.exists());

        let write_path = temp.path().join("bad-write.kdbx");
        let error = VaultService::default().create(
            &write_path,
            &mut credentials(),
            KdbxWriteOptions {
                kdf: KdbxKdf::Argon2id,
                argon2_memory_kib: 0,
                ..Default::default()
            },
            None,
        );
        assert_eq!(error, Err(ServiceError::InvalidInput));
        assert!(!write_path.exists());

        let write_path = temp.path().join("serialization-failure.kdbx");
        let error = install_new_vault(&write_path, |_staged| Err(ServiceError::CreateWrite));
        assert_eq!(error, Err(ServiceError::CreateWrite));
        assert!(!write_path.exists());
    }

    #[test]
    fn create_install_failure_keeps_existing_directory_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target-directory");
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            install_new_vault(&path, |_staged| Ok(())),
            Err(ServiceError::CreateExists)
        );
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn create_durability_failure_reports_installed_partial_success() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("installed.kdbx");
        let result = install_new_vault_with_durability(
            &path,
            |staged| {
                use std::io::Write as _;
                staged
                    .write_all(b"installed")
                    .map_err(|_| ServiceError::CreateWrite)
            },
            |_| Err(ServiceError::CreateDurability),
        );
        assert_eq!(result, Err(ServiceError::CreateDurability));
        assert_eq!(std::fs::read(path).unwrap(), b"installed");
    }

    #[cfg(not(unix))]
    #[test]
    fn create_is_usable_when_directory_durability_cannot_be_confirmed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("best-effort.kdbx");
        let mut create_credentials = credentials();
        VaultService::default()
            .create(
                &path,
                &mut create_credentials,
                KdbxWriteOptions {
                    aes_kdf_rounds: 8,
                    ..Default::default()
                },
                None,
            )
            .expect("non-Unix create succeeds with best-effort directory durability");

        let mut service = VaultService::default();
        service
            .open(&path, &mut credentials(), &crate::KDBX_LIMITS)
            .expect("the installed vault remains immediately usable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_staging_failure_leaves_no_target() {
        let path = Path::new("/proc").join(format!("nkeepass-{}.kdbx", std::process::id()));
        assert_eq!(
            VaultService::default().create(
                &path,
                &mut credentials(),
                KdbxWriteOptions::default(),
                None,
            ),
            Err(ServiceError::CreateStage)
        );
        assert!(!path.exists());
    }

    #[test]
    fn concurrent_create_has_one_winner_and_never_clobbers() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("race.kdbx");
        let barrier = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let handles = (0..2)
                .map(|_| {
                    let barrier = &barrier;
                    let path = &path;
                    scope.spawn(move || {
                        barrier.wait();
                        VaultService::default().create(
                            path,
                            &mut credentials(),
                            KdbxWriteOptions {
                                aes_kdf_rounds: 8,
                                ..Default::default()
                            },
                            None,
                        )
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ServiceError::CreateExists))
                .count(),
            1
        );
        assert!(KdbxFile::open(File::open(path).unwrap(), "service-test-password").is_ok());
    }

    fn vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("service.kdbx");
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("mail");
        entry.username = "alice".into();
        entry.url = "https://example.test".into();
        entry.tags.push("personal".into());
        entry
            .fields
            .push(Field::new("recovery", "must-not-cross-boundary"));
        database.root.add_entry(entry);
        let mut credentials = KdbxCredentials::password("service-test-password").unwrap();
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut credentials,
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        (temp, path)
    }

    fn credentials() -> KdbxCredentials {
        KdbxCredentials::password("service-test-password").unwrap()
    }

    fn service_with_database(database: KeePassDatabase) -> VaultService {
        VaultService {
            generation: 1,
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        }
    }

    #[test]
    fn group_mutations_validate_names_and_invalidate_old_references() {
        let service_session = SessionId(1);
        let mut service = service_with_database(KeePassDatabase::default());
        let root = service.root_group(service_session).unwrap();
        assert_eq!(service.group_path(&root).unwrap(), "Root");
        assert_eq!(
            service.remove_group(&root),
            Err(ServiceError::RootGroupMutation)
        );
        assert_eq!(
            service.add_group(&root, ".."),
            Err(ServiceError::InvalidInput)
        );
        service.add_group(&root, "Work").unwrap();
        assert_eq!(service.group_path(&root), Err(ServiceError::Stale));
        let mut work = service.resolve_group(service_session, "Root/Work").unwrap();
        assert_eq!(service.group_path(&work).unwrap(), "Root/Work");
        service.add_group(&work, "Nested").unwrap();
        work = service.resolve_group(service_session, "Root/Work").unwrap();
        assert_eq!(
            service.add_group(&work, "nested"),
            Err(ServiceError::GroupExists)
        );
        let nested = service
            .resolve_group(service_session, "Root/Work/Nested")
            .unwrap();
        assert!(
            service
                .ensure_entry(service_session, "Root/Work/Nested/New", None, false)
                .unwrap()
        );
        assert_eq!(service.group_path(&nested), Err(ServiceError::Stale));
        let nested = service
            .resolve_group(service_session, "Root/Work/Nested")
            .unwrap();
        service.remove_group(&nested).unwrap();
        assert!(matches!(
            service.resolve_group(service_session, "Root/Work/Nested"),
            Err(ServiceError::NotFound)
        ));
        let groups = service.completion_metadata().unwrap().groups;
        assert_eq!(groups, ["Root", "Root/Work"]);
    }

    #[test]
    fn direct_tree_pages_are_bounded_ordered_single_use_and_withhold_hostile_labels() {
        let mut database = KeePassDatabase::default();
        for index in 0..130 {
            database
                .root
                .add_group(Group::new(format!("group-{index:03}")));
        }
        database.root.add_group(Group::new("slash/segment"));
        database.root.add_entry(Entry::new("entry-after-groups"));
        database.root.add_group(Group::new("bad\u{1b}label"));
        let mut service = service_with_database(database);
        let session = SessionId(1);
        let root = service.root_group(session).unwrap();
        let first = service.tree_page(&root, None).unwrap();
        assert_eq!(first.groups.len(), 128);
        assert!(first.entries.is_empty());
        let cursor = first.next_cursor.unwrap();
        let second = service.tree_page(&root, Some(cursor)).unwrap();
        assert_eq!(
            second
                .groups
                .iter()
                .map(TreeGroup::label)
                .collect::<Vec<_>>(),
            ["group-128", "group-129"]
        );
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.withheld, 2);
        assert!(second.next_cursor.is_none());
        assert_eq!(
            service.tree_page(&root, Some(cursor)).err().unwrap(),
            ServiceError::Stale
        );
        let child = first.groups[0].reference();
        assert!(service.tree_page(&child, None).unwrap().entries.is_empty());
    }

    #[test]
    fn direct_tree_cursor_can_be_released_and_group_handles_are_session_bound() {
        let mut database = KeePassDatabase::default();
        for index in 0..129 {
            database.root.add_group(Group::new(format!("g{index}")));
        }
        let mut service = service_with_database(database);
        let root = service.root_group(SessionId(1)).unwrap();
        let cursor = service.tree_page(&root, None).unwrap().next_cursor.unwrap();
        assert!(service.release_tree_cursor(cursor));
        assert!(!service.release_tree_cursor(cursor));
        assert_eq!(
            service.tree_page(&root, Some(cursor)).err().unwrap(),
            ServiceError::Stale
        );
        let mut foreign = root;
        foreign.session = SessionId(2);
        assert_eq!(
            service.tree_page(&foreign, None).err().unwrap(),
            ServiceError::Stale
        );
    }

    #[test]
    fn mutation_invalidates_tree_continuations_and_releases_their_capacity() {
        let mut database = KeePassDatabase::default();
        for index in 0..130 {
            database.root.add_group(Group::new(format!("g{index}")));
        }
        let mut service = service_with_database(database);
        let root = service.root_group(SessionId(1)).unwrap();
        let mut cursors = Vec::new();
        for _ in 0..MAX_ACTIVE_CURSORS {
            cursors.push(service.tree_page(&root, None).unwrap().next_cursor.unwrap());
        }
        assert_eq!(
            service.tree_page(&root, None).err().unwrap(),
            ServiceError::ResourceLimit
        );
        service.invalidate_references();
        assert!(service.trees.is_empty());
        assert_eq!(
            service.tree_page(&root, Some(cursors[0])).err().unwrap(),
            ServiceError::Stale
        );
        let current_root = service.root_group(SessionId(1)).unwrap();
        assert!(
            service
                .tree_page(&current_root, None)
                .unwrap()
                .next_cursor
                .is_some()
        );
    }

    #[test]
    fn replacing_a_live_search_query_releases_its_superseded_cursor() {
        let mut database = KeePassDatabase::default();
        for index in 0..MAX_RESULTS + 2 {
            database
                .root
                .add_entry(Entry::new(format!("match-{index:04}")));
        }
        let mut service = service_with_database(database);
        let session = SessionId(1);
        let previous = service
            .search_page(session, "match", None)
            .unwrap()
            .next_cursor
            .unwrap();
        assert!(service.release_search_cursor(previous));
        let replacement = service
            .search_page(session, "a", None)
            .unwrap()
            .next_cursor
            .unwrap();
        assert_eq!(
            service
                .search_page(session, "match", Some(previous))
                .err()
                .unwrap(),
            ServiceError::Stale
        );
        assert!(service.search_page(session, "a", Some(replacement)).is_ok());
    }

    #[test]
    fn tree_projection_withholds_oversized_metadata_and_bounds_deep_handles() {
        let mut database = KeePassDatabase::default();
        let mut huge = Entry::new("oversized-metadata");
        huge.tags.push("t".repeat(MAX_TREE_LABEL_BYTES + 1));
        database.root.add_entry(huge);
        let mut huge_fields = Entry::new("oversized-fields");
        huge_fields.fields.push(Field::new(
            "f".repeat(MAX_TREE_LABEL_BYTES + 1),
            "secret-marker-not-projected",
        ));
        database.root.add_entry(huge_fields);
        database.root.add_entry(Entry::new("safe-after-hostile"));
        let mut service = service_with_database(database);
        let root = service.root_group(SessionId(1)).unwrap();
        let page = service.tree_page(&root, None).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].title(), "safe-after-hostile");
        assert_eq!(page.withheld, 2);

        let mut wide_text = Entry::new("bounded-work-row");
        wide_text.fields = (0..MAX_METADATA_ITEMS)
            .map(|_| Field::new("f".repeat(MAX_TREE_LABEL_BYTES), "value-never-projected"))
            .collect();
        wide_text.tags = (0..MAX_METADATA_ITEMS)
            .map(|_| "t".repeat(MAX_TREE_LABEL_BYTES))
            .collect();
        let mut database = KeePassDatabase::default();
        database.root.add_entry(wide_text);
        database
            .root
            .add_entry(Entry::new("benign-after-wide-text"));
        let mut service = service_with_database(database);
        let root = service.root_group(SessionId(1)).unwrap();
        let page = service.tree_page(&root, None).unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].title(), "benign-after-wide-text");
        assert_eq!(page.withheld, 1);

        let mut database = KeePassDatabase::default();
        let mut group = Group::new("g0");
        let mut parent_id = None;
        for _ in 1..=MAX_LOCATOR_DEPTH {
            let child = Group::new("g");
            parent_id = Some(child.id);
            group.add_group(child);
        }
        database.root.add_group(group);
        let service = service_with_database(database);
        let too_deep = GroupRef {
            session: SessionId(1),
            generation: 1,
            id: parent_id.unwrap(),
            locator: vec![0; MAX_LOCATOR_DEPTH + 1],
        };
        let mut service = service;
        assert_eq!(
            service.tree_page(&too_deep, None).err().unwrap(),
            ServiceError::ResourceLimit
        );
    }

    #[test]
    fn tree_ancestor_path_budget_fails_closed_before_projection() {
        let label = "a".repeat(MAX_TREE_LABEL_BYTES);
        let mut nested = Group::new(label.clone());
        for _ in 0..5 {
            let mut child = Group::new(label.clone());
            child.add_group(std::mem::replace(&mut nested, Group::new("temporary")));
            nested = child;
        }
        let mut database = KeePassDatabase::default();
        database.root.add_group(nested);
        let mut service = service_with_database(database);
        let mut parent = service.root_group(SessionId(1)).unwrap();
        let mut reached_limit = false;
        for _ in 0..6 {
            match service.tree_page(&parent, None) {
                Ok(page) => parent = page.groups[0].reference(),
                Err(ServiceError::ResourceLimit) => {
                    reached_limit = true;
                    break;
                }
                Err(error) => panic!("unexpected tree error: {}", error.message()),
            }
        }
        assert!(reached_limit);
    }

    fn snapshot(database: &KeePassDatabase) -> Vec<u8> {
        interchange::encode(database).unwrap().to_vec()
    }

    #[test]
    fn import_requires_explicit_authorization_for_nonempty_vault() {
        let mut target = KeePassDatabase::default();
        target.root.add_entry(Entry::new("existing"));
        let before = snapshot(&target);
        let input = snapshot(&KeePassDatabase::default());
        let mut service = service_with_database(target);

        let error = service
            .import_snapshot(&input, ImportOptions::default())
            .unwrap_err();
        assert_eq!(
            error.message(),
            "target vault is not empty; use --replace to authorize replacement"
        );
        assert_eq!(service.export_snapshot().unwrap().bytes(), before);
    }

    #[test]
    fn import_dry_run_reports_pending_without_mutating_or_generating() {
        let mut target = KeePassDatabase::default();
        target.root.add_entry(Entry::new("existing"));
        let before = snapshot(&target);
        let mut source = KeePassDatabase::default();
        let entry = Entry::new("planned");
        source.root.add_entry(entry);
        let mut wire: serde_json::Value = serde_json::from_slice(&snapshot(&source)).unwrap();
        wire["database"]["root"]["entries"][0]["ensure"] = serde_json::json!({"size": 48});
        let input = serde_json::to_vec(&wire).unwrap();
        let mut service = service_with_database(target);

        let report = service
            .import_snapshot(
                &input,
                ImportOptions {
                    replace: true,
                    dry_run: true,
                },
            )
            .unwrap();
        assert_eq!(report.passwords_generated, 0);
        assert_eq!(report.passwords_pending, 1);
        assert_eq!(report.entries, 1);
        assert_eq!(service.export_snapshot().unwrap().bytes(), before);
        assert!(
            service.session.as_ref().unwrap().database.root.entries[0]
                .title
                .eq("existing")
        );
    }

    #[test]
    fn export_refuses_a_lossy_model_without_producing_bytes() {
        let database = KeePassDatabase {
            can_save_losslessly: false,
            ..KeePassDatabase::default()
        };
        let service = service_with_database(database);
        let error = service.export_snapshot().err().unwrap();
        assert_eq!(
            error.message(),
            "vault contains unsupported data that cannot be exported losslessly"
        );
    }

    #[test]
    fn sync_dry_run_is_immutable_and_strategy_reports_expected_counts() {
        let mut target = KeePassDatabase::default();
        target.root.add_entry(Entry::new("target-only"));
        let before = snapshot(&target);
        let mut source = KeePassDatabase::default();
        source.root.add_entry(Entry::new("source-new"));
        let input = snapshot(&source);
        let mut service = service_with_database(target);

        let dry = service
            .sync_snapshot(
                &input,
                SyncOptions {
                    strategy: SyncStrategy::Newest,
                    dry_run: true,
                },
            )
            .unwrap();
        assert_eq!(dry.strategy, SyncStrategy::Newest);
        assert_eq!(dry.entries_updated, 0);
        assert_eq!(dry.entries_added, 1);
        assert_eq!(service.export_snapshot().unwrap().bytes(), before);

        let source_strategy = service_with_database(KeePassDatabase::default())
            .sync_snapshot(
                &input,
                SyncOptions {
                    strategy: SyncStrategy::Source,
                    dry_run: true,
                },
            )
            .unwrap();
        assert_eq!(source_strategy.strategy, SyncStrategy::Source);
        assert_eq!(source_strategy.entries_added, 1);

        let applied = service
            .sync_snapshot(
                &input,
                SyncOptions {
                    strategy: SyncStrategy::Target,
                    dry_run: false,
                },
            )
            .unwrap();
        assert_eq!(applied.entries_updated, 0);
        assert_eq!(applied.entries_added, 1);
        let entries = &service.session.as_ref().unwrap().database.root.entries;
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| entry.title == "target-only"));
        assert!(entries.iter().any(|entry| entry.title == "source-new"));
    }

    #[test]
    fn sync_rejects_cross_vault_shared_non_root_uuids_before_group_merge() {
        let mut target = KeePassDatabase::default();
        let target_group = Group::new("shared");
        let group_id = target_group.id;
        target.root.add_group(target_group);

        let mut source = KeePassDatabase::default();
        let mut source_group = Group::new("shared-source");
        source_group.id = group_id;
        source.root.add_group(source_group);

        let mut service = service_with_database(target);
        let error = service
            .sync_snapshot(
                &snapshot(&source),
                SyncOptions {
                    strategy: SyncStrategy::Newest,
                    dry_run: false,
                },
            )
            .unwrap_err();
        assert_eq!(error.message(), "interchange contains a UUID collision");
    }

    #[test]
    fn public_sync_remaps_current_and_history_attachment_references() {
        let mut target = KeePassDatabase::default();
        let target_binary = target
            .binary_pool
            .add(b"pre-existing-target-binary".to_vec(), true);
        let mut target_entry = Entry::new("target-only");
        target_entry.attachments.push(neotales_keepass::Attachment {
            name: "target.bin".into(),
            reference: target_binary,
        });
        target.root.add_entry(target_entry);

        let mut source = KeePassDatabase::default();
        let current_binary = source
            .binary_pool
            .add(b"unique-current-attachment".to_vec(), true);
        let history_binary = source
            .binary_pool
            .add(b"unique-history-attachment".to_vec(), false);
        let mut entry = Entry::new("source-added");
        entry.attachments.push(neotales_keepass::Attachment {
            name: "current.bin".into(),
            reference: current_binary,
        });
        let mut history = Entry::new("source-history");
        history.attachments.push(neotales_keepass::Attachment {
            name: "history.bin".into(),
            reference: history_binary,
        });
        entry.history.push(history);
        source.root.add_entry(entry);

        let mut service = service_with_database(target);
        let report = service
            .sync_snapshot(
                &snapshot(&source),
                SyncOptions {
                    strategy: SyncStrategy::Newest,
                    dry_run: false,
                },
            )
            .unwrap();
        assert_eq!(report.entries_added, 1);
        let database = &service.session.as_ref().unwrap().database;
        assert_eq!(database.binary_pool.len(), 3);
        let synced = database
            .root
            .entries
            .iter()
            .find(|item| item.title == "source-added")
            .unwrap();
        assert_eq!(synced.attachments.len(), 1);
        assert_eq!(
            database
                .binary_pool
                .get(synced.attachments[0].reference)
                .unwrap()
                .data,
            b"unique-current-attachment"
        );
        assert_eq!(synced.history.len(), 1);
        assert_eq!(synced.history[0].attachments.len(), 1);
        assert_eq!(
            database
                .binary_pool
                .get(synced.history[0].attachments[0].reference)
                .unwrap()
                .data,
            b"unique-history-attachment"
        );

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sync-round-trip.kdbx");
        service.save(&path, &mut credentials()).unwrap();
        let round_trip = KdbxFile::open(File::open(path).unwrap(), "service-test-password")
            .expect("synced vault should reopen");
        let synced = round_trip
            .root
            .entries
            .iter()
            .find(|item| item.title == "source-added")
            .unwrap();
        assert_eq!(
            round_trip
                .binary_pool
                .get(synced.attachments[0].reference)
                .unwrap()
                .data,
            b"unique-current-attachment"
        );
        assert_eq!(
            round_trip
                .binary_pool
                .get(synced.history[0].attachments[0].reference)
                .unwrap()
                .data,
            b"unique-history-attachment"
        );
    }

    fn root_prefix_collision_vault() -> VaultService {
        let mut database = KeePassDatabase::default();
        database.root.name = "Work Vault".into();
        let mut nested = Group::new("Work Vault");
        let mut first_x = Group::new("X");
        first_x.add_entry(Entry::new("Duplicate"));
        first_x.add_entry(Entry::new("NestedOnly"));
        let mut second_x = Group::new("X");
        second_x.add_entry(Entry::new("Duplicate"));
        nested.add_group(first_x);
        nested.add_group(second_x);
        database.root.add_group(nested);

        let mut root_x = Group::new("X");
        root_x.add_entry(Entry::new("Mail"));
        root_x.add_entry(Entry::new("Duplicate"));
        database.root.add_group(root_x);
        VaultService {
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        }
    }

    #[test]
    fn complete_root_prefixed_entry_paths_decide_collisions() {
        let service = root_prefix_collision_vault();
        let session = SessionId(1);

        let resolved = service.resolve_entry(session, "Work Vault/X/Mail").unwrap();
        assert_eq!(resolved.path(), "Work Vault/X/Mail");
        assert_eq!(
            resolve_locator(
                &service.session.as_ref().unwrap().database,
                &resolved.reference().locator,
                resolved.reference().id,
            )
            .unwrap()
            .title,
            "Mail"
        );

        assert_eq!(
            service
                .resolve_entry(session, "Work Vault/X/Duplicate")
                .err(),
            Some(ServiceError::Ambiguous)
        );
        assert_eq!(
            service.resolve_entry(session, "Work Vault/X/Missing").err(),
            Some(ServiceError::NotFound)
        );
        assert_eq!(
            service
                .resolve_entry(session, "Work Vault/X/Missing/Mail")
                .err(),
            Some(ServiceError::NotFound)
        );
    }

    #[test]
    fn ambiguous_ensure_does_not_mutate_any_candidate_group() {
        let mut service = root_prefix_collision_vault();
        let session = SessionId(1);
        let before = format!("{:?}", service.session.as_ref().unwrap().database.root);
        assert_eq!(
            service.ensure_entry(session, "Work Vault/X/Created", None, false),
            Err(ServiceError::Ambiguous)
        );
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
        assert_eq!(
            service.ensure_entry(session, "Work Vault/X/Missing/Created", None, false),
            Err(ServiceError::Ambiguous)
        );
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
    }

    #[test]
    fn completion_projection_contains_only_bounded_tree_and_field_names() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        service
            .open(&path, &mut credentials(), &crate::KDBX_LIMITS)
            .unwrap();
        let metadata = service.completion_metadata().unwrap();
        assert_eq!(metadata.groups, ["Root"]);
        assert_eq!(metadata.entries, ["Root/mail"]);
        assert!(metadata.keys.contains(&"recovery".to_owned()));
        assert!(!format!("{metadata:?}").contains("must-not-cross-boundary"));
    }

    #[test]
    fn completion_validates_raw_names_before_joining_paths() {
        let mut root = Group::new("Root");
        let mut unaddressable = Group::new("bad/group");
        let mut hidden = Group::new("hidden");
        hidden.add_entry(Entry::new("secret"));
        unaddressable.add_group(hidden);
        root.add_group(unaddressable);

        let mut valid = Group::new("Valid");
        valid.add_entry(Entry::new("bad/entry"));
        let mut bad = Group::new("bad");
        bad.add_entry(Entry::new("entry"));
        valid.add_group(bad);
        root.add_group(valid);
        let database = KeePassDatabase {
            root,
            ..KeePassDatabase::default()
        };
        let service = VaultService {
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };

        let metadata = service.completion_metadata().unwrap();
        assert_eq!(metadata.entries, ["Root/Valid/bad/entry"]);
        assert_eq!(
            metadata
                .entries
                .iter()
                .filter(|path| path.as_str() == "Root/Valid/bad/entry")
                .count(),
            1,
            "the slash-containing raw title must not collide with the real child path"
        );
        assert!(
            !metadata
                .groups
                .iter()
                .any(|path| path.starts_with("Root/bad/"))
        );
        assert!(
            !metadata
                .entries
                .iter()
                .any(|path| path.contains("hidden/secret"))
        );
        let selected = service
            .resolve_entry(SessionId(1), "Valid/bad/entry")
            .unwrap();
        assert_eq!(selected.path(), "Root/Valid/bad/entry");
        assert_eq!(
            resolve_locator(
                &service.session.as_ref().unwrap().database,
                &selected.reference().locator,
                selected.reference().id,
            )
            .unwrap()
            .title,
            "entry"
        );
    }

    #[test]
    fn completion_bounds_wide_fanout_before_queueing_unbounded_children() {
        let mut database = KeePassDatabase::default();
        for index in 0..=MAX_COMPLETION_NODES {
            database
                .root
                .add_group(Group::new(format!("child-{index}")));
        }
        let service = VaultService {
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        assert_eq!(
            service.completion_metadata().unwrap_err(),
            ServiceError::ResourceLimit
        );
    }

    #[test]
    fn completion_projection_fails_closed_when_its_node_budget_is_exceeded() {
        let mut database = KeePassDatabase::default();
        for index in 0..MAX_COMPLETION_NODES {
            database
                .root
                .add_entry(Entry::new(format!("entry-{index}")));
        }
        let service = VaultService {
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        assert_eq!(
            service.completion_metadata().unwrap_err(),
            ServiceError::ResourceLimit
        );
    }

    #[test]
    fn completion_projection_bounds_zero_length_custom_keys_and_huge_names() {
        let mut entry = Entry::new("many-fields");
        for _ in 0..=MAX_COMPLETION_FIELD_VISITS {
            entry.fields.push(Field::new("", "ignored-value"));
        }
        let mut database = KeePassDatabase::default();
        database.root.add_entry(entry);
        let service = VaultService {
            session: Some(LiveSession {
                id: SessionId(1),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        assert_eq!(
            service.completion_metadata().unwrap_err(),
            ServiceError::ResourceLimit
        );

        let mut entry = Entry::new("large-field");
        entry.fields.push(Field::new(
            "k".repeat(MAX_COMPLETION_PATH_BYTES + 1),
            "must-not-be-read",
        ));
        let mut database = KeePassDatabase::default();
        database.root.add_entry(entry);
        let service = VaultService {
            session: Some(LiveSession {
                id: SessionId(2),
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        assert_eq!(
            service.completion_metadata().unwrap_err(),
            ServiceError::ResourceLimit
        );
    }

    fn otp_vault(uri: &str, duplicate: bool) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("otp-service.kdbx");
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("mail");
        entry.fields.push(Field {
            key: "otp".into(),
            value: ProtectedValue::from_text(uri),
            protected: true,
            protect_in_memory: true,
        });
        if duplicate {
            entry.fields.push(Field {
                key: "otp".into(),
                value: ProtectedValue::from_text(uri),
                protected: true,
                protect_in_memory: true,
            });
        }
        database.root.add_entry(entry);
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut credentials(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        (temp, path)
    }

    #[test]
    fn otp_generation_is_reference_bound_zeroizing_and_preserves_diagnostics() {
        let (_temp, path) = otp_vault(
            "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let code = service.otp_code(&reference, 59).unwrap();
        assert_eq!(&*code, "287082");
        let root_id = service.session.as_ref().unwrap().database.root.id;
        service.session.as_mut().unwrap().database.root.id = reference.id;
        assert_eq!(
            service.otp_code(&reference, 59),
            Err(ServiceError::DuplicateIds)
        );
        service.session.as_mut().unwrap().database.root.id = root_id;

        let mut foreign = VaultService::default();
        foreign
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert_eq!(foreign.otp_code(&reference, 59), Err(ServiceError::Stale));
        service.lock(session).unwrap();
        assert_eq!(service.otp_code(&reference, 59), Err(ServiceError::Locked));
        service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert_eq!(service.otp_code(&reference, 59), Err(ServiceError::Stale));

        let (_temp, path) = otp_vault(
            "otpauth://hotp/mail?secret=JBSWY3DPEHPK3PXP&counter=0",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        assert_eq!(
            service.otp_code(&reference, 59),
            Err(ServiceError::HotpUnsupported)
        );

        let (_temp, path) = otp_vault("not-an-otp-uri", false);
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        assert_eq!(
            service.otp_code(&reference, 59),
            Err(ServiceError::InvalidOtp)
        );

        let (_temp, path) = otp_vault(
            "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let entry = resolve_locator_mut(
            &mut service.session.as_mut().unwrap().database,
            &reference.locator,
            reference.id,
        )
        .unwrap();
        let duplicate = entry
            .fields
            .iter()
            .find(|field| field.key == "otp")
            .unwrap()
            .clone();
        entry.fields.push(duplicate);
        assert_eq!(
            service.otp_code(&reference, 59),
            Err(ServiceError::AmbiguousField)
        );

        let (_temp, path) = otp_vault(
            "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let entry = resolve_locator_mut(
            &mut service.session.as_mut().unwrap().database,
            &reference.locator,
            reference.id,
        )
        .unwrap();
        entry.fields.push(Field::new("duplicate", "first"));
        entry.fields.push(Field::new("duplicate", "second"));
        assert_eq!(
            service.otp_code(&reference, 59),
            Err(ServiceError::DuplicateFields)
        );
    }

    #[test]
    fn cli_totp_result_returns_code_and_period_without_exposing_uri() {
        let (_temp, path) = otp_vault(
            "otpauth://totp/mail?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=45",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let result = service.totp_code_with_period(&reference, 59).unwrap();
        assert_eq!(result.code().len(), 6);
        assert_eq!(result.period(), 45);

        let (_temp, path) = otp_vault(
            "otpauth://hotp/mail?secret=JBSWY3DPEHPK3PXP&counter=0",
            false,
        );
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        assert_eq!(
            service.totp_code_with_period(&reference, 59).err().unwrap(),
            ServiceError::HotpUnsupported
        );
    }

    #[test]
    fn password_binding_preserves_first_serialized_standard_field() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let entry = resolve_locator_mut(
            &mut service.session.as_mut().unwrap().database,
            &reference.locator,
            reference.id,
        )
        .unwrap();
        entry.fields.push(Field::new("Password", "first-value"));
        entry.fields.push(Field::new("Password", "second-value"));
        entry.password = ProtectedValue::from_text("projection-value");

        assert_eq!(
            service.reveal_password(&reference).unwrap().as_slice(),
            b"first-value"
        );
    }

    #[test]
    fn safe_metadata_rejects_every_c0_del_and_c1_code_point() {
        for code in (0x00..=0x1f).chain(0x7f..=0x9f) {
            let control = char::from_u32(code).unwrap();
            assert!(
                !safe_metadata(&format!("group{control}name")),
                "U+{code:04X} must make group metadata unsafe",
            );
        }
        assert!(safe_metadata("ordinary group name"));
    }

    fn search_tree(group: &Group, query: &str) -> (usize, SearchPage) {
        let mut state = SearchState::new(query, SessionId(1), 1);
        let mut page = SearchPage {
            hits: Vec::new(),
            withheld: 0,
            next_cursor: None,
        };
        while state.has_more() {
            let next = scan_page(group, &mut state).unwrap();
            page.withheld += next.withheld;
            page.hits.extend(next.hits);
        }
        let count = page.hits.len() + page.withheld;
        (count, page)
    }

    #[test]
    fn search_returns_allowlisted_metadata_and_validates_opaque_handles() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let page = service.search(session, "alice").unwrap();
        assert_eq!(page.hits.len(), 1);
        let hit = &page.hits[0];
        assert_eq!(hit.title(), "mail");
        // KDBX round-tripping currently drops model-only tags; the service
        // projects the same loaded metadata the existing CLI sees.
        assert!(hit.tags().is_empty());
        assert_eq!(hit.field_names(), &["Title", "UserName", "URL", "recovery"]);
        let reference = hit.reference();
        assert!(service.validate_entry(&reference).is_ok());
        assert_eq!(
            service
                .search(session, "must-not-cross-boundary")
                .unwrap()
                .hits
                .len(),
            0
        );
    }

    #[test]
    fn field_mutation_invalidates_handles_and_round_trips_only_through_service_save() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        service
            .set_custom_field(&reference, "recovery", "updated")
            .unwrap();
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        service.save(&path, &mut credentials()).unwrap();

        let mut reopened = VaultService::default();
        let reopened_session = reopened
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let fresh = reopened
            .resolve_entry(reopened_session, "mail")
            .unwrap()
            .reference();
        assert_eq!(
            reopened
                .reveal_field(&fresh, "recovery")
                .unwrap()
                .as_slice(),
            b"updated"
        );
    }

    #[test]
    fn entry_and_field_removals_invalidate_old_handles() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        service.remove_custom_field(&reference, "recovery").unwrap();
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        let fresh = service.resolve_entry(session, "mail").unwrap().reference();
        service.remove_entry(&fresh).unwrap();
        assert_eq!(service.validate_entry(&fresh), Err(ServiceError::Stale));
        assert!(matches!(
            service.resolve_entry(session, "mail"),
            Err(ServiceError::NotFound)
        ));
    }

    #[test]
    fn attachment_mutations_are_exact_protected_pruned_and_round_trip() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        service
            .add_attachment(
                &reference,
                "Case.bin",
                Zeroizing::new(b"case-sensitive".to_vec()),
            )
            .unwrap();
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        let fresh = service.resolve_entry(session, "mail").unwrap().reference();
        service
            .add_attachment(
                &fresh,
                "case.bin",
                Zeroizing::new(b"distinct exact name".to_vec()),
            )
            .unwrap();
        let fresh = service.resolve_entry(session, "mail").unwrap().reference();
        assert_eq!(
            service.add_attachment(&fresh, "Case.bin", Zeroizing::new(b"duplicate".to_vec()),),
            Err(ServiceError::AttachmentExists)
        );
        service.remove_attachment(&fresh, "Case.bin").unwrap();
        assert_eq!(service.validate_entry(&fresh), Err(ServiceError::Stale));
        service.save(&path, &mut credentials()).unwrap();

        let mut reopened = VaultService::default();
        let reopened_session = reopened
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reopened_entry = reopened
            .resolve_entry(reopened_session, "mail")
            .unwrap()
            .reference();
        let attachments = reopened.attachment_metadata(&reopened_entry).unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].name(), "case.bin");
        assert!(attachments[0].protected());
        assert_eq!(
            reopened
                .reveal_attachment(&attachments[0].reference())
                .unwrap()
                .as_slice(),
            b"distinct exact name"
        );
        assert_eq!(
            reopened
                .session
                .as_ref()
                .unwrap()
                .database
                .binary_pool
                .len(),
            1
        );
    }

    #[test]
    fn attachment_add_moves_the_owned_input_allocation_into_the_binary_pool() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let data = Zeroizing::new(b"single-allocation attachment".to_vec());
        let original_allocation = data.as_ptr();
        service
            .add_attachment(&reference, "owned.bin", data)
            .unwrap();

        let stored = service
            .session
            .as_ref()
            .unwrap()
            .database
            .binary_pool
            .get(0)
            .unwrap();
        assert_eq!(stored.data.as_ptr(), original_allocation);
        assert_eq!(stored.data, b"single-allocation attachment");
    }

    #[test]
    fn attachment_add_rejects_duplicate_fields_before_adding_binary() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.fields.push(Field::new("recovery", "duplicate"));
        }

        let live = service.session.as_ref().unwrap();
        let binary_count = live.database.binary_pool.len();
        let entry = resolve_locator(&live.database, &reference.locator, reference.id).unwrap();
        let attachment_count = entry.attachments.len();
        assert_eq!(
            service.add_attachment(
                &reference,
                "must-not-be-added.bin",
                Zeroizing::new(b"sensitive bytes".to_vec()),
            ),
            Err(ServiceError::DuplicateFields)
        );

        let live = service.session.as_ref().unwrap();
        assert_eq!(live.database.binary_pool.len(), binary_count);
        let entry = resolve_locator(&live.database, &reference.locator, reference.id).unwrap();
        assert_eq!(entry.attachments.len(), attachment_count);
    }

    #[test]
    fn attachment_mutations_reject_duplicate_names_and_restore_on_dangling_prune() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        service
            .add_attachment(&reference, "duplicate", Zeroizing::new(b"first".to_vec()))
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.attachments.push(neotales_keepass::Attachment {
                name: "duplicate".into(),
                reference: entry.attachments[0].reference,
            });
        }
        assert_eq!(
            service.remove_attachment(&reference, "duplicate"),
            Err(ServiceError::Ambiguous)
        );

        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.attachments.pop();
            entry.attachments.push(neotales_keepass::Attachment {
                name: "dangling".into(),
                reference: usize::MAX,
            });
        }
        assert_eq!(
            service.remove_attachment(&reference, "duplicate"),
            Err(ServiceError::InvalidAttachmentReference)
        );
        let entry = resolve_locator(
            &service.session.as_ref().unwrap().database,
            &reference.locator,
            reference.id,
        )
        .unwrap();
        assert_eq!(entry.attachments.len(), 2);
        assert_eq!(entry.attachments[0].name, "duplicate");
    }

    #[test]
    fn attachment_pruning_keeps_and_remaps_history_references() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        {
            let live = service.session.as_mut().unwrap();
            let history_binary = live.database.binary_pool.add(b"history".to_vec(), true);
            let removed_binary = live.database.binary_pool.add(b"removed".to_vec(), true);
            let survivor_binary = live.database.binary_pool.add(b"survivor".to_vec(), true);
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.attachments.extend([
                neotales_keepass::Attachment {
                    name: "remove".into(),
                    reference: removed_binary,
                },
                neotales_keepass::Attachment {
                    name: "keep".into(),
                    reference: survivor_binary,
                },
            ]);
            let mut history = Entry::new("mail");
            history.attachments.push(neotales_keepass::Attachment {
                name: "historic".into(),
                reference: history_binary,
            });
            entry.history.push(history);
        }
        service.remove_attachment(&reference, "remove").unwrap();
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        let live = service.session.as_ref().unwrap();
        let fresh = service.resolve_entry(session, "mail").unwrap().reference();
        let entry = resolve_locator(&live.database, &fresh.locator, fresh.id).unwrap();
        assert_eq!(live.database.binary_pool.len(), 2);
        assert_eq!(entry.attachments[0].reference, 1);
        assert_eq!(entry.history[0].attachments[0].reference, 0);
        assert_eq!(live.database.binary_pool.get(0).unwrap().data, b"history");
        assert_eq!(live.database.binary_pool.get(1).unwrap().data, b"survivor");
    }

    #[test]
    fn removals_reject_duplicate_object_ids_before_mutating() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        let original_len = service
            .session
            .as_ref()
            .unwrap()
            .database
            .root
            .entries
            .len();
        service
            .session
            .as_mut()
            .unwrap()
            .database
            .root
            .groups
            .push(Group::new("duplicate-root-id"));
        let duplicate_id = service.session.as_ref().unwrap().database.root.id;
        service.session.as_mut().unwrap().database.root.groups[0].id = duplicate_id;
        assert_eq!(
            service.remove_entry(&reference),
            Err(ServiceError::DuplicateIds)
        );
        assert_eq!(
            service
                .session
                .as_ref()
                .unwrap()
                .database
                .root
                .entries
                .len(),
            original_len
        );
    }

    #[test]
    fn relative_save_target_uses_current_directory_as_parent() {
        assert_eq!(save_parent(Path::new("vault.kdbx")), Path::new("."));
        assert_eq!(save_parent(Path::new("data/vault.kdbx")), Path::new("data"));
        assert_eq!(save_parent(Path::new("/vault.kdbx")), Path::new("/"));
    }

    #[test]
    fn duplicate_fields_block_edit_and_failed_save_leaves_disk_unchanged() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.fields.push(Field::new("recovery", "duplicate"));
        }
        assert_eq!(
            service.set_custom_field(&reference, "recovery", "not-written"),
            Err(ServiceError::DuplicateFields)
        );
        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.fields.pop();
        }
        service
            .set_custom_field(&reference, "recovery", "not-written")
            .unwrap();
        // A save error is returned without installing a partial replacement.
        let missing_parent = path.with_file_name("missing/vault.kdbx");
        assert_eq!(
            service.save(&missing_parent, &mut credentials()),
            Err(ServiceError::SaveStage)
        );
        let mut reopened = VaultService::default();
        let reopened_session = reopened
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let fresh = reopened
            .resolve_entry(reopened_session, "mail")
            .unwrap()
            .reference();
        assert_eq!(
            reopened
                .reveal_field(&fresh, "recovery")
                .unwrap()
                .as_slice(),
            b"must-not-cross-boundary"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn set_fields_are_atomic_preserve_flags_and_round_trip_standard_values() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service.resolve_entry(session, "mail").unwrap().reference();
        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.fields.push(Field::new("recovery", "duplicate"));
        }
        let updates = vec![
            FieldUpdate {
                key: "UserName".into(),
                value: Zeroizing::new("changed".into()),
                protected: Some(true),
                protect_in_memory: Some(false),
            },
            FieldUpdate {
                key: "recovery".into(),
                value: Zeroizing::new("new-secret".into()),
                protected: Some(true),
                protect_in_memory: Some(false),
            },
        ];
        assert_eq!(
            service.set_fields(&reference, updates),
            Err(ServiceError::DuplicateFields)
        );
        let entry = resolve_locator(
            &service.session.as_ref().unwrap().database,
            &reference.locator,
            reference.id,
        )
        .unwrap();
        assert_eq!(entry.username, "alice");
        assert_eq!(
            entry
                .field("recovery")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "must-not-cross-boundary"
        );

        {
            let live = service.session.as_mut().unwrap();
            let entry =
                resolve_locator_mut(&mut live.database, &reference.locator, reference.id).unwrap();
            entry.fields.pop();
        }
        service
            .set_fields(
                &reference,
                vec![
                    FieldUpdate {
                        key: "UserName".into(),
                        value: Zeroizing::new("changed".into()),
                        protected: Some(true),
                        protect_in_memory: Some(false),
                    },
                    FieldUpdate {
                        key: "recovery".into(),
                        value: Zeroizing::new("new-secret".into()),
                        protected: Some(true),
                        protect_in_memory: Some(false),
                    },
                ],
            )
            .unwrap();
        service.save(&path, &mut credentials()).unwrap();
        let mut reopened = VaultService::default();
        let reopened_session = reopened
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let fresh = reopened
            .resolve_entry(reopened_session, "mail")
            .unwrap()
            .reference();
        assert_eq!(reopened.selected_entry(&fresh).unwrap().title(), "mail");
        let user = reopened
            .field_metadata(&fresh)
            .unwrap()
            .into_iter()
            .find(|field| field.name() == "UserName")
            .unwrap();
        assert!(user.protected());
        assert!(!user.protect_in_memory());
        assert_eq!(
            reopened
                .reveal_field(&fresh, "UserName")
                .unwrap()
                .as_slice(),
            b"changed"
        );
        let custom = reopened
            .field_metadata(&fresh)
            .unwrap()
            .into_iter()
            .find(|field| field.name() == "recovery")
            .unwrap();
        assert!(custom.protected());
        assert!(!custom.protect_in_memory());
        assert_eq!(
            reopened
                .reveal_field(&fresh, "recovery")
                .unwrap()
                .as_slice(),
            b"new-secret"
        );
    }

    #[test]
    fn ensure_resolves_full_paths_refuses_bad_paths_and_respects_dry_run() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let root_name = service.session.as_ref().unwrap().database.root.name.clone();
        service
            .session
            .as_mut()
            .unwrap()
            .database
            .root
            .add_group(Group::new("prod"));
        assert_eq!(
            service.ensure_entry(session, "prod/new", Some(24), true),
            Ok(true)
        );
        assert!(matches!(
            service.resolve_entry(session, "prod/new"),
            Err(ServiceError::NotFound)
        ));
        assert_eq!(
            service.ensure_entry(session, &format!("{root_name}/prod/new"), Some(24), false),
            Ok(true)
        );
        assert_eq!(
            service.ensure_entry(session, &format!("{root_name}/at-root"), None, false),
            Ok(true)
        );
        assert!(service.resolve_entry(session, "at-root").is_ok());
        let created = service
            .resolve_entry(session, "prod/new")
            .unwrap()
            .reference();
        assert_eq!(
            service
                .reveal_field(&created, "Password")
                .unwrap()
                .as_slice()
                .len(),
            24
        );
        assert_eq!(
            service.ensure_entry(session, "prod/new", Some(0), false),
            Ok(false)
        );
        assert_eq!(
            service.ensure_entry(session, "missing/new", None, false),
            Ok(true)
        );
        assert_eq!(
            service.ensure_entry(session, "prod//bad", None, false),
            Err(ServiceError::InvalidInput)
        );

        let group = Group::new("Prod");
        service
            .session
            .as_mut()
            .unwrap()
            .database
            .root
            .add_group(group);
        assert_eq!(
            service.ensure_entry(session, "prod/ambiguous", None, false),
            Err(ServiceError::Ambiguous)
        );
        service.session.as_mut().unwrap().database.root.groups[0].add_entry(Entry::new("existing"));
        service.session.as_mut().unwrap().database.root.groups[0].add_entry(Entry::new("EXISTING"));
        assert_eq!(
            service.ensure_entry(session, "prod/existing", None, false),
            Err(ServiceError::Ambiguous)
        );
        assert_eq!(
            service.ensure_entry(session, &root_name, None, false),
            Err(ServiceError::RootGroup)
        );
    }

    fn add_depth_metadata(entry: &mut Entry) {
        let mut field = Field::new("protected-depth-field", "depth-secret");
        field.protected = true;
        field.protect_in_memory = true;
        entry.fields.push(field);
        entry.custom_data.set("depth-marker", "depth-value", None);
        entry
            .auto_type
            .associations
            .push(neotales_keepass::AutoTypeAssociation {
                window: "depth-window".into(),
                keystrokes: "{USERNAME}{TAB}{PASSWORD}".into(),
            });
    }

    fn assert_depth_metadata(entry: &Entry) {
        let field = entry.field("protected-depth-field").unwrap();
        assert!(field.protected);
        assert!(field.protect_in_memory);
        assert_eq!(field.value.reveal_text().unwrap().as_str(), "depth-secret");
        assert_eq!(entry.custom_data.get("depth-marker"), Some("depth-value"));
        assert_eq!(entry.auto_type.associations[0].window, "depth-window");
    }

    fn depth_database(groups: usize, history_generations: usize) -> KeePassDatabase {
        let mut entry = Entry::new("login");
        add_depth_metadata(&mut entry);
        for _ in 0..history_generations {
            let mut parent = Entry::new("login");
            add_depth_metadata(&mut parent);
            parent.history.push(entry);
            entry = parent;
        }
        let mut database = KeePassDatabase::default();
        let mut group = &mut database.root;
        for _ in 1..groups {
            group.add_group(Group::new("g"));
            group = &mut group.groups[0];
        }
        group.add_entry(entry);
        database
    }

    #[test]
    fn nested_history_depth_is_checked_before_creation_or_save() {
        let shallow = depth_database(MAX_CREATE_GROUPS - 2, 2);
        assert_eq!(validate_xml_depth(&shallow.root), Ok(()));
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("unchanged.kdbx");
        std::fs::write(&path, b"unchanged").unwrap();
        let mut service = service_with_database(depth_database(MAX_CREATE_GROUPS, 2));
        let session = SessionId(1);
        let before = format!("{:?}", service.session.as_ref().unwrap().database.root);
        let generation = service.session.as_ref().unwrap().generation;
        for dry_run in [true, false] {
            assert_eq!(
                service.ensure_group(session, "new/child", dry_run),
                Err(ServiceError::XmlDepth)
            );
            assert_eq!(
                service.ensure_entry(session, "new/child/login", Some(24), dry_run),
                Err(ServiceError::XmlDepth)
            );
        }
        assert_eq!(
            service.save(&path, &mut credentials()),
            Err(ServiceError::XmlDepth)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
        assert_eq!(service.session.as_ref().unwrap().generation, generation);
        let mut group = &mut service.session.as_mut().unwrap().database.root;
        while !group.groups.is_empty() {
            group = &mut group.groups[0];
        }
        let snapshot = &mut group.entries[0].history[0].history[0];
        snapshot.custom_data = neotales_keepass::CustomData::default();
        snapshot.auto_type.associations.clear();
        // Times/CreationTime still exceeds the XML policy without the deeper fields.
        assert_eq!(
            validate_xml_depth(&service.session.as_ref().unwrap().database.root),
            Err(ServiceError::XmlDepth)
        );
    }

    #[test]
    fn creation_depth_rejects_overflow_without_mutation() {
        let mut service = service_with_database(KeePassDatabase::default());
        let session = SessionId(1);
        service.ensure_group(session, "g", false).unwrap();
        let root_name = service.session.as_ref().unwrap().database.root.name.clone();
        let before = format!("{:?}", service.session.as_ref().unwrap().database.root);
        let generation = service.session.as_ref().unwrap().generation;
        for groups in [
            vec!["g"; MAX_CREATE_GROUPS].join("/"),
            vec!["g"; MAX_LOCATOR_DEPTH].join("/"),
        ] {
            for group_path in [&groups, &format!("{root_name}/{groups}")] {
                for dry_run in [true, false] {
                    assert_eq!(
                        service.ensure_group(session, group_path, dry_run),
                        Err(ServiceError::InvalidInput)
                    );
                    assert_eq!(
                        service.ensure_entry(
                            session,
                            &format!("{group_path}/login"),
                            None,
                            dry_run
                        ),
                        Err(ServiceError::InvalidInput)
                    );
                }
            }
        }
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
        assert_eq!(service.session.as_ref().unwrap().generation, generation);
    }

    #[test]
    fn creation_depth_boundary_remains_readable_and_can_be_saved_and_removed() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &crate::KDBX_LIMITS)
            .unwrap();
        let root_name = service.session.as_ref().unwrap().database.root.name.clone();
        let implicit = vec!["g"; MAX_CREATE_GROUPS - 1].join("/");
        let canonical = format!("{root_name}/{implicit}");
        assert_eq!(
            service.ensure_group(session, &implicit, true),
            Ok(MAX_CREATE_GROUPS - 1)
        );
        assert_eq!(
            service.ensure_group(session, &canonical, false),
            Ok(MAX_CREATE_GROUPS - 1)
        );
        assert_eq!(service.ensure_group(session, &implicit, false), Ok(0));
        let entry_path = format!("{implicit}/login");
        let canonical_entry = format!("{canonical}/login");
        assert_eq!(
            service.ensure_entry(session, &entry_path, None, false),
            Ok(true)
        );
        assert_eq!(
            service.ensure_entry(session, &canonical_entry, None, false),
            Ok(false)
        );
        let group_id = service.resolve_group(session, &implicit).unwrap().id;
        assert_eq!(
            service.resolve_group(session, &canonical).unwrap().id,
            group_id
        );
        let entry_id = service
            .resolve_entry(session, &canonical_entry)
            .unwrap()
            .reference()
            .id;
        let model_entry =
            entry_by_id_mut(&mut service.session.as_mut().unwrap().database, entry_id).unwrap();
        add_depth_metadata(model_entry);
        let mut snapshot = Entry::new("login");
        add_depth_metadata(&mut snapshot);
        model_entry.history.push(snapshot);
        assert_eq!(
            service
                .resolve_entry(session, &entry_path)
                .unwrap()
                .reference()
                .id,
            entry_id
        );
        let metadata = service.completion_metadata().unwrap();
        assert_eq!(metadata.groups.len(), MAX_CREATE_GROUPS);
        assert!(metadata.groups.contains(&canonical));
        let page = service.list_page(session, None, None).unwrap();
        assert!(page.next_cursor.is_none());
        assert!(page.hits.iter().any(|hit| hit.path() == canonical_entry));
        service.save(&path, &mut credentials()).unwrap();
        service.lock(session).unwrap();
        let session = service
            .open(&path, &mut credentials(), &crate::KDBX_LIMITS)
            .unwrap();
        assert_eq!(
            service.resolve_group(session, &canonical).unwrap().id,
            group_id
        );
        let entry = service
            .resolve_entry(session, &canonical_entry)
            .unwrap()
            .reference();
        assert_eq!(entry.id, entry_id);
        let model_entry =
            entry_by_id(&service.session.as_ref().unwrap().database, entry_id).unwrap();
        assert_depth_metadata(model_entry);
        assert_eq!(model_entry.history.len(), 1);
        assert_depth_metadata(&model_entry.history[0]);
        let page = service.list_page(session, None, None).unwrap();
        assert!(page.hits.iter().any(|hit| hit.path() == canonical_entry));
        service.remove_entry(&entry).unwrap();
        let group = service.resolve_group(session, &canonical).unwrap();
        service.remove_group(&group).unwrap();
        service.save(&path, &mut credentials()).unwrap();
        service.lock(session).unwrap();
        let session = service
            .open(&path, &mut credentials(), &crate::KDBX_LIMITS)
            .unwrap();
        assert_eq!(
            service.resolve_group(session, &canonical).err(),
            Some(ServiceError::NotFound)
        );
        assert_eq!(
            service.resolve_entry(session, &canonical_entry).err(),
            Some(ServiceError::NotFound)
        );
        let parent = implicit.rsplit_once('/').unwrap().0;
        assert!(service.resolve_group(session, parent).is_ok());
    }

    #[test]
    fn ensure_keeps_unique_existing_routes_when_the_root_name_also_names_a_child() {
        let mut database = KeePassDatabase::default();
        let root_name = database.root.name.clone();
        let mut child = Group::new(&root_name);
        child.add_entry(Entry::new("child-only"));
        database.root.add_group(child);
        database.root.add_group(Group::new("parent"));
        let mut service = service_with_database(database);
        let session = SessionId(1);
        let before = format!("{:?}", service.session.as_ref().unwrap().database.root);
        for dry_run in [true, false] {
            for path in [
                format!("{root_name}/child-only"),
                format!("{root_name}/{root_name}/child-only"),
            ] {
                assert_eq!(
                    service.ensure_entry(session, &path, None, dry_run),
                    Ok(false)
                );
            }
        }
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
        assert_eq!(
            service.ensure_entry(session, &format!("{root_name}/parent/new"), None, true),
            Ok(true)
        );
        assert_eq!(
            format!("{:?}", service.session.as_ref().unwrap().database.root),
            before
        );
        assert_eq!(
            service.ensure_entry(session, &format!("{root_name}/parent/new"), None, false),
            Ok(true)
        );
        assert!(service.resolve_entry(session, "parent/new").is_ok());
    }

    #[test]
    fn hierarchy_creation_keeps_existing_parents_and_dry_runs_do_not_mutate() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert_eq!(
            service.ensure_group(session, "team/service/prod", true),
            Ok(3)
        );
        assert!(matches!(
            service.resolve_group(session, "team"),
            Err(ServiceError::NotFound)
        ));
        assert_eq!(
            service.ensure_group(session, "team/service/prod", false),
            Ok(3)
        );
        let parent_id = service.resolve_group(session, "team/service").unwrap().id;
        assert_eq!(
            service.ensure_group(session, "TEAM/service/staging", false),
            Ok(1)
        );
        assert_eq!(
            service.resolve_group(session, "team/service").unwrap().id,
            parent_id
        );
        assert_eq!(
            service.ensure_group(session, "team/service/prod", false),
            Ok(0)
        );
        assert_eq!(
            service.ensure_entry(session, "team/service/deep/child/login", Some(24), true),
            Ok(true)
        );
        assert!(matches!(
            service.resolve_group(session, "team/service/deep"),
            Err(ServiceError::NotFound)
        ));
        assert_eq!(
            service.ensure_entry(session, "team/service/deep/child/login", Some(24), false),
            Ok(true)
        );
        let entry = service
            .resolve_entry(session, "team/service/deep/child/login")
            .unwrap()
            .reference();
        let entry_id = entry.id;
        let password = service
            .reveal_field(&entry, "Password")
            .unwrap()
            .as_slice()
            .to_vec();
        assert_eq!(
            service.ensure_entry(session, "TEAM/service/deep/child/LOGIN", Some(48), false),
            Ok(false)
        );
        assert_eq!(
            service.reveal_field(&entry, "Password").unwrap().as_slice(),
            password
        );
        service.save(&path, &mut credentials()).unwrap();
        service.lock(session).unwrap();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let entry = service
            .resolve_entry(session, "team/service/deep/child/login")
            .unwrap()
            .reference();
        assert_eq!(entry.id, entry_id);
        assert_eq!(
            service.reveal_field(&entry, "Password").unwrap().as_slice(),
            password
        );
        assert_eq!(
            service.resolve_group(session, "team/service").unwrap().id,
            parent_id
        );
    }

    #[test]
    fn hierarchy_creation_rejects_bad_and_ambiguous_paths_without_mutation() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let root = &mut service.session.as_mut().unwrap().database.root;
        let mut prod = Group::new("prod");
        prod.add_entry(Entry::new("existing"));
        root.add_group(prod);
        root.add_group(Group::new("Prod"));
        let generation = service.session.as_ref().unwrap().generation;
        assert_eq!(
            service.ensure_entry(session, "new/child/login", Some(0), false),
            Err(ServiceError::InvalidSize)
        );
        for dry_run in [true, false] {
            for path in ["prod/existing", "prod/missing/login"] {
                assert_eq!(
                    service.ensure_entry(session, path, Some(24), dry_run),
                    Err(ServiceError::Ambiguous)
                );
            }
            assert_eq!(
                service.ensure_group(session, "prod/missing/child", dry_run),
                Err(ServiceError::Ambiguous)
            );
            for path in [
                "",
                "/new",
                "new/",
                "new//child",
                "new/./child",
                "new/../child",
                "new/\nchild",
            ] {
                assert_eq!(
                    service.ensure_group(session, path, dry_run),
                    Err(ServiceError::InvalidInput)
                );
                assert_eq!(
                    service.ensure_entry(session, path, Some(24), dry_run),
                    Err(ServiceError::InvalidInput)
                );
            }
            let deep = vec!["x"; 258].join("/");
            assert_eq!(
                service.ensure_entry(session, &deep, None, dry_run),
                Err(ServiceError::InvalidInput)
            );
            assert_eq!(
                service.ensure_group(session, &deep, dry_run),
                Err(ServiceError::InvalidInput)
            );
            let long = "x".repeat(MAX_HIT_BYTES + 1);
            assert_eq!(
                service.ensure_entry(session, &long, None, dry_run),
                Err(ServiceError::InvalidInput)
            );
            assert_eq!(
                service.ensure_group(session, &long, dry_run),
                Err(ServiceError::InvalidInput)
            );
        }
        let root_name = service.session.as_ref().unwrap().database.root.name.clone();
        service
            .session
            .as_mut()
            .unwrap()
            .database
            .root
            .add_group(Group::new(&root_name));
        for dry_run in [true, false] {
            assert_eq!(
                service.ensure_entry(session, &format!("{root_name}/new/login"), None, dry_run),
                Err(ServiceError::Ambiguous)
            );
            assert_eq!(
                service.ensure_group(session, &format!("{root_name}/new"), dry_run),
                Err(ServiceError::Ambiguous)
            );
        }
        assert_eq!(service.session.as_ref().unwrap().generation, generation);
        assert_eq!(
            service.session.as_ref().unwrap().database.root.groups.len(),
            3
        );
    }

    #[test]
    fn renamed_root_keeps_personal_as_a_real_child_path() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let root = &mut service.session.as_mut().unwrap().database.root;
        root.name = "Work Vault".into();
        let mut personal = Group::new("Personal");
        personal.add_entry(Entry::new("Mail"));
        root.add_group(personal);

        assert_eq!(
            service
                .resolve_entry(session, "Personal/Mail")
                .unwrap()
                .path(),
            "Work Vault/Personal/Mail"
        );
        assert_eq!(
            service
                .resolve_entry(session, "Work Vault/Personal/Mail")
                .unwrap()
                .path(),
            "Work Vault/Personal/Mail"
        );
        assert_eq!(
            service.ensure_entry(session, "Personal/New", None, true),
            Ok(true)
        );
        assert_eq!(
            service.ensure_entry(session, "Work Vault/Personal/New", None, false),
            Ok(true)
        );
        assert!(service.resolve_entry(session, "Personal/New").is_ok());
    }

    #[test]
    fn listing_bounds_patterns_and_fails_explicitly_on_pathological_paths() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let maximum = "x".repeat(MAX_LIST_PATTERN_BYTES);
        assert!(service.list_page(session, Some(&maximum), None).is_ok());
        let oversized = "x".repeat(MAX_LIST_PATTERN_BYTES + 1);
        assert_eq!(
            service.list_page(session, Some(&oversized), None).err(),
            Some(ServiceError::InvalidInput)
        );

        let mut root = Group::new("Root");
        root.add_entry(Entry::new("x".repeat(MAX_PAGE_TEXT_WORK / 8 + 1)));
        let mut state = ListState::new(Some("*"), SessionId(1), 1);
        assert_eq!(
            scan_list_page(&root, &mut state).err(),
            Some(ServiceError::ResourceLimit)
        );
    }

    #[test]
    fn listing_reports_unvisited_over_depth_subtrees_as_incomplete() {
        let mut root = Group::new("Root");
        let mut current = &mut root;
        for index in 1..MAX_LOCATOR_DEPTH {
            current.groups.push(Group::new(format!("level-{index}")));
            current = current.groups.last_mut().unwrap();
        }
        current.groups.push(Group::new("too-deep"));
        let mut state = ListState::new(None, SessionId(1), 1);
        assert!(matches!(
            scan_list_page(&root, &mut state),
            Err(ServiceError::ResourceLimit)
        ));
    }

    #[test]
    fn listing_charges_complete_rendered_path_bytes() {
        let mut root = Group::new("Root");
        let mut child = Group::new("ancestor".repeat(1_000));
        child.add_entry(Entry::new("row"));
        root.add_group(child);
        let mut state = ListState::new(None, SessionId(1), 1);
        let page = scan_list_page(&root, &mut state).unwrap();
        assert_eq!(page.hits.len(), 1);
        let rendered_bytes = page.hits[0].path().len();
        assert!(state.total_text_work >= rendered_bytes * 8);
    }

    #[test]
    fn selected_entry_is_allowlisted_and_field_reads_are_explicit() {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("safe title");
        entry.tags.push("tag".into());
        entry.password = neotales_keepass::ProtectedValue::from_text("password secret");
        entry.notes = "notes secret".into();
        entry.fields.push(Field::new("recovery", "explicit secret"));
        entry.fields.push(Field::new("otp", "otpauth://secret"));
        entry.attachments.push(neotales_keepass::Attachment {
            name: "file.bin".into(),
            reference: database.binary_pool.add(vec![1, 2, 3], false),
        });
        let id = entry.id;
        database.root.add_entry(entry);
        let session = SessionId(44);
        let reference = EntryRef {
            session,
            generation: 1,
            id,
            locator: vec![0],
        };
        let service = VaultService {
            generation: 1,
            session: Some(LiveSession {
                id: session,
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };

        let view = service.selected_entry(&reference).unwrap();
        assert_eq!(view.title(), "safe title");
        assert_eq!(view.tags(), &["tag"]);
        assert_eq!(view.attachments()[0].name(), "file.bin");
        assert_eq!(view.attachments()[0].size(), 3);
        assert_eq!(
            view.custom_fields()
                .iter()
                .map(CustomFieldDescriptor::name)
                .collect::<Vec<_>>(),
            ["recovery", "otp"]
        );
        assert!(!view.has_otp());
        assert!(!view.auto_type_enabled());
        let field = view.custom_fields()[0].reference();
        assert_eq!(
            service.reveal_custom_field(&field).unwrap().as_slice(),
            b"explicit secret"
        );
    }

    #[test]
    fn attachment_metadata_is_bounded_and_reveal_is_explicit_and_session_bound() {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("attachment entry");
        entry.attachments.push(neotales_keepass::Attachment {
            name: "private.bin".into(),
            reference: database.binary_pool.add(vec![0, 1, 255], true),
        });
        let id = entry.id;
        database.root.add_entry(entry);
        let session = SessionId(91);
        let entry_reference = EntryRef {
            session,
            generation: 3,
            id,
            locator: vec![0],
        };
        let service = VaultService {
            generation: 3,
            session: Some(LiveSession {
                id: session,
                generation: 3,
                database,
            }),
            ..VaultService::default()
        };
        let metadata = service.attachment_metadata(&entry_reference).unwrap();
        assert_eq!(metadata[0].name(), "private.bin");
        assert_eq!(metadata[0].size(), 3);
        assert!(metadata[0].protected());
        let attachment_ref = metadata[0].reference();
        assert_eq!(
            service
                .reveal_attachment(&attachment_ref)
                .unwrap()
                .as_slice(),
            &[0, 1, 255]
        );

        let mut foreign = attachment_ref;
        foreign.entry.session = SessionId(92);
        assert!(matches!(
            service.reveal_attachment(&foreign),
            Err(ServiceError::Stale)
        ));
    }

    #[test]
    fn attachment_metadata_rejects_duplicate_unsafe_and_dangling_references() {
        fn with_attachments(attachments: Vec<neotales_keepass::Attachment>) -> VaultService {
            let mut database = KeePassDatabase::default();
            database.binary_pool.add(vec![1], true);
            let mut entry = Entry::new("attachments");
            entry.attachments = attachments;
            database.root.add_entry(entry);
            let session = SessionId(93);
            VaultService {
                generation: 1,
                session: Some(LiveSession {
                    id: session,
                    generation: 1,
                    database,
                }),
                ..VaultService::default()
            }
        }
        let attachment = |name: &str, reference| neotales_keepass::Attachment {
            name: name.into(),
            reference,
        };
        let duplicate = with_attachments(vec![attachment("same", 0), attachment("same", 0)]);
        let duplicate_ref = duplicate.session.as_ref().unwrap();
        let entry = &duplicate_ref.database.root.entries[0];
        let reference = EntryRef {
            session: duplicate_ref.id,
            generation: 1,
            id: entry.id,
            locator: vec![0],
        };
        assert!(matches!(
            duplicate.attachment_metadata(&reference),
            Err(ServiceError::Ambiguous)
        ));

        let unsafe_name = with_attachments(vec![attachment("bad\nname", 0)]);
        let live = unsafe_name.session.as_ref().unwrap();
        let entry = &live.database.root.entries[0];
        let reference = EntryRef {
            session: live.id,
            generation: 1,
            id: entry.id,
            locator: vec![0],
        };
        assert!(matches!(
            unsafe_name.attachment_metadata(&reference),
            Err(ServiceError::InvalidInput)
        ));

        let dangling = with_attachments(vec![attachment("dangling", 99)]);
        let live = dangling.session.as_ref().unwrap();
        let entry = &live.database.root.entries[0];
        let reference = EntryRef {
            session: live.id,
            generation: 1,
            id: entry.id,
            locator: vec![0],
        };
        assert!(matches!(
            dangling.attachment_metadata(&reference),
            Err(ServiceError::NotFound)
        ));
    }

    #[test]
    fn duplicate_exact_custom_field_names_remain_visible_but_cannot_be_revealed() {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("duplicate");
        entry.fields.push(Field::new("token", "first"));
        entry.fields.push(Field::new("token", "second"));
        let id = entry.id;
        database.root.add_entry(entry);
        let session = SessionId(45);
        let reference = EntryRef {
            session,
            generation: 1,
            id,
            locator: vec![0],
        };
        let service = VaultService {
            generation: 1,
            session: Some(LiveSession {
                id: session,
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        let selected = service.selected_entry(&reference).unwrap();
        assert_eq!(selected.custom_fields().len(), 2);
        assert_eq!(
            service
                .reveal_custom_field(&selected.custom_fields()[0].reference())
                .err(),
            Some(ServiceError::Ambiguous)
        );
    }

    #[test]
    fn reveal_field_handles_standard_custom_duplicate_and_stale_cases() {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("entry title");
        entry.password = neotales_keepass::ProtectedValue::from_text("password");
        entry.username = "username".into();
        entry.url = "https://example.test".into();
        entry.notes = "notes".into();
        entry.fields.push(Field::new("Token", "custom"));
        let id = entry.id;
        database.root.add_entry(entry);
        let session = SessionId(46);
        let reference = EntryRef {
            session,
            generation: 1,
            id,
            locator: vec![0],
        };
        let service = VaultService {
            generation: 1,
            session: Some(LiveSession {
                id: session,
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };

        for (name, expected) in [
            ("Password", b"password".as_slice()),
            ("Title", b"entry title".as_slice()),
            ("UserName", b"username".as_slice()),
            ("URL", b"https://example.test".as_slice()),
            ("Notes", b"notes".as_slice()),
            ("Token", b"custom".as_slice()),
        ] {
            assert_eq!(
                service.reveal_field(&reference, name).unwrap().as_slice(),
                expected
            );
        }
        assert_eq!(
            service.reveal_field(&reference, "Missing").err(),
            Some(ServiceError::NotFound)
        );
        let mut foreign = reference;
        foreign.session = SessionId(47);
        assert_eq!(
            service.reveal_field(&foreign, "Password").err(),
            Some(ServiceError::Stale)
        );
    }

    #[test]
    fn reveal_field_fails_closed_when_standard_name_is_duplicated() {
        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("duplicate");
        entry.fields.push(Field::new("Title", "shadow"));
        entry.fields.push(Field::new("Title", "second shadow"));
        let id = entry.id;
        database.root.add_entry(entry);
        let session = SessionId(48);
        let reference = EntryRef {
            session,
            generation: 1,
            id,
            locator: vec![0],
        };
        let service = VaultService {
            generation: 1,
            session: Some(LiveSession {
                id: session,
                generation: 1,
                database,
            }),
            ..VaultService::default()
        };
        assert_eq!(
            service.reveal_field(&reference, "Title").err(),
            Some(ServiceError::Ambiguous)
        );
    }

    #[test]
    fn lock_and_reopen_make_previous_entry_handles_stale() {
        let (_temp, path) = vault();
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let reference = service
            .search(session, "mail")
            .unwrap()
            .hits
            .remove(0)
            .reference();
        let mut another_service = VaultService::default();
        another_service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert_eq!(
            another_service.validate_entry(&reference),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            another_service.reveal_field(&reference, "Password").err(),
            Some(ServiceError::Stale)
        );
        service.lock(session).unwrap();
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        let next = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert_ne!(next, session);
        assert_eq!(service.validate_entry(&reference), Err(ServiceError::Stale));
        assert_eq!(
            service.reveal_field(&reference, "Password").err(),
            Some(ServiceError::Stale)
        );
    }

    #[test]
    fn duplicate_entry_ids_search_as_distinct_locatable_hits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("duplicate-ids.kdbx");
        let mut database = KeePassDatabase::default();
        let first = Entry::new("matching-duplicate");
        let shared_id = first.id;
        database.root.add_entry(first);
        let mut second = Entry::new("matching-duplicate");
        second.id = shared_id;
        database.root.add_entry(second);
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut KdbxCredentials::password("service-test-password").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();

        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let page = service.search(session, "matching").unwrap();
        assert_eq!(page.hits.len(), 2);
        let first = page.hits[0].reference();
        let second = page.hits[1].reference();
        assert!(first != second);
        assert!(service.validate_entry(&first).is_ok());
        assert!(service.validate_entry(&second).is_ok());
    }

    #[test]
    fn service_errors_have_fixed_non_vault_text() {
        assert_eq!(ServiceError::Unlock.message(), "cannot unlock vault");
        assert_eq!(
            ServiceError::Ambiguous.message(),
            "ambiguous vault identifiers"
        );
        assert_eq!(
            ServiceError::InvalidInput.message(),
            "invalid service input"
        );
    }

    #[test]
    fn search_contract_uses_only_the_allowlisted_candidates() {
        let mut group = Group::new("GroupNeedle");
        let mut title = Entry::new("TitleNeedle");
        title.password = neotales_keepass::ProtectedValue::from_text("passwordNeedle");
        title.notes = "notesNeedle".into();
        title
            .fields
            .push(Field::new("field-name-needle", "field-value-needle"));
        group.add_entry(title);
        let mut tag = Entry::new("tag-result");
        tag.tags.push("tagNeedle".into());
        group.add_entry(tag);
        let mut username = Entry::new("username-result");
        username.username = "userNeedle".into();
        group.add_entry(username);
        let mut url = Entry::new("url-result");
        url.url = "https://urlNeedle.test".into();
        group.add_entry(url);

        let (count, page) = search_tree(&group, "needle");
        assert_eq!(count, 4);
        assert_eq!(page.hits.len(), 4);
        for (query, expected_path) in [
            ("titleneedle", "GroupNeedle/TitleNeedle"),
            ("tagneedle", "GroupNeedle/tag-result"),
            ("userneedle", "GroupNeedle/username-result"),
            ("urlneedle", "GroupNeedle/url-result"),
        ] {
            let (count, page) = search_tree(&group, query);
            assert_eq!(count, 1, "search candidate {query:?} should match once");
            assert_eq!(page.hits[0].path(), expected_path);
        }
        let (count, _) = search_tree(&group, "TITLENEEDLE");
        assert_eq!(count, 1);
        for forbidden in [
            "passwordNeedle",
            "notesNeedle",
            "field-name-needle",
            "field-value-needle",
        ] {
            let (count, _) = search_tree(&group, forbidden);
            assert_eq!(count, 0, "forbidden search source {forbidden:?} matched");
        }
    }

    #[test]
    fn hostile_matches_do_not_use_safe_hit_slots_or_hide_later_rows() {
        let mut root = Group::new("Root");
        let mut hostile_group = Group::new(format!("needle{}", "x".repeat(MAX_HIT_BYTES)));
        for _ in 0..1_001 {
            hostile_group.add_entry(Entry::new("ordinary"));
        }
        root.add_group(hostile_group);
        let mut benign_group = Group::new("needle-later");
        benign_group.add_entry(Entry::new("survivor"));
        root.add_group(benign_group);

        let (count, page) = search_tree(&root, "needle");
        assert_eq!(count, 1_002);
        assert_eq!(page.withheld, 1_001);
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].path(), "Root/needle-later/survivor");
    }

    #[test]
    fn unsafe_group_path_is_withheld_and_later_benign_match_is_projected() {
        let mut root = Group::new("Root");
        for control in ['\u{1b}', '\u{85}', '\u{7f}'] {
            let mut group = Group::new(format!("needle{control}group"));
            group.add_entry(Entry::new("ordinary"));
            root.add_group(group);
        }
        root.add_entry(Entry::new("needle-benign"));

        let (count, page) = search_tree(&root, "needle");
        assert_eq!(count, 4);
        assert_eq!(page.withheld, 3);
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].path(), "Root/needle-benign");
    }

    #[test]
    fn search_continuation_pages_have_no_skips_or_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("paged-search.kdbx");
        let mut database = KeePassDatabase::default();
        for index in 0..1_005 {
            database
                .root
                .add_entry(Entry::new(format!("needle-{index:04}")));
        }
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut credentials(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();

        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let first = service.search(session, "needle").unwrap();
        assert_eq!(first.hits.len(), MAX_RESULTS);
        let cursor = first.next_cursor.expect("first page should continue");
        let second = service
            .search_page(session, "needle", Some(cursor))
            .unwrap();
        assert_eq!(second.hits.len(), 5);
        assert_eq!(second.next_cursor, None);

        let paths = first
            .hits
            .iter()
            .chain(&second.hits)
            .map(|hit| hit.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 1_005);
        assert_eq!(paths[0], "Root/needle-0000");
        assert_eq!(paths[1_004], "Root/needle-1004");
        assert_eq!(
            paths.iter().collect::<std::collections::HashSet<_>>().len(),
            1_005
        );
    }

    #[test]
    fn continuations_are_query_bound_and_single_use() {
        let (_temp, path) = vault_with_titles(1_005, "needle");
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let first = service.search(session, "needle").unwrap();
        let cursor = first.next_cursor.unwrap();
        assert!(matches!(
            service.search_page(session, "other", Some(cursor)),
            Err(ServiceError::Stale)
        ));
        let second = service
            .search_page(session, "needle", Some(cursor))
            .unwrap();
        assert_eq!(second.hits.len(), 5);
        assert!(matches!(
            service.search_page(session, "needle", Some(cursor)),
            Err(ServiceError::Stale)
        ));
    }

    #[test]
    fn active_cursor_limit_and_abandoned_cursor_cleanup_are_bounded() {
        let (_temp, path) = vault_with_titles(1_005, "needle");
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        let mut cursors = Vec::new();
        for _ in 0..MAX_ACTIVE_CURSORS {
            cursors.push(
                service
                    .search(session, "needle")
                    .unwrap()
                    .next_cursor
                    .unwrap(),
            );
        }
        assert_eq!(service.searches.len(), MAX_ACTIVE_CURSORS);
        assert!(matches!(
            service.search(session, "needle"),
            Err(ServiceError::ResourceLimit)
        ));

        let completed = service
            .search_page(session, "needle", Some(cursors[0]))
            .unwrap();
        assert_eq!(completed.hits.len(), 5);
        assert_eq!(completed.next_cursor, None);
        assert_eq!(service.searches.len(), MAX_ACTIVE_CURSORS - 1);
        let abandoned = cursors[1];
        service.lock(session).unwrap();
        assert!(service.searches.is_empty());
        let reopened = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();
        assert!(matches!(
            service.search_page(reopened, "needle", Some(abandoned)),
            Err(ServiceError::Stale)
        ));
    }

    #[test]
    fn explicit_cursor_release_frees_search_and_listing_state() {
        let (_temp, path) = vault_with_titles(1_005, "needle");
        let mut service = VaultService::default();
        let session = service
            .open(&path, &mut credentials(), &KdbxReadLimits::default())
            .unwrap();

        let search_cursor = service
            .search(session, "needle")
            .unwrap()
            .next_cursor
            .unwrap();
        assert!(service.release_search_cursor(search_cursor));
        assert!(!service.release_search_cursor(search_cursor));
        assert!(matches!(
            service.search_page(session, "needle", Some(search_cursor)),
            Err(ServiceError::Stale)
        ));
        assert!(service.searches.is_empty());

        let token = service.next_search_token.wrapping_add(1).max(1);
        service.next_search_token = token;
        let generation = service.session.as_ref().unwrap().generation;
        service
            .listings
            .insert(token, ListState::new(None, session, generation));
        let list_cursor = ListCursor {
            session,
            generation,
            token,
        };
        assert!(service.release_list_cursor(list_cursor));
        assert!(!service.release_list_cursor(list_cursor));
        assert!(matches!(
            service.list_page(session, None, Some(list_cursor)),
            Err(ServiceError::Stale)
        ));
        assert!(service.listings.is_empty());
    }

    fn vault_with_titles(count: usize, title: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("generated.kdbx");
        let mut database = KeePassDatabase::default();
        for index in 0..count {
            database
                .root
                .add_entry(Entry::new(format!("{title}-{index}")));
        }
        KdbxFile::save(
            &database,
            File::create(&path).unwrap(),
            &mut credentials(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..Default::default()
            },
            &KdbxReadLimits::default(),
        )
        .unwrap();
        (temp, path)
    }

    #[test]
    fn hostile_matches_over_ten_thousand_do_not_hide_later_benign_hits() {
        let mut root = Group::new("Root");
        for _ in 0..10_005 {
            root.add_entry(Entry::new("needle\u{1b}"));
        }
        root.add_entry(Entry::new("needle-benign"));
        let mut state = SearchState::new("needle", SessionId(1), 1);
        let mut withheld = 0;
        let mut hits = Vec::new();
        while state.has_more() {
            let previous = state.total_work;
            let page = scan_page(&root, &mut state).unwrap();
            assert!(state.total_work - previous <= MAX_PAGE_WORK);
            withheld += page.withheld;
            hits.extend(page.hits);
        }
        assert_eq!(withheld, 10_005);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title(), "needle-benign");
    }

    #[test]
    fn long_shared_group_label_is_matched_once_for_many_entries() {
        let mut root = Group::new("Root");
        let mut shared = Group::new(format!("needle-{}", "x".repeat(100_000)));
        for _ in 0..10_001 {
            shared.add_entry(Entry::new("ordinary"));
        }
        root.add_group(shared);
        let mut later = Group::new("later");
        later.add_entry(Entry::new("needle-survivor"));
        root.add_group(later);

        let mut state = SearchState::new("needle", SessionId(1), 1);
        let mut withheld = 0;
        let mut hits = Vec::new();
        while state.has_more() {
            let page = scan_page(&root, &mut state).unwrap();
            withheld += page.withheld;
            hits.extend(page.hits);
        }
        assert_eq!(withheld, 10_001);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title(), "needle-survivor");
        // Rechecking the 100 KiB ancestor for each record would exceed the
        // global byte-work budget; it is charged once when its frame is entered.
        assert!(state.total_text_work < MAX_SEARCH_TEXT_WORK);
    }

    #[test]
    fn continuation_resumes_without_revisiting_prior_entries() {
        let mut root = Group::new("Root");
        for index in 0..1_005 {
            root.add_entry(Entry::new(format!("needle-{index:04}")));
        }
        let mut state = SearchState::new("needle", SessionId(1), 1);
        let first = scan_page(&root, &mut state).unwrap();
        assert_eq!(first.hits.len(), MAX_RESULTS);
        let visits_after_first = state.total_work;
        assert_eq!(visits_after_first, 1 + MAX_RESULTS); // root plus emitted entries
        let second = scan_page(&root, &mut state).unwrap();
        assert_eq!(second.hits.len(), 5);
        assert_eq!(state.total_work - visits_after_first, 5);
        assert!(!state.has_more());
    }

    #[test]
    fn page_work_is_bounded_for_unmatched_entries_and_exact_end_has_no_empty_page() {
        let mut root = Group::new("Root");
        for _ in 0..MAX_PAGE_WORK {
            root.add_entry(Entry::new("unmatched"));
        }
        root.add_entry(Entry::new("needle-last"));
        let mut state = SearchState::new("needle", SessionId(1), 1);
        let first = scan_page(&root, &mut state).unwrap();
        assert!(first.hits.is_empty());
        assert_eq!(state.total_work, MAX_PAGE_WORK);
        assert!(state.has_more());
        let second = scan_page(&root, &mut state).unwrap();
        assert_eq!(second.hits.len(), 1);
        assert!(!state.has_more());
    }

    #[test]
    fn oversized_metadata_is_withheld_without_suppressing_following_rows() {
        let mut root = Group::new("Root");
        let mut oversized = Entry::new("needle-oversized");
        for index in 0..=MAX_METADATA_ITEMS {
            oversized
                .fields
                .push(Field::new(format!("field-{index}"), "value"));
        }
        root.add_entry(oversized);
        root.add_entry(Entry::new("needle-safe"));
        let (_, page) = search_tree(&root, "needle");
        assert_eq!(page.withheld, 1);
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].title(), "needle-safe");
    }

    #[test]
    fn byte_budget_rejects_large_projection_before_copying_and_keeps_later_rows() {
        let mut root = Group::new("Root");
        let mut oversized = Entry::new("needle-large-metadata");
        oversized.tags = (0..MAX_METADATA_ITEMS)
            .map(|index| format!("tag-{index}-{}", "x".repeat(128)))
            .collect();
        root.add_entry(oversized);
        root.add_entry(Entry::new("needle-safe"));
        let (_, page) = search_tree(&root, "needle");
        assert_eq!(page.withheld, 1);
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].title(), "needle-safe");
    }

    #[test]
    fn global_work_limit_is_an_explicit_incomplete_error() {
        let mut root = Group::new("Root");
        root.add_entry(Entry::new("needle-first"));
        root.add_entry(Entry::new("needle-pending"));
        let mut state = SearchState::new("needle", SessionId(1), 1);
        state.total_work = MAX_SEARCH_WORK - 2;
        assert!(matches!(
            scan_page(&root, &mut state),
            Err(ServiceError::ResourceLimit)
        ));
        assert_eq!(state.total_work, MAX_SEARCH_WORK);
        assert_eq!(state.stack[0].next_entry, 1);
        assert_eq!(
            ServiceError::ResourceLimit.message(),
            "search incomplete: resource limit reached"
        );
    }

    #[test]
    fn single_pathological_candidate_fails_instead_of_being_silently_skipped() {
        let mut root = Group::new("Root");
        root.add_entry(Entry::new("x".repeat(MAX_PAGE_TEXT_WORK / 8 + 1)));
        let mut state = SearchState::new("needle", SessionId(1), 1);
        assert!(matches!(
            scan_page(&root, &mut state),
            Err(ServiceError::ResourceLimit)
        ));
    }

    #[test]
    fn maximum_supported_tree_depth_uses_iterative_traversal() {
        let mut root = Group::new("Root");
        let mut current = &mut root;
        for index in 1..MAX_LOCATOR_DEPTH {
            current.groups.push(Group::new(format!("level-{index}")));
            current = current.groups.last_mut().unwrap();
        }
        current.add_entry(Entry::new("needle-deep"));
        let mut state = SearchState::new("needle", SessionId(1), 1);
        let page = scan_page(&root, &mut state).unwrap();
        assert_eq!(page.hits.len(), 1);
        assert_eq!(page.hits[0].title(), "needle-deep");
    }

    #[test]
    fn excessive_group_depth_is_not_recursed_into() {
        let mut root = Group::new("Root");
        let mut current = &mut root;
        for index in 0..(MAX_LOCATOR_DEPTH + 32) {
            current.groups.push(Group::new(format!("level-{index}")));
            current = current.groups.last_mut().unwrap();
        }
        current.add_entry(Entry::new("needle-too-deep"));

        let (count, page) = search_tree(&root, "needle");
        assert_eq!(count, 0);
        assert!(page.hits.is_empty());
    }

    #[test]
    fn completed_page_stops_before_visiting_descendants() {
        let mut root = Group::new("Root");
        for index in 0..MAX_RESULTS {
            root.add_entry(Entry::new(format!("needle-{index}")));
        }
        let mut later = Group::new("later");
        later.add_entry(Entry::new("needle-not-scanned"));
        root.add_group(later);

        let mut state = SearchState::new("needle", SessionId(1), 1);
        let page = scan_page(&root, &mut state).unwrap();
        assert_eq!(page.hits.len(), MAX_RESULTS);
        assert!(state.has_more());
    }
}

#[cfg(all(test, windows))]
mod windows_secure_write_tests {
    use super::{ServiceError, permission_failure};

    #[test]
    fn unsupported_secure_permissions_survive_save_and_create_error_mapping() {
        const PLATFORM_ERROR: &str = "owner-only Windows ACL replacement is unsupported";
        for fallback in [ServiceError::SaveStage, ServiceError::CreatePermissions] {
            let error = permission_failure(PLATFORM_ERROR, fallback);
            assert_eq!(error, ServiceError::SecureFilePermissionsUnsupported);
            assert!(error.message().contains("secure owner-only file writes"));
        }
    }
}
