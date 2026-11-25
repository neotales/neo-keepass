//! Bounded, explicit-disclosure interchange and batch-edit formats for the nkp
//! CLI.

#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::drop_non_drop,
    clippy::needless_pass_by_value,
    clippy::serde_api_misuse,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    reason = "wire records intentionally mirror the complete KeePass model"
)]

use std::collections::BTreeSet;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use neotales_keepass::{
    Attachment, AutoType, AutoTypeAssociation, BinaryPool, CustomData, CustomIcon, DeletedObject,
    Entry, Field, Group, KdbxColor, KdbxTimestamp, KdbxUuid, KeePassDatabase, KeePassMeta,
    KeePassTimes, ProtectedValue, VariantDictionary, VariantValue,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroizing;

pub(crate) const FORMAT: &str = "org.neotales.nkeepass.interchange";
pub(crate) const VERSION: u32 = 1;

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_groups: usize,
    pub max_entries: usize,
    pub max_history_entries: usize,
    pub max_fields: usize,
    pub max_binary_records: usize,
    pub max_binary_bytes: u64,
    pub max_secret_bytes: u64,
    pub max_text_bytes: usize,
}

pub(crate) const VAULT_LIMITS: Limits = Limits {
    // The KDBX loader currently admits 64 MiB of binary data. Base64 and JSON
    // expansion leave enough room for the complete supported model below it.
    max_bytes: 128 * 1024 * 1024,
    max_depth: 128,
    max_groups: 100_000,
    max_entries: 100_000,
    max_history_entries: 100_000,
    max_fields: 1_000_000,
    max_binary_records: 1_000_000,
    max_binary_bytes: 64 * 1024 * 1024,
    max_secret_bytes: 64 * 1024 * 1024,
    max_text_bytes: 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterchangeError(&'static str);

impl InterchangeError {
    pub(crate) const fn message(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for InterchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for InterchangeError {}

type Result<T> = std::result::Result<T, InterchangeError>;

const fn invalid() -> InterchangeError {
    InterchangeError("invalid interchange document")
}

const fn too_large() -> InterchangeError {
    InterchangeError("interchange input exceeds size limit")
}

const fn unsupported() -> InterchangeError {
    InterchangeError("vault contains unsupported data that cannot be exported losslessly")
}

const fn duplicate_typed_custom_data_key() -> InterchangeError {
    InterchangeError("interchange contains duplicate typed custom-data keys")
}

/// A non-debug secret string used by the batch-edit input format.
pub(crate) struct SecretText(Zeroizing<String>);

impl SecretText {
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SecretVisitor;

        impl de::Visitor<'_> for SecretVisitor {
            type Value = SecretText;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a UTF-8 secret value")
            }

            fn visit_borrowed_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SecretText(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SecretText(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SecretVisitor)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format: &'static str,
    version: u32,
    kind: &'static str,
    database: DatabaseWire,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DatabaseWire {
    meta: MetaWire,
    root: GroupWire,
    deleted_objects: Vec<DeletedObjectWire>,
    binary_pool: Vec<BinaryWire>,
    public_custom_data: Vec<CustomDataWire>,
    typed_public_custom_data: Vec<VariantDictionaryWire>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct MetaWire {
    generator: String,
    name: String,
    description: String,
    default_username: String,
    settings_changed: Option<i64>,
    database_name_changed: Option<i64>,
    database_description_changed: Option<i64>,
    default_username_changed: Option<i64>,
    master_key_changed: Option<i64>,
    maintenance_history_days: u32,
    color: Option<[u8; 3]>,
    master_key_change_rec: i64,
    master_key_change_force: i64,
    master_key_change_force_once: bool,
    protect_password: bool,
    protect_title: bool,
    protect_username: bool,
    protect_url: bool,
    protect_notes: bool,
    times: TimesWire,
    history_max_items: Option<i64>,
    history_max_size: Option<i64>,
    memory_protection: bool,
    recycle_bin_enabled: bool,
    recycle_bin_uuid: String,
    recycle_bin_changed: Option<i64>,
    templates_uuid: String,
    templates_changed: Option<i64>,
    selected_group_uuid: String,
    top_visible_group_uuid: String,
    custom_data: Vec<CustomDataWire>,
    legacy_binaries: Vec<SecretB64>,
    custom_icons: Vec<CustomIconWire>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GroupWire {
    id: String,
    name: String,
    notes: String,
    icon_id: u32,
    custom_icon_id: String,
    times: TimesWire,
    is_expanded: bool,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
    default_auto_type_sequence: String,
    last_top_visible_entry_id: String,
    previous_parent_group_id: String,
    custom_data: Vec<CustomDataWire>,
    groups: Vec<GroupWire>,
    entries: Vec<EntryWire>,
    tags: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    id: String,
    title: String,
    username: String,
    password: ProtectedWire,
    url: String,
    override_url: String,
    notes: String,
    icon_id: u32,
    custom_icon_id: String,
    foreground_color: Option<[u8; 3]>,
    background_color: Option<[u8; 3]>,
    quality_check: Option<bool>,
    previous_parent_group_id: String,
    tags: Vec<String>,
    times: TimesWire,
    fields: Vec<FieldWire>,
    attachments: Vec<AttachmentWire>,
    auto_type: AutoTypeWire,
    custom_data: Vec<CustomDataWire>,
    history: Vec<EntryWire>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FieldWire {
    key: String,
    value: ProtectedWire,
    protected: bool,
    protect_in_memory: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedWire {
    value: SecretB64,
    memory_protected: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AttachmentWire {
    name: String,
    reference: usize,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AutoTypeWire {
    enabled: Option<bool>,
    obfuscated: Option<bool>,
    default_sequence: String,
    associations: Vec<AutoTypeAssociationWire>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AutoTypeAssociationWire {
    window: String,
    keystrokes: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct TimesWire {
    created: i64,
    modified: i64,
    accessed: i64,
    expires: i64,
    expires_enabled: bool,
    usage_count: u64,
    location_changed: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomDataWire {
    key: String,
    value: String,
    last_modification: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantDictionaryWire {
    key: String,
    value: VariantValueWire,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum VariantValueWire {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    Bytes(SecretB64),
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CustomIconWire {
    uuid: String,
    data: SecretB64,
    name: Option<String>,
    last_modification: Option<i64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryWire {
    data: SecretB64,
    protected: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DeletedObjectWire {
    id: String,
    deleted_at: i64,
}

struct SecretB64(Zeroizing<String>);

impl SecretB64 {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(STANDARD.encode(bytes)))
    }

    fn decode(&self) -> Result<Zeroizing<Vec<u8>>> {
        STANDARD
            .decode(self.0.as_str())
            .map(Zeroizing::new)
            .map_err(|_| invalid())
    }
}

impl Serialize for SecretB64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretB64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct B64Visitor;

        impl de::Visitor<'_> for B64Visitor {
            type Value = SecretB64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Base64 string")
            }

            fn visit_borrowed_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if !value.len().is_multiple_of(4) {
                    return Err(E::custom("invalid Base64 length"));
                }
                Ok(SecretB64(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, mut value: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                if !value.len().is_multiple_of(4) {
                    value.zeroize();
                    return Err(E::custom("invalid Base64 length"));
                }
                Ok(SecretB64(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(B64Visitor)
    }
}

use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseInput {
    meta: MetaInput,
    root: GroupInput,
    deleted_objects: Vec<DeletedObjectInput>,
    binary_pool: Vec<BinaryInput>,
    public_custom_data: Vec<CustomDataWire>,
    typed_public_custom_data: Vec<VariantDictionaryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotInput {
    format: String,
    version: u32,
    kind: String,
    database: DatabaseInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaInput {
    generator: String,
    name: String,
    description: String,
    default_username: String,
    settings_changed: Option<i64>,
    database_name_changed: Option<i64>,
    database_description_changed: Option<i64>,
    default_username_changed: Option<i64>,
    master_key_changed: Option<i64>,
    maintenance_history_days: u32,
    color: Option<[u8; 3]>,
    master_key_change_rec: i64,
    master_key_change_force: i64,
    master_key_change_force_once: bool,
    protect_password: bool,
    protect_title: bool,
    protect_username: bool,
    protect_url: bool,
    protect_notes: bool,
    times: TimesInput,
    history_max_items: Option<i64>,
    history_max_size: Option<i64>,
    memory_protection: bool,
    recycle_bin_enabled: bool,
    recycle_bin_uuid: String,
    recycle_bin_changed: Option<i64>,
    templates_uuid: String,
    templates_changed: Option<i64>,
    selected_group_uuid: String,
    top_visible_group_uuid: String,
    custom_data: Vec<CustomDataWire>,
    legacy_binaries: Vec<SecretB64>,
    custom_icons: Vec<CustomIconInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupInput {
    id: String,
    name: String,
    notes: String,
    icon_id: u32,
    custom_icon_id: String,
    times: TimesInput,
    is_expanded: bool,
    enable_auto_type: Option<bool>,
    enable_searching: Option<bool>,
    default_auto_type_sequence: String,
    last_top_visible_entry_id: String,
    previous_parent_group_id: String,
    custom_data: Vec<CustomDataWire>,
    groups: Vec<GroupInput>,
    entries: Vec<EntryInput>,
    tags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryInput {
    id: String,
    title: String,
    username: String,
    password: ProtectedInput,
    url: String,
    #[serde(default)]
    override_url: String,
    notes: String,
    icon_id: u32,
    custom_icon_id: String,
    foreground_color: Option<[u8; 3]>,
    background_color: Option<[u8; 3]>,
    quality_check: Option<bool>,
    previous_parent_group_id: String,
    tags: Vec<String>,
    times: TimesInput,
    fields: Vec<FieldInput>,
    attachments: Vec<AttachmentInput>,
    auto_type: AutoTypeInput,
    custom_data: Vec<CustomDataWire>,
    history: Vec<EntryInput>,
    /// Absent in every document written before this field existed, which is the
    /// point: an absent key is not an instruction and changes nothing.
    ensure: Option<EnsureInput>,
}

/// The `ensure` member of an entry: a request to generate a Password.
///
/// Nested rather than two sibling keys beside twenty others. A flat
/// `{"ensure": true, "size": 32}` makes `size` a key that means nothing unless
/// `ensure` is present, and a policy file with that key misspelled or omitted
/// reads exactly like a converged one. Here `size` is required *inside* the
/// directive, so a half-specified request is refused instead of silently doing
/// nothing -- and a directive with no size would have meant "give this entry an
/// empty password", which is what an absent directive already means.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnsureInput {
    size: u64,
}

/// One entry's generate-on-import request, as the file asked for it.
///
/// The size is the raw document value. The CLI's generated-password bound is a
/// property of the command that acts on the directive, not of the wire format,
/// so decoding applies no policy the writer never had to satisfy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnsureDirective {
    pub id: KdbxUuid,
    pub size: u64,
}

/// A decoded snapshot together with the directives that arrived with it.
///
/// The directives are returned beside the database instead of being stored in
/// it. A generated password is vault state; "this file asked for one" is a
/// property of the file. Keeping them apart is what lets `export` remain a
/// lossless snapshot of vault state, and leaves nothing written into the user's
/// vault to explain later.
pub(crate) struct Decoded {
    pub database: KeePassDatabase,
    pub directives: Vec<EnsureDirective>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldInput {
    key: String,
    value: ProtectedInput,
    protected: bool,
    protect_in_memory: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedInput {
    value: SecretB64,
    memory_protected: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentInput {
    name: String,
    reference: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutoTypeInput {
    enabled: Option<bool>,
    obfuscated: Option<bool>,
    default_sequence: String,
    associations: Vec<AutoTypeAssociationInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutoTypeAssociationInput {
    window: String,
    keystrokes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimesInput {
    created: i64,
    modified: i64,
    accessed: i64,
    expires: i64,
    expires_enabled: bool,
    usage_count: u64,
    location_changed: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomIconInput {
    uuid: String,
    data: SecretB64,
    name: Option<String>,
    last_modification: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryInput {
    data: SecretB64,
    protected: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletedObjectInput {
    id: String,
    deleted_at: i64,
}

pub(crate) fn encode(database: &KeePassDatabase) -> Result<Zeroizing<Vec<u8>>> {
    encode_with_limits(database, VAULT_LIMITS)
}

fn encode_with_limits(database: &KeePassDatabase, limits: Limits) -> Result<Zeroizing<Vec<u8>>> {
    if !database.can_save_losslessly {
        return Err(unsupported());
    }
    validate_model(database, limits)?;
    let mut budget = ConversionBudget {
        secret_bytes: 0,
        binary_bytes: 0,
    };
    let snapshot = Snapshot {
        format: FORMAT,
        version: VERSION,
        kind: "vault-snapshot",
        database: database_to_wire(database, &mut budget)?,
    };
    let bytes = serde_json::to_vec(&snapshot).map_err(|_| invalid())?;
    if bytes.len() > limits.max_bytes {
        return Err(too_large());
    }
    Ok(Zeroizing::new(bytes))
}

pub(crate) fn decode(input: &[u8]) -> Result<Decoded> {
    decode_with_limits(input, VAULT_LIMITS)
}

fn decode_with_limits(input: &[u8], limits: Limits) -> Result<Decoded> {
    if input.len() > limits.max_bytes {
        return Err(too_large());
    }
    let snapshot: SnapshotInput = serde_json::from_slice(input).map_err(|_| invalid())?;
    if snapshot.format != FORMAT || snapshot.version != VERSION || snapshot.kind != "vault-snapshot"
    {
        return Err(InterchangeError(
            "unsupported interchange format or version",
        ));
    }
    if snapshot.database.binary_pool.len() > limits.max_binary_records {
        return Err(too_large());
    }
    let mut budget = ConversionBudget {
        secret_bytes: 0,
        binary_bytes: 0,
    };
    let mut directives = Vec::new();
    let mut database = database_from_wire(snapshot.database, &mut budget, &mut directives)?;
    database.can_save_losslessly = true;
    validate_model(&database, limits)?;
    Ok(Decoded {
        database,
        directives,
    })
}

struct ConversionBudget {
    secret_bytes: u64,
    binary_bytes: u64,
}

impl ConversionBudget {
    fn secret(&mut self, count: usize, limits: Limits) -> Result<()> {
        self.secret_bytes = self
            .secret_bytes
            .checked_add(count as u64)
            .ok_or_else(too_large)?;
        if self.secret_bytes > limits.max_secret_bytes {
            return Err(too_large());
        }
        Ok(())
    }

    fn binary(&mut self, count: usize, limits: Limits) -> Result<()> {
        self.binary_bytes = self
            .binary_bytes
            .checked_add(count as u64)
            .ok_or_else(too_large)?;
        if self.binary_bytes > limits.max_binary_bytes {
            return Err(too_large());
        }
        Ok(())
    }
}

fn database_to_wire(
    database: &KeePassDatabase,
    budget: &mut ConversionBudget,
) -> Result<DatabaseWire> {
    let mut binary_pool = Vec::with_capacity(database.binary_pool.len());
    for record in database.binary_pool.records() {
        budget.binary(record.data.len(), VAULT_LIMITS)?;
        budget.secret(record.data.len(), VAULT_LIMITS)?;
        binary_pool.push(BinaryWire {
            data: SecretB64::from_bytes(&record.data),
            protected: record.protected,
        });
    }
    let mut legacy_binaries = Vec::with_capacity(database.meta.legacy_binaries.len());
    for data in &database.meta.legacy_binaries {
        budget.binary(data.len(), VAULT_LIMITS)?;
        budget.secret(data.len(), VAULT_LIMITS)?;
        legacy_binaries.push(SecretB64::from_bytes(data));
    }
    let mut custom_icons = Vec::with_capacity(database.meta.custom_icons.len());
    for icon in &database.meta.custom_icons {
        budget.binary(icon.data.len(), VAULT_LIMITS)?;
        budget.secret(icon.data.len(), VAULT_LIMITS)?;
        custom_icons.push(CustomIconWire {
            uuid: icon.uuid.to_base64(),
            data: SecretB64::from_bytes(&icon.data),
            name: icon.name.clone(),
            last_modification: icon.last_modification.map(|value| value.0),
        });
    }
    let meta = &database.meta;
    Ok(DatabaseWire {
        meta: MetaWire {
            generator: meta.generator.clone(),
            name: meta.name.clone(),
            description: meta.description.clone(),
            default_username: meta.default_username.clone(),
            settings_changed: meta.settings_changed.map(|value| value.0),
            database_name_changed: meta.database_name_changed.map(|value| value.0),
            database_description_changed: meta.database_description_changed.map(|value| value.0),
            default_username_changed: meta.default_username_changed.map(|value| value.0),
            master_key_changed: meta.master_key_changed.map(|value| value.0),
            maintenance_history_days: meta.maintenance_history_days,
            color: meta.color.rgb,
            master_key_change_rec: meta.master_key_change_rec,
            master_key_change_force: meta.master_key_change_force,
            master_key_change_force_once: meta.master_key_change_force_once,
            protect_password: meta.protect_password,
            protect_title: meta.protect_title,
            protect_username: meta.protect_username,
            protect_url: meta.protect_url,
            protect_notes: meta.protect_notes,
            times: times_to_wire(meta.times),
            history_max_items: meta.history_max_items,
            history_max_size: meta.history_max_size,
            memory_protection: meta.memory_protection,
            recycle_bin_enabled: meta.recycle_bin_enabled,
            recycle_bin_uuid: meta.recycle_bin_uuid.to_base64(),
            recycle_bin_changed: meta.recycle_bin_changed.map(|value| value.0),
            templates_uuid: meta.templates_uuid.to_base64(),
            templates_changed: meta.templates_changed.map(|value| value.0),
            selected_group_uuid: meta.selected_group_uuid.to_base64(),
            top_visible_group_uuid: meta.top_visible_group_uuid.to_base64(),
            custom_data: custom_data_to_wire(&meta.custom_data),
            legacy_binaries,
            custom_icons,
        },
        root: group_to_wire(&database.root, 1, budget)?,
        deleted_objects: database
            .deleted_objects
            .iter()
            .map(|item| DeletedObjectWire {
                id: item.id.to_base64(),
                deleted_at: item.deleted_at.0,
            })
            .collect(),
        binary_pool,
        public_custom_data: custom_data_to_wire(&database.public_custom_data),
        typed_public_custom_data: dictionary_to_wire(&database.typed_public_custom_data, budget)?,
    })
}

fn group_to_wire(group: &Group, depth: usize, budget: &mut ConversionBudget) -> Result<GroupWire> {
    let mut entries = Vec::with_capacity(group.entries.len());
    for entry in &group.entries {
        entries.push(entry_to_wire(entry, depth + 1, budget)?);
    }
    let mut groups = Vec::with_capacity(group.groups.len());
    for child in &group.groups {
        groups.push(group_to_wire(child, depth + 1, budget)?);
    }
    Ok(GroupWire {
        id: group.id.to_base64(),
        name: group.name.clone(),
        notes: group.notes.clone(),
        icon_id: group.icon_id,
        custom_icon_id: group.custom_icon_id.to_base64(),
        times: times_to_wire(group.times),
        is_expanded: group.is_expanded,
        enable_auto_type: group.enable_auto_type,
        enable_searching: group.enable_searching,
        default_auto_type_sequence: group.default_auto_type_sequence.clone(),
        last_top_visible_entry_id: group.last_top_visible_entry_id.to_base64(),
        previous_parent_group_id: group.previous_parent_group_id.to_base64(),
        custom_data: custom_data_to_wire(&group.custom_data),
        groups,
        entries,
        tags: group.tags.clone(),
    })
}

fn entry_to_wire(entry: &Entry, depth: usize, budget: &mut ConversionBudget) -> Result<EntryWire> {
    if depth > VAULT_LIMITS.max_depth {
        return Err(too_large());
    }
    let mut history = Vec::with_capacity(entry.history.len());
    for snapshot in &entry.history {
        history.push(entry_to_wire(snapshot, depth + 1, budget)?);
    }
    let mut fields = Vec::with_capacity(entry.fields.len());
    for field in &entry.fields {
        fields.push(FieldWire {
            key: field.key.clone(),
            value: protected_to_wire(&field.value, budget)?,
            protected: field.protected,
            protect_in_memory: field.protect_in_memory,
        });
    }
    let title = standard_text(entry, "Title", &entry.title)?;
    let username = standard_text(entry, "UserName", &entry.username)?;
    let url = standard_text(entry, "URL", &entry.url)?;
    let notes = standard_text(entry, "Notes", &entry.notes)?;
    let password = entry
        .field("Password")
        .map_or(&entry.password, |field| &field.value);
    Ok(EntryWire {
        id: entry.id.to_base64(),
        title,
        username,
        password: protected_to_wire(password, budget)?,
        url,
        override_url: entry.override_url.clone(),
        notes,
        icon_id: entry.icon_id,
        custom_icon_id: entry.custom_icon_id.to_base64(),
        foreground_color: entry.foreground_color.rgb,
        background_color: entry.background_color.rgb,
        quality_check: entry.quality_check,
        previous_parent_group_id: entry.previous_parent_group_id.to_base64(),
        tags: entry.tags.clone(),
        times: times_to_wire(entry.times),
        fields,
        attachments: entry
            .attachments
            .iter()
            .map(|item| AttachmentWire {
                name: item.name.clone(),
                reference: item.reference,
            })
            .collect(),
        auto_type: AutoTypeWire {
            enabled: entry.auto_type.enabled,
            obfuscated: entry.auto_type.obfuscated,
            default_sequence: entry.auto_type.default_sequence.clone(),
            associations: entry
                .auto_type
                .associations
                .iter()
                .map(|item| AutoTypeAssociationWire {
                    window: item.window.clone(),
                    keystrokes: item.keystrokes.clone(),
                })
                .collect(),
        },
        custom_data: custom_data_to_wire(&entry.custom_data),
        history,
    })
}

fn standard_text(entry: &Entry, key: &str, scalar: &str) -> Result<String> {
    entry.field(key).map_or_else(
        || Ok(scalar.to_owned()),
        |field| {
            field
                .value
                .reveal_text()
                .map(|value| value.as_str().to_owned())
                .map_err(|_| unsupported())
        },
    )
}

fn protected_to_wire(
    value: &ProtectedValue,
    budget: &mut ConversionBudget,
) -> Result<ProtectedWire> {
    let bytes = value.reveal_bytes().map_err(|_| unsupported())?;
    budget.secret(bytes.len(), VAULT_LIMITS)?;
    Ok(ProtectedWire {
        value: SecretB64::from_bytes(bytes.as_slice()),
        memory_protected: value.is_memory_protected(),
    })
}

fn times_to_wire(times: KeePassTimes) -> TimesWire {
    TimesWire {
        created: times.created.0,
        modified: times.modified.0,
        accessed: times.accessed.0,
        expires: times.expires.0,
        expires_enabled: times.expires_enabled,
        usage_count: times.usage_count,
        location_changed: times.location_changed.0,
    }
}

fn custom_data_to_wire(data: &CustomData) -> Vec<CustomDataWire> {
    data.items()
        .iter()
        .map(|item| CustomDataWire {
            key: item.key.clone(),
            value: item.value.clone(),
            last_modification: item.last_modification.map(|value| value.0),
        })
        .collect()
}

fn dictionary_to_wire(
    dictionary: &VariantDictionary,
    budget: &mut ConversionBudget,
) -> Result<Vec<VariantDictionaryWire>> {
    let mut output = Vec::with_capacity(dictionary.items().len());
    for item in dictionary.items() {
        let value = match &item.value {
            VariantValue::UInt32(value) => VariantValueWire::UInt32(*value),
            VariantValue::UInt64(value) => VariantValueWire::UInt64(*value),
            VariantValue::Bool(value) => VariantValueWire::Bool(*value),
            VariantValue::Int32(value) => VariantValueWire::Int32(*value),
            VariantValue::Int64(value) => VariantValueWire::Int64(*value),
            VariantValue::String(value) => VariantValueWire::String(value.clone()),
            VariantValue::Bytes(value) => {
                budget.secret(value.len(), VAULT_LIMITS)?;
                VariantValueWire::Bytes(SecretB64::from_bytes(value))
            }
        };
        output.push(VariantDictionaryWire {
            key: item.key.clone(),
            value,
        });
    }
    Ok(output)
}

fn database_from_wire(
    wire: DatabaseInput,
    budget: &mut ConversionBudget,
    directives: &mut Vec<EnsureDirective>,
) -> Result<KeePassDatabase> {
    let binary_pool = BinaryPool::default();
    let mut database = KeePassDatabase {
        meta: meta_from_wire(wire.meta, budget)?,
        root: group_from_wire(wire.root, 1, budget, directives)?,
        deleted_objects: wire
            .deleted_objects
            .iter()
            .map(|item| {
                Ok(DeletedObject {
                    id: uuid(&item.id)?,
                    deleted_at: KdbxTimestamp(item.deleted_at),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        binary_pool,
        public_custom_data: custom_data_from_wire(wire.public_custom_data)?,
        typed_public_custom_data: dictionary_from_wire(wire.typed_public_custom_data, budget)?,
        can_save_losslessly: true,
        write_options: None,
    };
    for binary in wire.binary_pool {
        budget.binary(binary.data.decoded_len_hint()?, VAULT_LIMITS)?;
        budget.secret(binary.data.decoded_len_hint()?, VAULT_LIMITS)?;
        let bytes = binary.data.decode()?;
        database.binary_pool.add(bytes.to_vec(), binary.protected);
    }
    validate_model(&database, VAULT_LIMITS)?;
    Ok(database)
}

fn meta_from_wire(wire: MetaInput, budget: &mut ConversionBudget) -> Result<KeePassMeta> {
    let mut legacy_binaries = Vec::with_capacity(wire.legacy_binaries.len());
    for data in &wire.legacy_binaries {
        let count = data.decoded_len_hint()?;
        budget.binary(count, VAULT_LIMITS)?;
        budget.secret(count, VAULT_LIMITS)?;
        legacy_binaries.push(data.decode()?.to_vec());
    }
    let mut custom_icons = Vec::with_capacity(wire.custom_icons.len());
    for icon in wire.custom_icons {
        let count = icon.data.decoded_len_hint()?;
        budget.binary(count, VAULT_LIMITS)?;
        budget.secret(count, VAULT_LIMITS)?;
        custom_icons.push(CustomIcon {
            uuid: uuid(&icon.uuid)?,
            data: icon.data.decode()?.to_vec(),
            name: icon.name,
            last_modification: icon.last_modification.map(KdbxTimestamp),
        });
    }
    Ok(KeePassMeta {
        generator: wire.generator,
        name: wire.name,
        description: wire.description,
        default_username: wire.default_username,
        settings_changed: wire.settings_changed.map(KdbxTimestamp),
        database_name_changed: wire.database_name_changed.map(KdbxTimestamp),
        database_description_changed: wire.database_description_changed.map(KdbxTimestamp),
        default_username_changed: wire.default_username_changed.map(KdbxTimestamp),
        master_key_changed: wire.master_key_changed.map(KdbxTimestamp),
        maintenance_history_days: wire.maintenance_history_days,
        color: KdbxColor { rgb: wire.color },
        master_key_change_rec: wire.master_key_change_rec,
        master_key_change_force: wire.master_key_change_force,
        master_key_change_force_once: wire.master_key_change_force_once,
        protect_password: wire.protect_password,
        protect_title: wire.protect_title,
        protect_username: wire.protect_username,
        protect_url: wire.protect_url,
        protect_notes: wire.protect_notes,
        times: times_from_wire(wire.times),
        history_max_items: wire.history_max_items,
        history_max_size: wire.history_max_size,
        memory_protection: wire.memory_protection,
        recycle_bin_enabled: wire.recycle_bin_enabled,
        recycle_bin_uuid: uuid(&wire.recycle_bin_uuid)?,
        recycle_bin_changed: wire.recycle_bin_changed.map(KdbxTimestamp),
        templates_uuid: uuid(&wire.templates_uuid)?,
        templates_changed: wire.templates_changed.map(KdbxTimestamp),
        selected_group_uuid: uuid(&wire.selected_group_uuid)?,
        top_visible_group_uuid: uuid(&wire.top_visible_group_uuid)?,
        custom_data: custom_data_from_wire(wire.custom_data)?,
        legacy_binaries,
        custom_icons,
    })
}

fn group_from_wire(
    wire: GroupInput,
    depth: usize,
    budget: &mut ConversionBudget,
    directives: &mut Vec<EnsureDirective>,
) -> Result<Group> {
    if depth > VAULT_LIMITS.max_depth {
        return Err(too_large());
    }
    let mut group = Group {
        id: uuid(&wire.id)?,
        name: wire.name,
        notes: wire.notes,
        icon_id: wire.icon_id,
        custom_icon_id: uuid(&wire.custom_icon_id)?,
        times: times_from_wire(wire.times),
        is_expanded: wire.is_expanded,
        enable_auto_type: wire.enable_auto_type,
        enable_searching: wire.enable_searching,
        default_auto_type_sequence: wire.default_auto_type_sequence,
        last_top_visible_entry_id: uuid(&wire.last_top_visible_entry_id)?,
        previous_parent_group_id: uuid(&wire.previous_parent_group_id)?,
        custom_data: custom_data_from_wire(wire.custom_data)?,
        groups: Vec::with_capacity(wire.groups.len()),
        entries: Vec::with_capacity(wire.entries.len()),
        tags: wire.tags,
    };
    for child in wire.groups {
        group
            .groups
            .push(group_from_wire(child, depth + 1, budget, directives)?);
    }
    for entry in wire.entries {
        group
            .entries
            .push(entry_from_wire(entry, depth + 1, budget, directives)?);
    }
    Ok(group)
}

fn entry_from_wire(
    wire: EntryInput,
    depth: usize,
    budget: &mut ConversionBudget,
    directives: &mut Vec<EnsureDirective>,
) -> Result<Entry> {
    if depth > VAULT_LIMITS.max_depth {
        return Err(too_large());
    }
    let mut fields = Vec::with_capacity(wire.fields.len());
    for field in wire.fields {
        let value = protected_from_wire(field.value, budget)?;
        fields.push(Field {
            key: field.key,
            value,
            protected: field.protected,
            protect_in_memory: field.protect_in_memory,
        });
    }
    let mut history = Vec::with_capacity(wire.history.len());
    for snapshot in wire.history {
        // A past revision has no present to converge. Honouring a directive
        // here would write a generated value into history, where nothing reads
        // it, so the request is refused rather than dropped: a directive the
        // tool silently ignores is a policy file that reads as converged.
        if snapshot.ensure.is_some() {
            return Err(InterchangeError(
                "interchange history entry carries a generate directive",
            ));
        }
        history.push(entry_from_wire(snapshot, depth + 1, budget, directives)?);
    }
    let id = uuid(&wire.id)?;
    if let Some(ensure) = wire.ensure {
        directives.push(EnsureDirective {
            id,
            size: ensure.size,
        });
    }
    let mut entry = Entry {
        id,
        title: wire.title,
        username: wire.username,
        password: protected_from_wire(wire.password, budget)?,
        url: wire.url,
        override_url: wire.override_url,
        notes: wire.notes,
        icon_id: wire.icon_id,
        custom_icon_id: uuid(&wire.custom_icon_id)?,
        foreground_color: KdbxColor {
            rgb: wire.foreground_color,
        },
        background_color: KdbxColor {
            rgb: wire.background_color,
        },
        quality_check: wire.quality_check,
        previous_parent_group_id: uuid(&wire.previous_parent_group_id)?,
        tags: wire.tags,
        times: times_from_wire(wire.times),
        fields,
        attachments: wire
            .attachments
            .iter()
            .map(|item| Attachment {
                name: item.name.clone(),
                reference: item.reference,
            })
            .collect(),
        auto_type: AutoType {
            enabled: wire.auto_type.enabled,
            obfuscated: wire.auto_type.obfuscated,
            default_sequence: wire.auto_type.default_sequence,
            associations: wire
                .auto_type
                .associations
                .into_iter()
                .map(|item| AutoTypeAssociation {
                    window: item.window,
                    keystrokes: item.keystrokes,
                })
                .collect(),
        },
        custom_data: custom_data_from_wire(wire.custom_data)?,
        history,
    };
    reconcile_standard_fields(&mut entry)?;
    Ok(entry)
}

fn reconcile_standard_fields(entry: &mut Entry) -> Result<()> {
    let mut fields = BTreeMapAccess::new(&mut entry.fields);
    if let Some(field) = fields.get_mut("Password") {
        entry.password = field.value.clone();
    }
    for (key, projection) in [
        ("Title", &mut entry.title),
        ("UserName", &mut entry.username),
        ("URL", &mut entry.url),
        ("Notes", &mut entry.notes),
    ] {
        if let Some(field) = fields.get_mut(key) {
            let value = field.value.reveal_text().map_err(|_| invalid())?;
            *projection = value.as_str().to_owned();
        }
    }
    drop(fields);
    if !entry.password.is_empty() && entry.field("Password").is_none() {
        entry.fields.push(Field {
            key: "Password".into(),
            value: entry.password.clone(),
            protected: true,
            protect_in_memory: entry.password.is_memory_protected(),
        });
    }
    if !entry.notes.is_empty() && entry.field("Notes").is_none() {
        entry.fields.push(Field::new("Notes", entry.notes.clone()));
    }
    Ok(())
}

struct BTreeMapAccess<'a> {
    fields: &'a mut Vec<Field>,
}

impl<'a> BTreeMapAccess<'a> {
    fn new(fields: &'a mut Vec<Field>) -> Self {
        Self { fields }
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|field| field.key == key)
    }
}

fn protected_from_wire(
    wire: ProtectedInput,
    budget: &mut ConversionBudget,
) -> Result<ProtectedValue> {
    let count = wire.value.decoded_len_hint()?;
    budget.secret(count, VAULT_LIMITS)?;
    let bytes = wire.value.decode()?;
    if wire.memory_protected {
        ProtectedValue::from_bytes_protected(bytes.to_vec()).map_err(|_| invalid())
    } else if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        Ok(ProtectedValue::from_text(text))
    } else {
        Ok(ProtectedValue::from_bytes_unprotected(bytes.to_vec()))
    }
}

fn times_from_wire(wire: TimesInput) -> KeePassTimes {
    KeePassTimes {
        created: KdbxTimestamp(wire.created),
        modified: KdbxTimestamp(wire.modified),
        accessed: KdbxTimestamp(wire.accessed),
        expires: KdbxTimestamp(wire.expires),
        expires_enabled: wire.expires_enabled,
        usage_count: wire.usage_count,
        location_changed: KdbxTimestamp(wire.location_changed),
    }
}

fn custom_data_from_wire(items: Vec<CustomDataWire>) -> Result<CustomData> {
    let mut data = CustomData::default();
    for item in items {
        if data.get(&item.key).is_some() {
            return Err(invalid());
        }
        data.set(
            item.key,
            item.value,
            item.last_modification.map(KdbxTimestamp),
        );
    }
    Ok(data)
}

fn dictionary_from_wire(
    items: Vec<VariantDictionaryWire>,
    budget: &mut ConversionBudget,
) -> Result<VariantDictionary> {
    let mut data = VariantDictionary::default();
    let mut keys = BTreeSet::new();
    for item in items {
        let key = item.key;
        if !keys.insert(key.clone()) {
            return Err(duplicate_typed_custom_data_key());
        }
        let value = match item.value {
            VariantValueWire::UInt32(value) => VariantValue::UInt32(value),
            VariantValueWire::UInt64(value) => VariantValue::UInt64(value),
            VariantValueWire::Bool(value) => VariantValue::Bool(value),
            VariantValueWire::Int32(value) => VariantValue::Int32(value),
            VariantValueWire::Int64(value) => VariantValue::Int64(value),
            VariantValueWire::String(value) => VariantValue::String(value),
            VariantValueWire::Bytes(value) => {
                let count = value.decoded_len_hint()?;
                budget.secret(count, VAULT_LIMITS)?;
                VariantValue::Bytes(value.decode()?.to_vec())
            }
        };
        data.set(key, value);
    }
    Ok(data)
}

impl SecretB64 {
    fn decoded_len_hint(&self) -> Result<usize> {
        if !self.0.len().is_multiple_of(4) {
            return Err(invalid());
        }
        let padding = self
            .0
            .bytes()
            .rev()
            .take_while(|byte| *byte == b'=')
            .count();
        if padding > 2 {
            return Err(invalid());
        }
        let count = self
            .0
            .len()
            .checked_div(4)
            .ok_or_else(invalid)?
            .checked_mul(3)
            .ok_or_else(invalid)?;
        count
            .checked_sub(padding)
            .filter(|value| *value > 0 || self.0.is_empty())
            .ok_or_else(invalid)
    }
}

fn uuid(value: &str) -> Result<KdbxUuid> {
    KdbxUuid::from_base64(value).map_err(|_| invalid())
}

#[derive(Default)]
struct StructuralCounts {
    groups: usize,
    entries: usize,
    history_entries: usize,
    fields: usize,
    binary_bytes: u64,
    object_ids: BTreeSet<KdbxUuid>,
}

fn validate_model(database: &KeePassDatabase, limits: Limits) -> Result<()> {
    if !neotales_keepass::history_limits_valid(&database.meta) {
        return Err(invalid());
    }
    let mut counts = StructuralCounts {
        binary_bytes: 0,
        ..StructuralCounts::default()
    };
    if database.binary_pool.len() > limits.max_binary_records {
        return Err(too_large());
    }
    for record in database.binary_pool.records() {
        counts.binary_bytes = counts
            .binary_bytes
            .checked_add(record.data.len() as u64)
            .ok_or_else(too_large)?;
        if counts.binary_bytes > limits.max_binary_bytes {
            return Err(too_large());
        }
    }
    for value in [
        &database.meta.generator,
        &database.meta.name,
        &database.meta.description,
        &database.meta.default_username,
    ] {
        if !valid_text(value, limits.max_text_bytes) {
            return Err(InterchangeError(
                "interchange text exceeds the allowed size",
            ));
        }
    }
    validate_custom_data(&database.meta.custom_data, limits)?;
    validate_custom_data(&database.public_custom_data, limits)?;
    validate_dictionary(&database.typed_public_custom_data, limits)?;
    if database.meta.custom_icons.len() > limits.max_binary_records
        || database.meta.custom_icons.iter().any(|icon| {
            icon.name
                .as_ref()
                .is_some_and(|name| !valid_text(name, limits.max_text_bytes))
        })
    {
        return Err(too_large());
    }
    validate_group(
        &database.root,
        1,
        &mut counts,
        database.binary_pool.len(),
        limits,
    )?;
    for deleted in &database.deleted_objects {
        if !counts.object_ids.insert(deleted.id) {
            return Err(InterchangeError(
                "interchange contains duplicate object UUIDs",
            ));
        }
    }
    if database
        .meta
        .legacy_binaries
        .iter()
        .try_fold(0u64, |total, item| total.checked_add(item.len() as u64))
        .is_none_or(|total| total > limits.max_binary_bytes)
    {
        return Err(too_large());
    }
    Ok(())
}

fn validate_group(
    group: &Group,
    depth: usize,
    counts: &mut StructuralCounts,
    binary_records: usize,
    limits: Limits,
) -> Result<()> {
    if depth > limits.max_depth || counts.groups >= limits.max_groups {
        return Err(too_large());
    }
    if !counts.object_ids.insert(group.id) {
        return Err(InterchangeError(
            "interchange contains duplicate object UUIDs",
        ));
    }
    counts.groups += 1;
    for value in [&group.name, &group.notes, &group.default_auto_type_sequence] {
        if !valid_text(value, limits.max_text_bytes) {
            return Err(InterchangeError(
                "interchange text exceeds the allowed size",
            ));
        }
    }
    if group.tags.len() > limits.max_fields
        || group
            .tags
            .iter()
            .any(|tag| !valid_text(tag, limits.max_text_bytes))
    {
        return Err(too_large());
    }
    validate_custom_data(&group.custom_data, limits)?;
    for entry in &group.entries {
        validate_entry(entry, depth + 1, counts, binary_records, limits)?;
    }
    for child in &group.groups {
        validate_group(child, depth + 1, counts, binary_records, limits)?;
    }
    Ok(())
}

fn validate_entry(
    entry: &Entry,
    depth: usize,
    counts: &mut StructuralCounts,
    binary_records: usize,
    limits: Limits,
) -> Result<()> {
    if depth > limits.max_depth || counts.entries >= limits.max_entries {
        return Err(too_large());
    }
    if !counts.object_ids.insert(entry.id) {
        return Err(InterchangeError(
            "interchange contains duplicate object UUIDs",
        ));
    }
    counts.entries += 1;
    for value in [
        &entry.title,
        &entry.username,
        &entry.url,
        &entry.override_url,
        &entry.notes,
    ] {
        if !valid_text(value, limits.max_text_bytes) {
            return Err(InterchangeError(
                "interchange text exceeds the allowed size",
            ));
        }
    }
    if entry.tags.len() > limits.max_fields
        || entry
            .tags
            .iter()
            .any(|tag| !valid_text(tag, limits.max_text_bytes))
        || entry.fields.len() > limits.max_fields
    {
        return Err(too_large());
    }
    let mut field_names = BTreeSet::new();
    for field in &entry.fields {
        if !valid_text(&field.key, limits.max_text_bytes) {
            return Err(too_large());
        }
        if !field_names.insert(&field.key) {
            return Err(InterchangeError(
                "interchange contains duplicate field names",
            ));
        }
        counts.fields += 1;
        if counts.fields > limits.max_fields {
            return Err(too_large());
        }
    }
    for attachment in &entry.attachments {
        if attachment.reference >= binary_records
            || !valid_text(&attachment.name, limits.max_text_bytes)
        {
            return Err(invalid());
        }
    }
    if entry.auto_type.default_sequence.len() > limits.max_text_bytes
        || entry.auto_type.associations.len() > limits.max_fields
        || entry.auto_type.associations.iter().any(|item| {
            item.window.len() > limits.max_text_bytes
                || item.keystrokes.len() > limits.max_text_bytes
        })
    {
        return Err(too_large());
    }
    validate_custom_data(&entry.custom_data, limits)?;
    for snapshot in &entry.history {
        if counts.history_entries >= limits.max_history_entries {
            return Err(too_large());
        }
        counts.history_entries += 1;
        validate_entry(snapshot, depth + 1, counts, binary_records, limits)?;
    }
    Ok(())
}

fn validate_custom_data(data: &CustomData, limits: Limits) -> Result<()> {
    if data.items().len() > limits.max_fields
        || data.items().iter().any(|item| {
            !valid_text(&item.key, limits.max_text_bytes)
                || !valid_text(&item.value, limits.max_text_bytes)
        })
    {
        return Err(too_large());
    }
    Ok(())
}

fn validate_dictionary(data: &VariantDictionary, limits: Limits) -> Result<()> {
    if data.items().len() > limits.max_fields
        || data.items().iter().any(|item| {
            !valid_text(&item.key, limits.max_text_bytes)
                || match &item.value {
                    VariantValue::String(value) => !valid_text(value, limits.max_text_bytes),
                    VariantValue::Bytes(value) => value.len() > limits.max_binary_bytes as usize,
                    _ => false,
                }
        })
    {
        return Err(too_large());
    }
    Ok(())
}

fn valid_text(value: &str, limit: usize) -> bool {
    value.len() <= limit
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DatabaseStats {
    pub groups: usize,
    pub entries: usize,
    pub history_entries: usize,
    pub fields: usize,
    pub attachments: usize,
    pub protected_values: usize,
    pub binary_records: usize,
    pub binary_bytes: u64,
}

pub(crate) fn stats(database: &KeePassDatabase) -> DatabaseStats {
    let mut output = DatabaseStats {
        binary_records: database.binary_pool.len(),
        ..DatabaseStats::default()
    };
    for record in database.binary_pool.records() {
        output.binary_bytes = output.binary_bytes.saturating_add(record.data.len() as u64);
        output.protected_values += usize::from(record.protected);
    }
    fn visit(group: &Group, output: &mut DatabaseStats) {
        output.groups += 1;
        for entry in &group.entries {
            visit_entry(entry, output);
        }
        for child in &group.groups {
            visit(child, output);
        }
    }
    fn visit_entry(entry: &Entry, output: &mut DatabaseStats) {
        output.entries += 1;
        if !entry.password.is_empty() {
            output.protected_values += 1;
        }
        output.fields += entry.fields.len();
        output.attachments += entry.attachments.len();
        output.protected_values += entry.fields.iter().filter(|field| field.protected).count();
        for snapshot in &entry.history {
            output.history_entries += 1;
            visit_entry(snapshot, output);
        }
    }
    visit(&database.root, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_base64_length_hint_matches_decoding_for_short_lengths() {
        for length in 0..=64 {
            let bytes: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let encoded = SecretB64::from_bytes(&bytes);
            assert_eq!(encoded.decoded_len_hint().unwrap(), length);
            assert_eq!(encoded.decode().unwrap().as_slice(), bytes);
        }
        for encoded in ["YQ==", "Yg=="] {
            let value = SecretB64(Zeroizing::new(encoded.to_owned()));
            assert_eq!(value.decoded_len_hint().unwrap(), 1);
            assert_eq!(value.decode().unwrap().as_slice().len(), 1);
        }
    }

    fn fixture() -> KeePassDatabase {
        let mut database = KeePassDatabase::default();
        let reference = database
            .binary_pool
            .add(b"attachment-secret".to_vec(), true);
        let mut entry = Entry::new("login");
        entry.password = ProtectedValue::from_text("password-secret");
        entry.set_field(Field {
            key: "Token".into(),
            value: ProtectedValue::from_text("token-secret"),
            protected: true,
            protect_in_memory: true,
        });
        entry.attachments.push(Attachment {
            name: "secret.txt".into(),
            reference,
        });
        entry.history.push(Entry::new("old"));
        database.root.entries.push(entry);
        database
            .meta
            .custom_data
            .set("label", "value", Some(KdbxTimestamp::from_unix_seconds(10)));
        database
    }

    #[test]
    fn complete_snapshot_round_trip_preserves_protected_history_and_binaries() {
        let original = fixture();
        let encoded = encode(&original).unwrap();
        let text = String::from_utf8(encoded.to_vec()).unwrap();
        assert!(text.contains(&STANDARD.encode("password-secret")));
        assert!(text.contains(&STANDARD.encode("token-secret")));
        assert!(text.contains(&STANDARD.encode("attachment-secret")));
        let decoded = decode(&encoded).unwrap().database;
        assert!(decoded.can_save_losslessly);
        assert_eq!(decoded.meta.custom_data.get("label"), Some("value"));
        let entry = &decoded.root.entries[0];
        assert_eq!(
            entry.password.reveal_text().unwrap().as_str(),
            "password-secret"
        );
        assert_eq!(
            entry
                .field("Token")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "token-secret"
        );
        assert_eq!(entry.history.len(), 1);
        assert_eq!(
            decoded
                .binary_pool
                .get(entry.attachments[0].reference)
                .unwrap()
                .data,
            b"attachment-secret"
        );
    }

    #[test]
    fn standard_title_field_wins_across_snapshot_edit_import_and_kdbx_save() {
        use neotales_keepass::{KdbxCredentials, KdbxFile, KdbxReadLimits, KdbxWriteOptions};

        let mut database = KeePassDatabase::default();
        let mut entry = Entry::new("stale scalar title");
        entry.set_field(Field::new("Title", "canonical field title"));
        entry.notes = "stale notes projection".into();
        entry.set_field(Field::new("Notes", "canonical notes"));
        database.root.entries.push(entry);

        let encoded = encode(&database).expect("export snapshot");
        let wire: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            wire["database"]["root"]["entries"][0]["title"],
            "canonical field title"
        );
        let mut decoded = decode(&encoded).expect("import snapshot").database;
        let entry = &decoded.root.entries[0];
        assert_eq!(entry.title, "canonical field title");
        assert_eq!(entry.notes, "canonical notes");

        let entry = &mut decoded.root.entries[0];
        entry.title = "stale edited projection".into();
        entry.set_field(Field::new("Title", "edited canonical title"));
        let encoded = encode(&decoded).expect("export edited snapshot");
        let imported = decode(&encoded).expect("reimport edited snapshot").database;
        assert_eq!(imported.root.entries[0].title, "edited canonical title");

        let mut kdbx = Vec::new();
        KdbxFile::save(
            &imported,
            &mut kdbx,
            &mut KdbxCredentials::password("test-password").unwrap(),
            KdbxWriteOptions {
                aes_kdf_rounds: 8,
                ..KdbxWriteOptions::default()
            },
            &KdbxReadLimits::default(),
        )
        .expect("save imported snapshot");
        let reopened =
            KdbxFile::load_password(kdbx.as_slice(), "test-password", &KdbxReadLimits::default())
                .expect("reopen KDBX");
        assert_eq!(reopened.root.entries[0].title, "edited canonical title");
        assert_eq!(
            reopened.root.entries[0]
                .field("Title")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "edited canonical title"
        );
    }

    #[test]
    fn override_url_obeys_interchange_text_limit_on_export_and_import() {
        let mut database = fixture();
        database.root.entries[0].override_url = "long override".into();
        let limits = Limits {
            max_text_bytes: 8,
            ..VAULT_LIMITS
        };
        let error = encode_with_limits(&database, limits).unwrap_err();
        assert_eq!(error.message(), "interchange text exceeds the allowed size");

        database.root.entries[0].override_url = "short".into();
        let encoded = encode(&database).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        document["database"]["root"]["entries"][0]["override_url"] =
            serde_json::Value::String("long override".into());
        let input = serde_json::to_vec(&document).unwrap();
        let error = match decode_with_limits(&input, limits) {
            Ok(_) => panic!("oversized override URL was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.message(), "interchange text exceeds the allowed size");
    }

    /// The message a document was refused with, without requiring `Debug` on
    /// the decoded value.
    ///
    /// `Decoded` deliberately cannot be `Debug`: it holds every protected value
    /// in a snapshot, and a derived `Debug` would be a way to print them from a
    /// panic. Matching on the `Result` keeps that property intact.
    fn refusal(input: &[u8]) -> &'static str {
        match decode(input) {
            Ok(_) => panic!("document was accepted"),
            Err(error) => error.message(),
        }
    }

    #[test]
    fn decode_rejects_duplicate_typed_public_custom_data_keys() {
        let mut database = fixture();
        database
            .typed_public_custom_data
            .set("outer", VariantValue::String("outer-value".into()));
        let encoded = encode(&database).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let items = document["database"]["typed_public_custom_data"]
            .as_array_mut()
            .unwrap();
        let duplicate = items[0].clone();
        items.push(duplicate);
        let input = serde_json::to_vec(&document).unwrap();

        assert_eq!(refusal(&input), duplicate_typed_custom_data_key().message());
    }

    #[test]
    fn decode_enforces_byte_and_structural_limits_before_model_use() {
        let original = fixture();
        let encoded = encode(&original).unwrap();
        let tiny = Limits {
            max_bytes: encoded.len() - 1,
            ..VAULT_LIMITS
        };
        assert!(decode_with_limits(&encoded, tiny).is_err());
        let too_many_fields = Limits {
            max_fields: 0,
            ..VAULT_LIMITS
        };
        assert!(decode_with_limits(&encoded, too_many_fields).is_err());
    }

    /// A snapshot whose only entry carries `key` with the given `size`.
    ///
    /// The `key` is a parameter so a misspelling can be tested as easily as the
    /// real name, and so a directive can be attached to a name this build does
    /// not have.
    fn document_with_ensure(size: u64, key: &str) -> Vec<u8> {
        let encoded = encode(&fixture()).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        document["database"]["root"]["entries"][0][key] = serde_json::json!({ "size": size });
        serde_json::to_vec(&document).unwrap()
    }

    /// The exact member names an exported entry carries.
    ///
    /// This is the pin for "absent means today's behaviour": `export` writes
    /// this set of keys and no others, so the directive cannot reach the wire
    /// without adding a key here, and a document that omits `ensure` keeps
    /// meaning exactly what it meant before the field existed.
    const EXPORTED_ENTRY_KEYS: [&str; 20] = [
        "attachments",
        "auto_type",
        "background_color",
        "custom_data",
        "custom_icon_id",
        "fields",
        "foreground_color",
        "history",
        "icon_id",
        "id",
        "notes",
        "override_url",
        "password",
        "previous_parent_group_id",
        "quality_check",
        "tags",
        "times",
        "title",
        "url",
        "username",
    ];

    fn exported_entry_keys(encoded: &[u8]) -> BTreeSet<String> {
        let document: serde_json::Value = serde_json::from_slice(encoded).unwrap();
        document["database"]["root"]["entries"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn a_document_without_the_directive_collects_nothing_and_writes_no_new_key() {
        let encoded = encode(&fixture()).unwrap();
        assert!(
            !encoded
                .windows(b"\"ensure\"".len())
                .any(|w| w == b"\"ensure\"")
        );
        let decoded = decode(&encoded).unwrap();
        assert!(decoded.directives.is_empty());
        // Decoding and re-encoding must not smuggle the directive into the
        // model, or the second export of an unchanged vault would differ from
        // the first.
        let re_encoded = encode(&decoded.database).unwrap();
        assert!(
            !re_encoded
                .windows(b"\"ensure\"".len())
                .any(|w| w == b"\"ensure\"")
        );
        assert_eq!(
            exported_entry_keys(&re_encoded),
            EXPORTED_ENTRY_KEYS
                .iter()
                .map(|key| (*key).to_owned())
                .collect()
        );
    }

    #[test]
    fn the_directive_is_collected_against_the_entry_it_names() {
        let input = document_with_ensure(32, "ensure");
        let decoded = decode(&input).unwrap();
        assert_eq!(
            decoded.directives,
            vec![EnsureDirective {
                id: decoded.database.root.entries[0].id,
                size: 32,
            }]
        );
        // The value in the file is untouched: the directive is a request, not a
        // replacement, and decoding never invents one.
        assert_eq!(
            decoded.database.root.entries[0]
                .password
                .reveal_text()
                .unwrap()
                .as_str(),
            "password-secret"
        );
    }

    #[test]
    fn a_misspelled_or_half_specified_directive_is_refused() {
        for input in [
            document_with_ensure(32, "ensur"),
            document_with_ensure(32, "ensuree"),
            document_with_ensure(32, "Ensure"),
        ] {
            assert_eq!(refusal(&input), invalid().message());
        }
        // `size` is required inside the directive, and a directive carrying
        // anything else -- including a `classes` member -- is refused rather
        // than ignored, so a policy that asks for something this build cannot
        // do fails instead of quietly doing less than it says.
        let encoded = encode(&fixture()).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for directive in [
            serde_json::json!({}),
            serde_json::json!({"size": 32, "classes": {"lower": true}}),
            serde_json::json!({"len": 32}),
            serde_json::json!(true),
        ] {
            document["database"]["root"]["entries"][0]["ensure"] = directive;
            assert_eq!(
                refusal(&serde_json::to_vec(&document).unwrap()),
                invalid().message()
            );
        }
    }

    #[test]
    fn a_directive_on_a_history_entry_is_refused_rather_than_ignored() {
        let encoded = encode(&fixture()).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let entry = &mut document["database"]["root"]["entries"][0];
        entry["history"][0]["ensure"] = serde_json::json!({"size": 32});
        assert_eq!(
            refusal(&serde_json::to_vec(&document).unwrap()),
            "interchange history entry carries a generate directive"
        );
    }

    #[test]
    fn the_export_side_never_writes_the_directive() {
        // A directive is an instruction in a policy file, not vault state, so
        // `encode` has no way to emit one and a round trip cannot carry it.
        let mut database = fixture();
        database.root.entries[0].password = ProtectedValue::from_text(String::new());
        let encoded = encode(&database).unwrap();
        assert!(
            !encoded
                .windows(b"\"ensure\"".len())
                .any(|w| w == b"\"ensure\"")
        );
        assert!(decode(&encoded).unwrap().directives.is_empty());
    }

    #[test]
    fn duplicate_ids_and_fields_fail_closed() {
        let mut database = fixture();
        let duplicate = database.root.entries[0].clone();
        database.root.entries.push(duplicate);
        assert!(encode(&database).is_err());

        let mut database = fixture();
        let duplicate_field = database.root.entries[0].field("Token").unwrap().clone();
        database.root.entries[0].fields.push(duplicate_field);
        assert!(encode(&database).is_err());
    }

    #[test]
    fn lossless_flag_is_required_for_export() {
        let mut database = fixture();
        database.can_save_losslessly = false;
        assert_eq!(
            encode(&database).unwrap_err().message(),
            unsupported().message()
        );
    }

    #[test]
    fn the_decoded_directives_carry_the_requested_size_and_nothing_else() {
        // A size the CLI will later refuse is still decoded faithfully: the
        // wire format records what the file asked for, and the command that
        // acts on it owns the bound. A 0 is a request, not a value, and never
        // becomes a generated password by accident.
        let input = document_with_ensure(0, "ensure");
        assert_eq!(decode(&input).unwrap().directives[0].size, 0);
        let input = document_with_ensure(u64::MAX, "ensure");
        assert_eq!(decode(&input).unwrap().directives[0].size, u64::MAX);
    }
}

/// A group survives export and import, and an entry inside it stays addressable.
///
/// The round-trip test above covers entries in the root and nothing else, so the
/// whole group subtree was untested: `group_to_wire` and `group_from_wire` existed
/// and were never exercised end to end. That matters more than usual here, because
/// groups are the only way a nested entry path can exist at all -- `secrets set`,
/// Field updates address entries in groups that are already there and do not
/// create them -- so "can a group be created by importing a document" is a
/// question about the only route to a nested entry, and it had no answer in the
/// test suite.
///
/// Two levels, so a group inside a group is covered rather than assumed, and the
/// nested entry is checked by name so a decoder that flattened the tree would fail
/// rather than pass with the right bytes somewhere else.
#[test]
fn groups_and_their_entries_survive_a_round_trip() {
    let mut database = KeePassDatabase::default();

    let mut outer = Group::new("prod");
    let mut inner = Group::new("db");
    let mut deep = Entry::new("primary");
    deep.password = ProtectedValue::from_text("nested-secret");
    inner.entries.push(deep);
    outer.groups.push(inner);

    let mut shallow = Entry::new("staging");
    shallow.password = ProtectedValue::from_text("outer-secret");
    outer.entries.push(shallow);
    database.root.groups.push(outer);

    // A root entry too, so a decoder that dropped the root's own entries while
    // handling the subtree would be caught rather than passing.
    let mut root_entry = Entry::new("top");
    root_entry.password = ProtectedValue::from_text("root-secret");
    database.root.entries.push(root_entry);

    let encoded = encode(&database).unwrap();
    let decoded = decode(&encoded).unwrap().database;
    assert!(decoded.can_save_losslessly);

    assert_eq!(decoded.root.entries.len(), 1);
    assert_eq!(decoded.root.entries[0].title, "top");

    assert_eq!(decoded.root.groups.len(), 1);
    let outer = &decoded.root.groups[0];
    assert_eq!(outer.name, "prod");
    assert_eq!(outer.entries.len(), 1);
    assert_eq!(outer.entries[0].title, "staging");

    assert_eq!(outer.groups.len(), 1);
    let inner = &outer.groups[0];
    assert_eq!(inner.name, "db");
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.entries[0].title, "primary");
    assert_eq!(
        inner.entries[0].password.reveal_text().unwrap().as_str(),
        "nested-secret"
    );
}
