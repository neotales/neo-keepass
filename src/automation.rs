//! Non-disclosing vault mutation planning shared by the automation commands.

#![allow(
    clippy::assigning_clones,
    clippy::too_many_lines,
    reason = "the sync planner keeps its merge and regression cases together"
)]

use std::collections::BTreeSet;

use neotales_keepass::{BinaryPool, Entry, Group, KdbxUuid, KeePassDatabase, ProtectedValue};

pub(crate) type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SyncPlan {
    pub groups_added: usize,
    pub entries_added: usize,
    pub entries_updated: usize,
    pub groups_updated: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyncStrategy {
    Newest,
    Source,
    Target,
}

impl SyncStrategy {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "newest" => Ok(Self::Newest),
            "source" => Ok(Self::Source),
            "target" => Ok(Self::Target),
            _ => Err("invalid sync strategy"),
        }
    }

    fn replaces(self, target_modified: i64, source_modified: i64) -> bool {
        match self {
            Self::Newest => source_modified >= target_modified,
            Self::Source => true,
            Self::Target => false,
        }
    }
}

pub(crate) fn tree_is_empty(database: &KeePassDatabase) -> bool {
    database.root.entries.is_empty() && database.root.groups.is_empty()
}

/// Remove a duplicate protected Password projection before KDBX serialization.
/// KDBX writes the Password String element when it is present; clearing the
/// redundant in-memory copy avoids provider-state coupling in the core writer.
pub(crate) fn prepare_standard_fields_for_save(database: &mut KeePassDatabase) {
    fn visit_entry(entry: &mut Entry) {
        if entry.field("Password").is_some() {
            entry.password = ProtectedValue::from_text(String::new());
        }
        for snapshot in &mut entry.history {
            visit_entry(snapshot);
        }
    }
    fn visit_group(group: &mut Group) {
        for item in &mut group.entries {
            visit_entry(item);
        }
        for child in &mut group.groups {
            visit_group(child);
        }
    }
    visit_group(&mut database.root);
}

/// Reconcile redundant standard-field projections after a KDBX load. The
/// serialized String element is authoritative when both representations exist.
pub(crate) fn normalize_standard_projections(database: &mut KeePassDatabase) {
    fn field_text(entry: &Entry, name: &str) -> Option<String> {
        entry
            .field(name)
            .and_then(|field| field.value.reveal_text().ok())
            .map(|value| value.as_str().to_owned())
    }
    fn visit_entry(entry: &mut Entry) {
        if let Some(field) = entry.field("Password") {
            entry.password = field.value.clone();
        }
        if let Some(value) = field_text(entry, "UserName") {
            entry.username = value;
        }
        if let Some(value) = field_text(entry, "URL") {
            entry.url = value;
        }
        if let Some(value) = field_text(entry, "Notes") {
            entry.notes = value;
        }
        for snapshot in &mut entry.history {
            visit_entry(snapshot);
        }
    }
    fn visit_group(group: &mut Group) {
        for item in &mut group.entries {
            visit_entry(item);
        }
        for child in &mut group.groups {
            visit_group(child);
        }
    }
    visit_group(&mut database.root);
}

/// Merge one complete source snapshot into a target without deleting target-only
/// objects. Incoming protected values, histories, attachment bytes, and protection
/// flags remain intact; only binary-pool references are interned into the target.
pub(crate) fn sync(
    target: &mut KeePassDatabase,
    source: &KeePassDatabase,
    strategy: SyncStrategy,
) -> Result<SyncPlan> {
    let target_ids = collect_ids(target)?;
    let source_ids = collect_ids(source)?;
    for id in &source_ids {
        if id != &source.root.id && target_ids.contains(id) {
            return Err("interchange contains a UUID collision");
        }
    }
    let mut remapper = BinaryRemapper::new(&source.binary_pool, &mut target.binary_pool);
    let mut plan = SyncPlan::default();
    // The snapshot root is the document container, not a child group. Merge
    // its contents directly so a source entry cannot be added twice.
    merge_group_contents(
        &mut target.root,
        &source.root,
        strategy,
        &mut remapper,
        &mut plan,
    )?;
    Ok(plan)
}

fn collect_ids(database: &KeePassDatabase) -> Result<BTreeSet<KdbxUuid>> {
    fn entry_ids(entry: &Entry, ids: &mut BTreeSet<KdbxUuid>, count: &mut usize) -> Result<()> {
        *count += 1;
        if *count > 1_000_000 || !ids.insert(entry.id) {
            return Err("interchange contains duplicate object UUIDs");
        }
        for snapshot in &entry.history {
            entry_ids(snapshot, ids, count)?;
        }
        Ok(())
    }
    fn group_ids(group: &Group, ids: &mut BTreeSet<KdbxUuid>, count: &mut usize) -> Result<()> {
        *count += 1;
        if *count > 1_000_000 || !ids.insert(group.id) {
            return Err("vault contains duplicate object UUIDs");
        }
        for entry in &group.entries {
            entry_ids(entry, ids, count)?;
        }
        for child in &group.groups {
            group_ids(child, ids, count)?;
        }
        Ok(())
    }
    let mut ids = BTreeSet::new();
    let mut count = 0;
    group_ids(&database.root, &mut ids, &mut count)?;
    Ok(ids)
}

struct BinaryRemapper<'a> {
    source: &'a BinaryPool,
    target: &'a mut BinaryPool,
    references: Vec<Option<usize>>,
}

impl<'a> BinaryRemapper<'a> {
    fn new(source: &'a BinaryPool, target: &'a mut BinaryPool) -> Self {
        Self {
            source,
            target,
            references: vec![None; source.len()],
        }
    }

    fn remap(&mut self, reference: usize) -> Result<usize> {
        if let Some(existing) = self.references.get(reference).and_then(|value| *value) {
            return Ok(existing);
        }
        let record = self
            .source
            .get(reference)
            .ok_or("interchange attachment reference is invalid")?;
        let existing = self
            .target
            .records()
            .iter()
            .position(|candidate| {
                candidate.protected == record.protected && candidate.data == record.data
            })
            .unwrap_or_else(|| self.target.add(record.data.clone(), record.protected));
        if let Some(slot) = self.references.get_mut(reference) {
            *slot = Some(existing);
        }
        Ok(existing)
    }

    fn entry(&mut self, entry: &Entry) -> Result<Entry> {
        let mut output = entry.clone();
        for attachment in &mut output.attachments {
            attachment.reference = self.remap(attachment.reference)?;
        }
        for snapshot in &mut output.history {
            *snapshot = self.entry(snapshot)?;
        }
        Ok(output)
    }

    fn group(&mut self, group: &Group) -> Result<Group> {
        let mut output = group.clone();
        for entry in &mut output.entries {
            *entry = self.entry(entry)?;
        }
        for child in &mut output.groups {
            *child = self.group(child)?;
        }
        Ok(output)
    }
}

fn merge_group_contents(
    target: &mut Group,
    source: &Group,
    strategy: SyncStrategy,
    remapper: &mut BinaryRemapper<'_>,
    plan: &mut SyncPlan,
) -> Result<()> {
    for entry in &source.entries {
        if let Some(index) = target.entries.iter().position(|item| item.id == entry.id) {
            if strategy.replaces(
                target.entries[index].times.modified.0,
                entry.times.modified.0,
            ) {
                target.entries[index] = remapper.entry(entry)?;
                plan.entries_updated += 1;
            }
        } else {
            target.entries.push(remapper.entry(entry)?);
            plan.entries_added += 1;
        }
    }
    for child in &source.groups {
        merge_group(target, child, strategy, remapper, plan)?;
    }
    Ok(())
}

fn merge_group(
    target: &mut Group,
    source: &Group,
    strategy: SyncStrategy,
    remapper: &mut BinaryRemapper<'_>,
    plan: &mut SyncPlan,
) -> Result<()> {
    if let Some(index) = target.groups.iter().position(|item| item.id == source.id) {
        if strategy.replaces(
            target.groups[index].times.modified.0,
            source.times.modified.0,
        ) {
            // Descendants are merged below. Remapping a full group here would
            // copy attachments from entries whose target versions are retained,
            // then discard those entries and leave their binaries orphaned.
            copy_group_metadata(&mut target.groups[index], source);
            plan.groups_updated += 1;
        }
        merge_group_contents(&mut target.groups[index], source, strategy, remapper, plan)?;
    } else {
        target.groups.push(remapper.group(source)?);
        plan.groups_added += 1;
    }
    Ok(())
}

fn copy_group_metadata(target: &mut Group, source: &Group) {
    target.id = source.id;
    target.name = source.name.clone();
    target.notes = source.notes.clone();
    target.icon_id = source.icon_id;
    target.custom_icon_id = source.custom_icon_id;
    target.times = source.times;
    target.is_expanded = source.is_expanded;
    target.enable_auto_type = source.enable_auto_type;
    target.enable_searching = source.enable_searching;
    target.default_auto_type_sequence = source.default_auto_type_sequence.clone();
    target.last_top_visible_entry_id = source.last_top_visible_entry_id;
    target.previous_parent_group_id = source.previous_parent_group_id;
    target.custom_data = source.custom_data.clone();
    target.tags = source.tags.clone();
}

#[cfg(test)]
mod tests {
    use super::*;
    use neotales_keepass::{Field, ProtectedValue};

    #[test]
    fn sync_preserves_existing_protected_values() {
        let mut target = KeePassDatabase::default();
        let mut entry = Entry::new("target");
        entry.password = ProtectedValue::from_text("target-password");
        entry.set_field(Field::new("Token", "target-token"));
        target.root.entries.push(entry);

        let mut source = KeePassDatabase::default();
        let mut entry = Entry::new("source");
        entry.password = ProtectedValue::from_text("source-password");
        source.root.entries.push(entry);

        sync(&mut target, &source, SyncStrategy::Newest).unwrap();
        assert_eq!(target.root.entries.len(), 2);
        assert_eq!(
            target.root.entries[0]
                .password
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
    }

    #[test]
    fn sync_merges_snapshot_root_without_duplicate_objects() {
        let mut target = KeePassDatabase::default();
        let mut source = KeePassDatabase::default();
        source.root.entries.push(Entry::new("source"));

        sync(&mut target, &source, SyncStrategy::Newest).unwrap();

        assert_eq!(target.root.entries.len(), 1);
        assert!(target.root.groups.is_empty());
        assert!(collect_ids(&target).is_ok());
    }

    // `sync` rejects every cross-vault shared non-root UUID during preflight,
    // so the matching-group update branch cannot be reached by a valid pair of
    // interchange snapshots. Exercise the helper directly to pin its binary-pool
    // ownership behavior if that preflight policy or call structure changes.
    #[test]
    fn group_metadata_update_does_not_remap_discarded_child_history_binaries() {
        let mut target_database = KeePassDatabase::default();
        let target_binary = target_database
            .binary_pool
            .add(b"target-binary".to_vec(), true);
        let mut target_entry = Entry::new("target-child");
        target_entry.times.modified = neotales_keepass::KdbxTimestamp(10);
        target_entry.attachments.push(neotales_keepass::Attachment {
            name: "target.bin".into(),
            reference: target_binary,
        });
        target_entry.password = ProtectedValue::from_text("target-password");

        let mut target_group = Group::new("shared-group");
        target_group.times.modified = neotales_keepass::KdbxTimestamp(10);
        target_group.add_entry(target_entry.clone());
        let mut target_parent = Group::new("root");
        target_parent.add_group(target_group);

        let mut source_database = KeePassDatabase::default();
        let source_current_binary = source_database
            .binary_pool
            .add(b"source-current-orphan".to_vec(), true);
        let source_history_binary = source_database
            .binary_pool
            .add(b"source-history-orphan".to_vec(), true);
        let mut source_entry = target_entry.clone();
        source_entry.title = "source-child".into();
        source_entry.times.modified = neotales_keepass::KdbxTimestamp(5);
        source_entry.attachments = vec![neotales_keepass::Attachment {
            name: "source-current.bin".into(),
            reference: source_current_binary,
        }];
        let mut history = Entry::new("source-history");
        history.attachments.push(neotales_keepass::Attachment {
            name: "source-history.bin".into(),
            reference: source_history_binary,
        });
        source_entry.history.push(history);
        let mut source_group = Group::new("shared-group-updated");
        source_group.id = target_parent.groups[0].id;
        source_group.times.modified = neotales_keepass::KdbxTimestamp(20);
        source_group.add_entry(source_entry);

        let mut plan = SyncPlan::default();
        let mut remapper = BinaryRemapper::new(
            &source_database.binary_pool,
            &mut target_database.binary_pool,
        );
        merge_group(
            &mut target_parent,
            &source_group,
            SyncStrategy::Newest,
            &mut remapper,
            &mut plan,
        )
        .unwrap();
        drop(remapper);

        assert_eq!(plan.groups_updated, 1);
        assert_eq!(plan.entries_updated, 0);
        assert_eq!(target_database.binary_pool.len(), 1);
        assert_eq!(
            target_database.binary_pool.get(target_binary).unwrap().data,
            b"target-binary"
        );
        let kept_group = &target_parent.groups[0];
        assert_eq!(kept_group.name, "shared-group-updated");
        assert_eq!(kept_group.entries.len(), 1);
        let kept_entry = &kept_group.entries[0];
        assert_eq!(kept_entry.title, "target-child");
        assert_eq!(
            kept_entry.password.reveal_text().unwrap().as_str(),
            "target-password"
        );
        assert_eq!(kept_entry.attachments.len(), 1);
        assert_eq!(kept_entry.attachments[0].reference, target_binary);
    }

    #[test]
    fn kdbx_writer_preserves_multiple_protected_fields() {
        let mut database = KeePassDatabase::default();
        for (title, value) in [("first", "first-secret"), ("second", "second-secret")] {
            let mut entry = Entry::new(title);
            entry.password = ProtectedValue::from_text(value);
            entry.set_field(Field {
                key: "Password".into(),
                value: ProtectedValue::from_bytes_unprotected(value.as_bytes()),
                protected: true,
                protect_in_memory: false,
            });
            entry.set_field(Field {
                key: "Token".into(),
                value: ProtectedValue::from_text(format!("{value}-token")),
                protected: true,
                protect_in_memory: true,
            });
            entry.username = "user".into();
            entry.url = "https://example.invalid".into();
            entry.notes = "notes".into();
            entry.set_field(Field::new("UserName", "user"));
            entry.set_field(Field::new("URL", "https://example.invalid"));
            entry.set_field(Field::new("Notes", "notes"));
            database.root.entries.push(entry);
        }
        let mut bytes = Vec::new();
        neotales_keepass::KdbxFile::save(
            &database,
            &mut bytes,
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let loaded = neotales_keepass::KdbxFile::load(
            bytes.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            loaded.root.entries[0]
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "first-secret"
        );
    }

    #[test]
    fn sync_preserves_existing_values_with_decoded_source() {
        let mut target = KeePassDatabase::default();
        let mut entry = Entry::new("target");
        entry.password = ProtectedValue::from_text("target-password");
        entry.username = "target-user".into();
        entry.url = "https://example.invalid".into();
        entry.notes = "target-notes".into();
        entry.set_field(Field {
            key: "Password".into(),
            value: ProtectedValue::from_bytes_unprotected(b"target-password"),
            protected: true,
            protect_in_memory: false,
        });
        entry.set_field(Field::new("UserName", "target-user"));
        entry.set_field(Field::new("URL", "https://example.invalid"));
        entry.set_field(Field::new("Notes", "target-notes"));
        target.root.entries.push(entry);
        normalize_standard_projections(&mut target);
        let mut no_projection = target.clone();
        no_projection.root.entries[0].password = ProtectedValue::from_text(String::new());
        let mut no_projection_bytes = Vec::new();
        neotales_keepass::KdbxFile::save(
            &no_projection,
            &mut no_projection_bytes,
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let no_projection_reloaded = neotales_keepass::KdbxFile::load(
            no_projection_bytes.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            no_projection_reloaded.root.entries[0]
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
        let mut isolated = target.clone();
        let mut isolated_no_attachment = Vec::new();
        neotales_keepass::KdbxFile::save(
            &isolated,
            &mut isolated_no_attachment,
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let isolated_no_attachment_reloaded = neotales_keepass::KdbxFile::load(
            isolated_no_attachment.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            isolated_no_attachment_reloaded.root.entries[0]
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
        let reference = isolated.binary_pool.add(b"isolated".to_vec(), true);
        isolated.root.entries[0]
            .attachments
            .push(neotales_keepass::Attachment {
                name: "isolated".into(),
                reference,
            });
        let mut isolated_bytes = Vec::new();
        neotales_keepass::KdbxFile::save(
            &isolated,
            &mut isolated_bytes,
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let isolated_reloaded = neotales_keepass::KdbxFile::load(
            isolated_bytes.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            isolated_reloaded.root.entries[0]
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );

        let mut source = KeePassDatabase::default();
        source.root.entries.push(Entry::new("source"));
        let source = crate::interchange::decode(&crate::interchange::encode(&source).unwrap())
            .unwrap()
            .database;

        sync(&mut target, &source, SyncStrategy::Newest).unwrap();
        assert_eq!(
            target.root.entries[0]
                .password
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
        let mut synced_without_projection = target.clone();
        synced_without_projection.root.entries[0].password =
            ProtectedValue::from_text(String::new());
        let mut synced_without_projection_bytes = Vec::new();
        neotales_keepass::KdbxFile::save(
            &synced_without_projection,
            &mut synced_without_projection_bytes,
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let synced_without_projection_reloaded = neotales_keepass::KdbxFile::load(
            synced_without_projection_bytes.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            synced_without_projection_reloaded.root.entries[0]
                .field("Password")
                .unwrap()
                .value
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
        let mut credentials = neotales_keepass::KdbxCredentials::password("password").unwrap();
        let mut initial = Vec::new();
        neotales_keepass::KdbxFile::save(
            &target,
            &mut initial,
            &mut credentials,
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let loaded = neotales_keepass::KdbxFile::load(
            initial.as_slice(),
            &mut credentials,
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let mut bytes = Vec::new();
        neotales_keepass::KdbxFile::save(
            &loaded,
            &mut bytes,
            &mut credentials,
            neotales_keepass::KdbxWriteOptions::default(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        let reloaded = neotales_keepass::KdbxFile::load(
            bytes.as_slice(),
            &mut neotales_keepass::KdbxCredentials::password("password").unwrap(),
            &crate::KDBX_LIMITS,
        )
        .unwrap();
        assert_eq!(
            reloaded.root.entries[0]
                .password
                .reveal_text()
                .unwrap()
                .as_str(),
            "target-password"
        );
    }
}
