//! Standard `KeePass` 2.x icon catalog and custom-icon size limits.

/// Total number of standard `KeePass` 2.x icons (`0..=68`).
pub const STANDARD_ICON_COUNT: usize = 69;

/// Highest valid standard `KeePass` 2.x icon identifier.
pub const MAX_STANDARD_ICON_ID: u32 = 68;

/// Default standard icon identifier for newly created entries (`Key`).
pub const DEFAULT_ENTRY_ICON_ID: u32 = 0;

/// Default standard icon identifier for newly created groups (`Folder`).
pub const DEFAULT_GROUP_ICON_ID: u32 = 48;

/// Maximum custom icon payload size in bytes returned by [`crate::VaultService::custom_icon_bytes`].
pub const MAX_CUSTOM_ICON_BYTES: usize = 256 * 1024;

/// Logical category for a standard `KeePass` 2.x icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconCategory {
    /// Keys, locks, expiration, and certificates.
    Security,
    /// World, servers, sockets, and web resources.
    Network,
    /// Settings, consoles, tools, and operating systems.
    System,
    /// Email, identity, notes, finance, and personal items.
    Personal,
    /// Folders, archives, packages, and trash.
    Folders,
    /// Drives, screens, printers, cameras, and devices.
    Media,
    /// Documents, status indicators, and miscellaneous icons.
    Misc,
}

/// Descriptor for one standard `KeePass` 2.x icon (`0..=68`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardIcon {
    /// Numeric `KeePass` 2.x icon identifier (`0..=68`).
    pub id: u32,
    /// Standard `KeePass` 2.x display name.
    pub name: &'static str,
    /// Logical icon category.
    pub category: IconCategory,
    /// Single-column BMP Unicode symbol safe for TUI rendering.
    pub glyph: &'static str,
    /// Single printable ASCII fallback character.
    pub ascii: &'static str,
}

const fn icon(
    id: u32,
    name: &'static str,
    category: IconCategory,
    glyph: &'static str,
    ascii: &'static str,
) -> StandardIcon {
    StandardIcon {
        id,
        name,
        category,
        glyph,
        ascii,
    }
}

static STANDARD_ICONS: [StandardIcon; STANDARD_ICON_COUNT] = [
    icon(0, "Key", IconCategory::Security, "⚷", "K"),
    icon(1, "World", IconCategory::Network, "◎", "W"),
    icon(2, "Warning", IconCategory::Misc, "▲", "!"),
    icon(3, "Network Server", IconCategory::Network, "▣", "S"),
    icon(4, "Marked Directory", IconCategory::Folders, "◧", "F"),
    icon(5, "User Communication", IconCategory::Personal, "◉", "@"),
    icon(6, "Parts", IconCategory::System, "⚙", "%"),
    icon(7, "Notepad", IconCategory::Personal, "≡", "N"),
    icon(8, "World Socket", IconCategory::Network, "◈", "O"),
    icon(9, "Identity", IconCategory::Personal, "◐", "I"),
    icon(10, "Paper Ready", IconCategory::Misc, "▤", "R"),
    icon(11, "Digicam", IconCategory::Media, "◫", "C"),
    icon(12, "IR Communication", IconCategory::Network, "◌", "~"),
    icon(13, "Multi Keys", IconCategory::Security, "⚿", "k"),
    icon(14, "Energy", IconCategory::System, "❖", "E"),
    icon(15, "Scanner", IconCategory::Media, "▦", "s"),
    icon(16, "World Star", IconCategory::Network, "★", "*"),
    icon(17, "CD-Rom", IconCategory::Media, "○", "D"),
    icon(18, "Monitor", IconCategory::Media, "▭", "M"),
    icon(19, "Email", IconCategory::Personal, "✉", "e"),
    icon(20, "Configuration", IconCategory::System, "⚒", "c"),
    icon(21, "Clipboard Ready", IconCategory::Misc, "❏", "p"),
    icon(22, "Paper New", IconCategory::Misc, "▢", "n"),
    icon(23, "Screen", IconCategory::Media, "▬", "m"),
    icon(24, "Energy Careful", IconCategory::System, "△", "z"),
    icon(25, "Email Box", IconCategory::Personal, "⌧", "E"),
    icon(26, "Disk", IconCategory::Media, "◪", "d"),
    icon(27, "Drive", IconCategory::Media, "◩", "v"),
    icon(28, "Paper Q", IconCategory::Misc, "⍰", "?"),
    icon(29, "Terminal Encrypted", IconCategory::Security, "⌘", "#"),
    icon(30, "Console", IconCategory::System, "❯", ">"),
    icon(31, "Printer", IconCategory::Media, "⎙", "P"),
    icon(32, "Program Icons", IconCategory::System, "⊞", "G"),
    icon(33, "Run", IconCategory::System, "▷", "r"),
    icon(34, "Settings", IconCategory::System, "☸", "g"),
    icon(35, "World Computer", IconCategory::Network, "⊕", "w"),
    icon(36, "Archive", IconCategory::Folders, "⌸", "A"),
    icon(37, "Homebanking", IconCategory::Personal, "¤", "B"),
    icon(38, "Drive Windows", IconCategory::Media, "⊟", "V"),
    icon(39, "Clock", IconCategory::Misc, "◷", "T"),
    icon(40, "Email Search", IconCategory::Personal, "⌕", "q"),
    icon(41, "Paper Flag", IconCategory::Misc, "⚑", "f"),
    icon(42, "Memory", IconCategory::System, "◬", "y"),
    icon(43, "Trash Bin", IconCategory::Folders, "⌫", "X"),
    icon(44, "Note", IconCategory::Personal, "✎", "t"),
    icon(45, "Expired", IconCategory::Security, "⊗", "x"),
    icon(46, "Info", IconCategory::Misc, "ℹ", "i"),
    icon(47, "Package", IconCategory::Folders, "⬡", "a"),
    icon(48, "Folder", IconCategory::Folders, "▸", "F"),
    icon(49, "Folder Open", IconCategory::Folders, "▾", "f"),
    icon(50, "Folder Package", IconCategory::Folders, "◰", "b"),
    icon(51, "Lock Open", IconCategory::Security, "⚐", "u"),
    icon(52, "Paper Locked", IconCategory::Security, "◱", "L"),
    icon(53, "Checked", IconCategory::Misc, "✓", "+"),
    icon(54, "Pen", IconCategory::Personal, "✒", "j"),
    icon(55, "Thumbnail", IconCategory::Media, "◲", "h"),
    icon(56, "Book", IconCategory::Personal, "◳", "B"),
    icon(57, "List", IconCategory::Misc, "≣", "l"),
    icon(58, "User Key", IconCategory::Security, "⚶", "U"),
    icon(59, "Tool", IconCategory::System, "⌖", "t"),
    icon(60, "Home", IconCategory::Personal, "⌂", "H"),
    icon(61, "Star", IconCategory::Misc, "✦", "*"),
    icon(62, "Tux", IconCategory::System, "◆", "L"),
    icon(63, "Feather", IconCategory::Misc, "◇", "~"),
    icon(64, "Apple", IconCategory::System, "●", "A"),
    icon(65, "Wiki", IconCategory::Network, "§", "W"),
    icon(66, "Money", IconCategory::Personal, "$", "$"),
    icon(67, "Certificate", IconCategory::Security, "✪", "C"),
    icon(68, "BlackBerry", IconCategory::Media, "▯", "b"),
];

/// Returns the complete `KeePass` 2.x standard icon catalog ordered by ID (`0..=68`).
#[must_use]
pub fn standard_icons() -> &'static [StandardIcon] {
    &STANDARD_ICONS
}

/// Looks up a standard `KeePass` 2.x icon by ID (`0..=68`), returning `None` for unknown IDs.
#[must_use]
pub fn lookup_standard_icon(id: u32) -> Option<&'static StandardIcon> {
    STANDARD_ICONS.get(id as usize)
}

/// Returns the standard `KeePass` 2.x icon for `id`, falling back to icon `0` (`Key`) when `id` is unknown.
#[must_use]
pub fn standard_icon(id: u32) -> &'static StandardIcon {
    lookup_standard_icon(id).unwrap_or(&STANDARD_ICONS[DEFAULT_ENTRY_ICON_ID as usize])
}

/// Returns `true` when `id` is within the standard `KeePass` 2.x icon range (`0..=68`).
#[must_use]
pub const fn is_valid_standard_icon_id(id: u32) -> bool {
    id <= MAX_STANDARD_ICON_ID
}
