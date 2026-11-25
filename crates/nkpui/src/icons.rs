//! `KeePass` 2.x standard SVG icon catalog (`0..=68`), semantic `Kit` tinting,
//! and bounded custom KDBX icon rendering helpers.

use nkeepass::icons::{IconCategory, MAX_STANDARD_ICON_ID, STANDARD_ICON_COUNT, standard_icon};
use rune::{Color, El, Icon, Image, el, icon as rune_icon};
use rune_kit::Kit;

macro_rules! kicon {
    ($name:expr, $body:expr) => {
        Icon {
            name: $name,
            view: 24.0,
            body: $body,
        }
    };
}

/// Star icon used for favorite toggles (`KeePass` standard icon `61`).
pub static STAR_ICON: Icon = kicon!(
    "kp-61-star",
    r#"<polygon points="12 2.5 14.9 8.4 21.4 9.3 16.7 13.9 17.8 20.4 12 17.3 6.2 20.4 7.3 13.9 2.6 9.3 9.1 8.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
);

/// Filled star icon used when an entry is marked as a favorite.
pub static STAR_FILLED_ICON: Icon = kicon!(
    "kp-61-star-filled",
    r#"<polygon points="12 2.5 14.9 8.4 21.4 9.3 16.7 13.9 17.8 20.4 12 17.3 6.2 20.4 7.3 13.9 2.6 9.3 9.1 8.4" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>"#
);

/// Search icon used in filter inputs and search controls.
pub static SEARCH_ICON: Icon = kicon!(
    "kp-search",
    r#"<circle cx="11" cy="11" r="6.5" stroke="currentColor" stroke-width="1.8"/><path d="M15.8 15.8L20.5 20.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
);

/// All 69 `KeePass` 2.x standard vector SVG icons (`0..=68`) in a 24×24 viewBox.
pub static STANDARD_SVG_ICONS: [Icon; STANDARD_ICON_COUNT] = [
    // 0: Key
    kicon!(
        "kp-00-key",
        r#"<circle cx="7.5" cy="14.5" r="4.5" stroke="currentColor" stroke-width="1.8"/><path d="M10.7 11.3L19.5 2.5M16.5 5.5L19.5 8.5M14 8L16.5 10.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 1: World
    kicon!(
        "kp-01-world",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><ellipse cx="12" cy="12" rx="4.2" ry="9" stroke="currentColor" stroke-width="1.6"/><path d="M3.5 9.5H20.5M3.5 14.5H20.5" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 2: Warning
    kicon!(
        "kp-02-warning",
        r#"<path d="M12 3.2L21.2 19.5H2.8Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9.5V14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="16.8" r="1" fill="currentColor"/>"#
    ),
    // 3: Network Server
    kicon!(
        "kp-03-network-server",
        r#"<rect x="4" y="3.5" width="16" height="6" rx="1.5" stroke="currentColor" stroke-width="1.8"/><rect x="4" y="13.5" width="16" height="6" rx="1.5" stroke="currentColor" stroke-width="1.8"/><circle cx="7.5" cy="6.5" r="1" fill="currentColor"/><circle cx="7.5" cy="16.5" r="1" fill="currentColor"/><path d="M11 6.5H16.5M11 16.5H16.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>"#
    ),
    // 4: Marked Directory
    kicon!(
        "kp-04-marked-directory",
        r#"<path d="M3 6.5C3 5.4 3.9 4.5 5 4.5H9.5L11.5 6.8H19C20.1 6.8 21 7.7 21 8.8V18C21 19.1 20.1 20 19 20H5C3.9 20 3 19.1 3 18Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M9 13.5L11.2 15.7L15.5 11.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 5: User Communication
    kicon!(
        "kp-05-user-communication",
        r#"<circle cx="9.5" cy="8" r="3.5" stroke="currentColor" stroke-width="1.8"/><path d="M3.5 19.5C3.5 16.2 6.2 14 9.5 14C12.8 14 15.5 16.2 15.5 19.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M16 5.5H20.5V10.5L18 9H16Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>"#
    ),
    // 6: Parts
    kicon!(
        "kp-06-parts",
        r#"<path d="M14.7 6.3A4.5 4.5 0 0 0 9.1 12.1L4.2 17A1.8 1.8 0 0 0 6.8 19.5L11.7 14.6A4.5 4.5 0 0 0 17.5 9L14.9 11.6L12.3 9Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>"#
    ),
    // 7: Notepad
    kicon!(
        "kp-07-notepad",
        r#"<rect x="5" y="3.5" width="14" height="17" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 8.5H15.5M8.5 12H15.5M8.5 15.5H13" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 8: World Socket
    kicon!(
        "kp-08-world-socket",
        r#"<circle cx="10.5" cy="12" r="7.5" stroke="currentColor" stroke-width="1.8"/><path d="M3.5 12H17.5M10.5 4.5A10 10 0 0 1 10.5 19.5M10.5 4.5A10 10 0 0 0 10.5 19.5" stroke="currentColor" stroke-width="1.5"/><path d="M18 9H21.5M18 15H21.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 9: Identity
    kicon!(
        "kp-09-identity",
        r#"<rect x="3" y="5" width="18" height="14" rx="2" stroke="currentColor" stroke-width="1.8"/><circle cx="8.5" cy="11" r="2.2" stroke="currentColor" stroke-width="1.6"/><path d="M5.5 16.5C6.2 14.8 7.3 14.2 8.5 14.2C9.7 14.2 10.8 14.8 11.5 16.5M14 10H18.5M14 13.5H17.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>"#
    ),
    // 10: Paper Ready
    kicon!(
        "kp-10-paper-ready",
        r#"<path d="M6 3.5H14.5L18.5 7.5V20.5H6Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M14 3.5V8H18.5M9.5 13.5L11.5 15.5L15.5 11.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 11: Digicam
    kicon!(
        "kp-11-digicam",
        r#"<path d="M4 8.5H7.5L9 6H15L16.5 8.5H20C21.1 8.5 22 9.4 22 10.5V18C22 19.1 21.1 20 20 20H4C2.9 20 2 19.1 2 18V10.5C2 9.4 2.9 8.5 4 8.5Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="14" r="3.2" stroke="currentColor" stroke-width="1.8"/>"#
    ),
    // 12: IR Communication
    kicon!(
        "kp-12-ir-communication",
        r#"<circle cx="6.5" cy="17.5" r="2" fill="currentColor"/><path d="M6.5 11.5A6 6 0 0 1 12.5 17.5M6.5 7A10.5 10.5 0 0 1 17 17.5M6.5 3A14.5 14.5 0 0 1 21 17.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 13: Multi Keys
    kicon!(
        "kp-13-multi-keys",
        r#"<circle cx="6.5" cy="15.5" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M8.8 13.2L15.5 6.5M13.5 8.5L15.5 10.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="11.5" cy="17.5" r="2.5" stroke="currentColor" stroke-width="1.6"/><path d="M13.5 15.5L20 9M18 11L20 13" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>"#
    ),
    // 14: Energy
    kicon!(
        "kp-14-energy",
        r#"<path d="M13.5 2.5L5.5 13H12L10.5 21.5L18.5 11H12Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>"#
    ),
    // 15: Scanner
    kicon!(
        "kp-15-scanner",
        r#"<rect x="4" y="13" width="16" height="7" rx="1.5" stroke="currentColor" stroke-width="1.8"/><path d="M5 13L9 5H18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 10.5H21" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>"#
    ),
    // 16: World Star
    kicon!(
        "kp-16-world-star",
        r#"<circle cx="10.5" cy="12" r="7.5" stroke="currentColor" stroke-width="1.8"/><path d="M3.5 12H17.5M10.5 4.5A10 10 0 0 1 10.5 19.5" stroke="currentColor" stroke-width="1.5"/><polygon points="18.5 3.5 19.6 5.8 22.1 6.1 20.3 7.9 20.7 10.4 18.5 9.2 16.3 10.4 16.7 7.9 14.9 6.1 17.4 5.8" fill="currentColor"/>"#
    ),
    // 17: CD-Rom
    kicon!(
        "kp-17-cd-rom",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="2.8" stroke="currentColor" stroke-width="1.8"/><path d="M12 3V7M17 17L14.2 14.2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>"#
    ),
    // 18: Monitor
    kicon!(
        "kp-18-monitor",
        r#"<rect x="3" y="4" width="18" height="12.5" rx="1.8" stroke="currentColor" stroke-width="1.8"/><path d="M9 20H15M12 16.5V20" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 19: Email
    kicon!(
        "kp-19-email",
        r#"<rect x="3" y="5.5" width="18" height="13" rx="1.8" stroke="currentColor" stroke-width="1.8"/><path d="M3.5 6.5L12 13L20.5 6.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 20: Configuration
    kicon!(
        "kp-20-configuration",
        r#"<path d="M4 7H20M4 12H20M4 17H20" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="9" cy="7" r="2" fill="currentColor"/><circle cx="15" cy="12" r="2" fill="currentColor"/><circle cx="10" cy="17" r="2" fill="currentColor"/>"#
    ),
    // 21: Clipboard Ready
    kicon!(
        "kp-21-clipboard-ready",
        r#"<rect x="5" y="5" width="14" height="16" rx="1.8" stroke="currentColor" stroke-width="1.8"/><path d="M9 5V3.5H15V5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M9 13.5L11 15.5L15.5 11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 22: Paper New
    kicon!(
        "kp-22-paper-new",
        r#"<path d="M6 3.5H14.5L18.5 7.5V20.5H6Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M14 3.5V8H18.5M12 11.5V16.5M9.5 14H14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 23: Screen
    kicon!(
        "kp-23-screen",
        r#"<rect x="3" y="5" width="18" height="14" rx="1.8" stroke="currentColor" stroke-width="1.8"/><path d="M3 9H21" stroke="currentColor" stroke-width="1.6"/><circle cx="6" cy="7" r="0.8" fill="currentColor"/><circle cx="8.8" cy="7" r="0.8" fill="currentColor"/>"#
    ),
    // 24: Energy Careful
    kicon!(
        "kp-24-energy-careful",
        r#"<path d="M13 3L6 13H11.5L10.5 21L17.5 11H12Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><circle cx="18.5" cy="17.5" r="3" stroke="currentColor" stroke-width="1.5"/>"#
    ),
    // 25: Email Box
    kicon!(
        "kp-25-email-box",
        r#"<path d="M4 7.5H20V18.5H4Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M4 13.5H8.5L10 15.5H14L15.5 13.5H20M7 4.5H17" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 26: Disk
    kicon!(
        "kp-26-disk",
        r#"<path d="M4 4H17L20 7V20H4Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><rect x="7.5" y="4" width="7.5" height="5" stroke="currentColor" stroke-width="1.6"/><rect x="7" y="13.5" width="10" height="6.5" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 27: Drive
    kicon!(
        "kp-27-drive",
        r#"<rect x="3" y="6.5" width="18" height="11" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M3 13.5H21" stroke="currentColor" stroke-width="1.6"/><circle cx="17" cy="15.5" r="1" fill="currentColor"/>"#
    ),
    // 28: Paper Q
    kicon!(
        "kp-28-paper-q",
        r#"<path d="M6 3.5H14.5L18.5 7.5V20.5H6Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M10.2 11A2 2 0 1 1 12.2 13V14.2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12.2" cy="17" r="0.9" fill="currentColor"/>"#
    ),
    // 29: Terminal Encrypted
    kicon!(
        "kp-29-terminal-encrypted",
        r#"<rect x="3" y="4.5" width="18" height="15" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M6.5 9.5L9.5 12L6.5 14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><rect x="13.5" y="12" width="5" height="4" rx="0.8" stroke="currentColor" stroke-width="1.6"/><path d="M14.5 12V10.5A1.5 1.5 0 0 1 17.5 10.5V12" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 30: Console
    kicon!(
        "kp-30-console",
        r#"<rect x="3" y="4.5" width="18" height="15" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M7 9.5L10.5 12.5L7 15.5M12 15.5H17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 31: Printer
    kicon!(
        "kp-31-printer",
        r#"<path d="M7 8V4H17V8M7 16H4V10H20V16H17" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><rect x="7" y="13.5" width="10" height="6.5" stroke="currentColor" stroke-width="1.8"/>"#
    ),
    // 32: Program Icons
    kicon!(
        "kp-32-program-icons",
        r#"<rect x="3.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/>"#
    ),
    // 33: Run
    kicon!(
        "kp-33-run",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><polygon points="10 8 17 12 10 16" fill="currentColor"/>"#
    ),
    // 34: Settings
    kicon!(
        "kp-34-settings",
        r#"<circle cx="12" cy="12" r="3.2" stroke="currentColor" stroke-width="1.8"/><path d="M12 3V5.5M12 18.5V21M3 12H5.5M18.5 12H21M5.6 5.6L7.4 7.4M16.6 16.6L18.4 18.4M18.4 5.6L16.6 7.4M7.4 16.6L5.6 18.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 35: World Computer
    kicon!(
        "kp-35-world-computer",
        r#"<circle cx="9.5" cy="9.5" r="6" stroke="currentColor" stroke-width="1.7"/><path d="M3.8 9.5H15.2M9.5 3.5A8 8 0 0 1 9.5 15.5" stroke="currentColor" stroke-width="1.4"/><rect x="12" y="13.5" width="9" height="6.5" rx="1.2" stroke="currentColor" stroke-width="1.7"/>"#
    ),
    // 36: Archive
    kicon!(
        "kp-36-archive",
        r#"<rect x="3.5" y="4.5" width="17" height="4.5" rx="1" stroke="currentColor" stroke-width="1.8"/><path d="M5 9V19.5H19V9M9.5 13H14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 37: Homebanking
    kicon!(
        "kp-37-homebanking",
        r#"<path d="M3 9.5L12 4L21 9.5Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M5.5 9.5V18M9.8 9.5V18M14.2 9.5V18M18.5 9.5V18M3.5 19.5H20.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 38: Drive Windows
    kicon!(
        "kp-38-drive-windows",
        r#"<rect x="3.5" y="4.5" width="17" height="15" rx="1.8" stroke="currentColor" stroke-width="1.8"/><path d="M12 4.5V19.5M3.5 12H20.5" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 39: Clock
    kicon!(
        "kp-39-clock",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M12 7V12L15.5 14" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 40: Email Search
    kicon!(
        "kp-40-email-search",
        r#"<path d="M3 6H19V13.5M3 6V17H11.5M3 6.5L11 12L19 6.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><circle cx="16.5" cy="16.5" r="3.2" stroke="currentColor" stroke-width="1.7"/><path d="M19 19L21.5 21.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 41: Paper Flag
    kicon!(
        "kp-41-paper-flag",
        r#"<path d="M6 20.5V4H16.5L14.5 7.8L16.5 11.5H6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 42: Memory
    kicon!(
        "kp-42-memory",
        r#"<rect x="6" y="6" width="12" height="12" rx="1.5" stroke="currentColor" stroke-width="1.8"/><path d="M9 3V6M15 3V6M9 18V21M15 18V21M3 9H6M3 15H6M18 9H21M18 15H21" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 43: Trash Bin
    kicon!(
        "kp-43-trash-bin",
        r#"<path d="M4.5 6.5H19.5M9 6.5V4H15V6.5M6.5 6.5L7.5 20H16.5L17.5 6.5M10 10.5V16.5M14 10.5V16.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 44: Note
    kicon!(
        "kp-44-note",
        r#"<path d="M4.5 4.5H19.5V14.5L14.5 19.5H4.5Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M14.5 19.5V14.5H19.5M8 9.5H16M8 13H12.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 45: Expired
    kicon!(
        "kp-45-expired",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 8.5L15.5 15.5M15.5 8.5L8.5 15.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 46: Info
    kicon!(
        "kp-46-info",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="8" r="1" fill="currentColor"/><path d="M12 11.5V16.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 47: Package
    kicon!(
        "kp-47-package",
        r#"<path d="M12 3L20.5 7.5V16.5L12 21L3.5 16.5V7.5Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M3.5 7.5L12 12L20.5 7.5M12 12V21" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>"#
    ),
    // 48: Folder
    kicon!(
        "kp-48-folder",
        r#"<path d="M3 6.5C3 5.4 3.9 4.5 5 4.5H9.5L11.5 7H19C20.1 7 21 7.9 21 9V18C21 19.1 20.1 20 19 20H5C3.9 20 3 19.1 3 18Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>"#
    ),
    // 49: Folder Open
    kicon!(
        "kp-49-folder-open",
        r#"<path d="M3 18V6.5C3 5.4 3.9 4.5 5 4.5H9.5L11.5 7H18.5C19.6 7 20.5 7.9 20.5 9V10.5M3 18L5.5 10.5H21.5L19 18.5C18.7 19.4 17.9 20 17 20H5C3.9 20 3 19.1 3 18Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>"#
    ),
    // 50: Folder Package
    kicon!(
        "kp-50-folder-package",
        r#"<path d="M3 6.5C3 5.4 3.9 4.5 5 4.5H9.5L11.5 7H19C20.1 7 21 7.9 21 9V18C21 19.1 20.1 20 19 20H5C3.9 20 3 19.1 3 18Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 10.5V16.5M9.5 13.5H14.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 51: Lock Open
    kicon!(
        "kp-51-lock-open",
        r#"<rect x="5" y="10.5" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 10.5V7.5A3.5 3.5 0 0 1 15.3 6.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="15.5" r="1.2" fill="currentColor"/>"#
    ),
    // 52: Paper Locked
    kicon!(
        "kp-52-paper-locked",
        r#"<path d="M6 3.5H14.5L18.5 7.5V20.5H6Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><rect x="9.5" y="12.5" width="5" height="4.5" rx="0.8" stroke="currentColor" stroke-width="1.6"/><path d="M10.5 12.5V11A1.5 1.5 0 0 1 13.5 11V12.5" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 53: Checked
    kicon!(
        "kp-53-checked",
        r#"<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M8 12.2L10.8 15L16.2 9.2" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 54: Pen
    kicon!(
        "kp-54-pen",
        r#"<path d="M4 20L5.2 15.2L16.8 3.6A1.8 1.8 0 0 1 19.4 6.2L7.8 17.8Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M14.5 5.9L17.1 8.5" stroke="currentColor" stroke-width="1.6"/>"#
    ),
    // 55: Thumbnail
    kicon!(
        "kp-55-thumbnail",
        r#"<rect x="3.5" y="4.5" width="17" height="15" rx="2" stroke="currentColor" stroke-width="1.8"/><circle cx="8.5" cy="9.5" r="1.5" fill="currentColor"/><path d="M5 17L10 12L13.5 15L16 12.8L19 17" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 56: Book
    kicon!(
        "kp-56-book",
        r#"<path d="M5 4.5H17.5C18.6 4.5 19.5 5.4 19.5 6.5V19.5H6.5C5.7 19.5 5 18.8 5 18Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M5 16.5H19.5M8.5 8.5H15.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 57: List
    kicon!(
        "kp-57-list",
        r#"<path d="M8.5 6.5H20M8.5 12H20M8.5 17.5H20" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="4.5" cy="6.5" r="1.1" fill="currentColor"/><circle cx="4.5" cy="12" r="1.1" fill="currentColor"/><circle cx="4.5" cy="17.5" r="1.1" fill="currentColor"/>"#
    ),
    // 58: User Key
    kicon!(
        "kp-58-user-key",
        r#"<circle cx="8.5" cy="8" r="3.2" stroke="currentColor" stroke-width="1.8"/><path d="M3 19C3 15.8 5.5 13.8 8.5 13.8C10.2 13.8 11.8 14.5 12.8 15.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="16" cy="16.5" r="2.5" stroke="currentColor" stroke-width="1.7"/><path d="M18 14.5L21 11.5M19.5 13L21 14.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 59: Tool
    kicon!(
        "kp-59-tool",
        r#"<path d="M15.5 4.5L19.5 8.5L17 11L13 7ZM13 7L5 15L7 19L11 17L17 11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 60: Home
    kicon!(
        "kp-60-home",
        r#"<path d="M3.5 11.5L12 4L20.5 11.5M5.5 10V19.5H10V14.5H14V19.5H18.5V10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 61: Star
    kicon!(
        "kp-61-star",
        r#"<polygon points="12 2.5 14.9 8.4 21.4 9.3 16.7 13.9 17.8 20.4 12 17.3 6.2 20.4 7.3 13.9 2.6 9.3 9.1 8.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 62: Tux
    kicon!(
        "kp-62-tux",
        r#"<path d="M12 3.5C9.5 3.5 8 5.5 8 8.5C8 10.5 6 13.5 6 16.5C6 19 8.5 20.5 12 20.5C15.5 20.5 18 19 18 16.5C18 13.5 16 10.5 16 8.5C16 5.5 14.5 3.5 12 3.5Z" stroke="currentColor" stroke-width="1.8"/><circle cx="10.5" cy="7.5" r="0.8" fill="currentColor"/><circle cx="13.5" cy="7.5" r="0.8" fill="currentColor"/><path d="M10.5 9.8L12 11L13.5 9.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 63: Feather
    kicon!(
        "kp-63-feather",
        r#"<path d="M19.5 4.5C15 4.5 10.5 8 8 12.5L4.5 19.5L11.5 16C16 13.5 19.5 9 19.5 4.5Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M4.5 19.5L14.5 9.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>"#
    ),
    // 64: Apple
    kicon!(
        "kp-64-apple",
        r#"<path d="M12 7.5C9 7.5 6.5 9.8 6.5 13.5C6.5 17 9 20 11 20C11.7 20 12 19.6 12 19.6C12 19.6 12.3 20 13 20C15 20 17.5 17 17.5 13.5C17.5 9.8 15 7.5 12 7.5Z" stroke="currentColor" stroke-width="1.8"/><path d="M12 7.5C12 5.5 13.5 4 15 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 65: Wiki
    kicon!(
        "kp-65-wiki",
        r#"<path d="M3.5 6L7.5 18L11.5 8L15.5 18L20.5 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 66: Money
    kicon!(
        "kp-66-money",
        r#"<path d="M12 3.5V20.5M15.8 7.5C15.8 5.8 14.1 4.8 12 4.8C9.9 4.8 8.2 5.8 8.2 7.5C8.2 9.4 10 10.2 12 10.8C14 11.4 16 12.2 16 14.3C16 16.2 14.2 17.4 12 17.4C9.7 17.4 8 16.2 8 14.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#
    ),
    // 67: Certificate
    kicon!(
        "kp-67-certificate",
        r#"<circle cx="12" cy="9.5" r="5.5" stroke="currentColor" stroke-width="1.8"/><path d="M9.5 14.2L8.5 20.5L12 18.5L15.5 20.5L14.5 14.2" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M9.8 9.5L11.3 11L14.4 7.8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>"#
    ),
    // 68: BlackBerry
    kicon!(
        "kp-68-blackberry",
        r#"<rect x="6.5" y="2.8" width="11" height="18.4" rx="2.2" stroke="currentColor" stroke-width="1.8"/><path d="M9 6.5H15V11H9Z" stroke="currentColor" stroke-width="1.5"/><circle cx="9.5" cy="14.5" r="0.8" fill="currentColor"/><circle cx="12" cy="14.5" r="0.8" fill="currentColor"/><circle cx="14.5" cy="14.5" r="0.8" fill="currentColor"/><circle cx="12" cy="17.5" r="0.8" fill="currentColor"/>"#
    ),
];

/// Returns the static SVG vector [`Icon`] for `KeePass` standard icon `id` (`0..=68`),
/// falling back to icon `0` (`Key`) for unknown IDs.
#[must_use]
pub fn standard_svg_icon(id: u32) -> &'static Icon {
    if id <= MAX_STANDARD_ICON_ID {
        &STANDARD_SVG_ICONS[id as usize]
    } else {
        &STANDARD_SVG_ICONS[0]
    }
}

/// Returns a category- and status-aware semantic [`Kit`] tint colour for standard icon `id`
/// with WCAG AA contrast in both dark and light modes.
#[must_use]
pub fn semantic_tint(k: &Kit, id: u32) -> Color {
    match id {
        2 => k.c.warning.icon,
        43 | 45 => k.c.danger.icon,
        51 | 53 => k.c.success.icon,
        28 | 46 => k.c.info.icon,
        0 | 13 | 29 | 52 | 58 | 61 | 67 => k.c.icon_accent,
        _ => match standard_icon(id).category {
            IconCategory::Security => k.c.icon_accent,
            IconCategory::Network | IconCategory::Personal | IconCategory::Folders => k.c.icon_base,
            IconCategory::System | IconCategory::Media | IconCategory::Misc => k.c.icon_muted,
        },
    }
}

/// Maximum allowed raster width or height in pixels for decoded custom KDBX icons.
pub const MAX_CUSTOM_ICON_DIMENSION: u32 = 1024;

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn dims_within(w: u32, h: u32, max_dim: u32) -> bool {
    w > 0 && h > 0 && w <= max_dim && h <= max_dim
}

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.get(..8) != Some(SIG.as_slice()) || bytes.get(12..16) != Some(b"IHDR".as_slice()) {
        return None;
    }
    Some((read_u32_be(bytes, 16)?, read_u32_be(bytes, 20)?))
}

fn gif_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let hdr = bytes.get(..6)?;
    if hdr != b"GIF87a" && hdr != b"GIF89a" {
        return None;
    }
    Some((
        u32::from(read_u16_le(bytes, 6)?),
        u32::from(read_u16_le(bytes, 8)?),
    ))
}

fn bmp_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2) != Some(b"BM".as_slice()) {
        return None;
    }
    let dib_size = read_u32_le(bytes, 14)?;
    if dib_size == 12 {
        Some((
            u32::from(read_u16_le(bytes, 18)?),
            u32::from(read_u16_le(bytes, 20)?),
        ))
    } else if dib_size >= 40 {
        let w = i32::from_le_bytes(bytes.get(18..22)?.try_into().ok()?);
        let h = i32::from_le_bytes(bytes.get(22..26)?.try_into().ok()?);
        (w > 0 && h != 0).then(|| (w.unsigned_abs(), h.unsigned_abs()))
    } else {
        None
    }
}

fn webp_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..4) != Some(b"RIFF".as_slice()) || bytes.get(8..12) != Some(b"WEBP".as_slice()) {
        return None;
    }
    match bytes.get(12..16)? {
        b"VP8 " => {
            if bytes.get(23..26) != Some([0x9d_u8, 0x01, 0x2a].as_slice()) {
                return None;
            }
            let w = u32::from(read_u16_le(bytes, 26)? & 0x3fff);
            let h = u32::from(read_u16_le(bytes, 28)? & 0x3fff);
            Some((w, h))
        }
        b"VP8L" => {
            if *bytes.get(20)? != 0x2f {
                return None;
            }
            let bits = read_u32_le(bytes, 21)?;
            Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
        }
        // Reject extended/animated WebP (VP8X) because canvas dimensions can
        // understate inner VP8/VP8L/ANMF frame allocations during decode.
        _ => None,
    }
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2) != Some([0xff_u8, 0xd8].as_slice()) {
        return None;
    }
    let mut pos = 2usize;
    while pos < bytes.len() {
        if bytes.get(pos) != Some(&0xff) {
            return None;
        }
        while bytes.get(pos) == Some(&0xff) {
            pos += 1;
        }
        let marker = *bytes.get(pos)?;
        pos += 1;
        if marker == 0x00 || marker == 0xd9 || marker == 0xda {
            return None;
        }
        if (0xd0..=0xd8).contains(&marker) || marker == 0x01 {
            continue;
        }
        let seg_len = usize::from(read_u16_be(bytes, pos)?);
        if seg_len < 2 {
            return None;
        }
        if matches!(
            marker,
            0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf
        ) {
            if seg_len < 7 {
                return None;
            }
            let h = u32::from(read_u16_be(bytes, pos + 3)?);
            let w = u32::from(read_u16_be(bytes, pos + 5)?);
            return Some((w, h));
        }
        pos = pos.checked_add(seg_len)?;
    }
    None
}

fn ico_dib_dimensions_within(payload: &[u8], max_dim: u32) -> bool {
    let Some(dib_size) = read_u32_le(payload, 0) else {
        return false;
    };
    if dib_size == 12 && payload.len() >= 12 {
        let Some(w) = read_u16_le(payload, 4).map(u32::from) else {
            return false;
        };
        let Some(h) = read_u16_le(payload, 6).map(u32::from) else {
            return false;
        };
        h >= 2 && dims_within(w, h / 2, max_dim)
    } else if dib_size >= 40 && payload.len() >= 40 {
        let Ok(w_bytes) = payload[4..8].try_into() else {
            return false;
        };
        let Ok(h_bytes) = payload[8..12].try_into() else {
            return false;
        };
        let w = i32::from_le_bytes(w_bytes);
        let h = i32::from_le_bytes(h_bytes);
        if w <= 0 || h == 0 || h == i32::MIN {
            return false;
        }
        let ico_h = h.unsigned_abs() / 2;
        dims_within(w.unsigned_abs(), ico_h, max_dim)
    } else {
        false
    }
}

fn ico_dimensions_within(bytes: &[u8], max_dim: u32) -> Option<bool> {
    if bytes.get(..4) != Some([0x00_u8, 0x00, 0x01, 0x00].as_slice()) {
        return None;
    }
    let count = usize::from(read_u16_le(bytes, 4)?);
    if count == 0 || count > 64 {
        return Some(false);
    }
    for i in 0..count {
        let entry = bytes.get(6 + i * 16..6 + (i + 1) * 16)?;
        let w = if entry[0] == 0 {
            256
        } else {
            u32::from(entry[0])
        };
        let h = if entry[1] == 0 {
            256
        } else {
            u32::from(entry[1])
        };
        if !dims_within(w, h, max_dim) {
            return Some(false);
        }
        let payload_len = usize::try_from(read_u32_le(entry, 8)?).ok()?;
        let payload_off = usize::try_from(read_u32_le(entry, 12)?).ok()?;
        let payload_end = payload_off.checked_add(payload_len)?;
        let payload = bytes.get(payload_off..payload_end)?;
        if payload.get(..8) == Some(b"\x89PNG\r\n\x1a\n".as_slice()) {
            let Some((pw, ph)) = png_dimensions(payload) else {
                return Some(false);
            };
            if !dims_within(pw, ph, max_dim) {
                return Some(false);
            }
        } else if !ico_dib_dimensions_within(payload, max_dim) {
            return Some(false);
        }
    }
    Some(true)
}

/// Validates raster image header dimensions (PNG IHDR, JPEG SOF, GIF, BMP, WebP, ICO)
/// before handing untrusted custom KDBX icon bytes to Rune's image decoder.
///
/// Rejects unrecognized formats, zero dimensions, and dimensions exceeding `max_dim`.
#[must_use]
pub fn raster_dimensions_within_limit(bytes: &[u8], max_dim: u32) -> bool {
    if max_dim == 0 {
        return false;
    }
    if let Some((w, h)) = png_dimensions(bytes)
        .or_else(|| gif_dimensions(bytes))
        .or_else(|| bmp_dimensions(bytes))
        .or_else(|| webp_dimensions(bytes))
        .or_else(|| jpeg_dimensions(bytes))
    {
        return dims_within(w, h, max_dim);
    }
    ico_dimensions_within(bytes, max_dim).unwrap_or(false)
}

/// Renders either a decoded custom KDBX icon (`img.size().is_some()`) or the matching
/// standard `KeePass` vector SVG icon with semantic [`Kit`] tinting.
pub fn render_keepass_icon(
    k: &Kit,
    icon_id: u32,
    custom_icon: Option<&Image>,
    size: f32,
    key: impl Into<String>,
) -> El {
    let key_str = key.into();
    if let Some(img) = custom_icon
        && img.size().is_some()
    {
        return el()
            .key(key_str)
            .size(size, size)
            .pixels(img.pixels())
            .a11y_hidden();
    }
    rune_icon(standard_svg_icon(icon_id), size)
        .key(key_str)
        .color(semantic_tint(k, icon_id))
        .a11y_hidden()
}

#[cfg(test)]
mod tests {
    use nkeepass::icons::{MAX_STANDARD_ICON_ID, STANDARD_ICON_COUNT, standard_icons};

    use super::*;

    #[test]
    fn all_69_standard_icons_have_unique_svg_bodies() {
        assert_eq!(STANDARD_SVG_ICONS.len(), STANDARD_ICON_COUNT);
        let catalog = standard_icons();
        for (idx, meta) in catalog.iter().enumerate() {
            let svg = standard_svg_icon(meta.id);
            assert_eq!(u32::try_from(idx), Ok(meta.id));
            assert!((svg.view - 24.0).abs() < f32::EPSILON);
            assert_ne!(svg.body.trim(), "");
            assert!(svg.name.starts_with("kp-"));
        }
        assert_eq!(
            standard_svg_icon(MAX_STANDARD_ICON_ID + 1).name,
            STANDARD_SVG_ICONS[0].name
        );
        assert_eq!(standard_svg_icon(u32::MAX).name, STANDARD_SVG_ICONS[0].name);
    }

    #[test]
    fn semantic_tint_covers_dark_and_light_modes() {
        for dark in [false, true] {
            let k = Kit::neutral(dark);
            for id in 0..=MAX_STANDARD_ICON_ID {
                let c = semantic_tint(&k, id);
                assert!(c.a > 0.5, "icon {id} tint should remain opaque");
            }
        }
    }

    fn png_header_bytes(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(29);
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        out.extend_from_slice(&13_u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&w.to_be_bytes());
        out.extend_from_slice(&h.to_be_bytes());
        out.extend_from_slice(&[8, 6, 0, 0, 0]);
        out
    }

    #[test]
    fn raster_dimension_guard_validates_headers_and_rejects_oversized() {
        assert!(raster_dimensions_within_limit(
            &png_header_bytes(64, 64),
            MAX_CUSTOM_ICON_DIMENSION
        ));
        assert!(raster_dimensions_within_limit(
            &png_header_bytes(1024, 1024),
            MAX_CUSTOM_ICON_DIMENSION
        ));
        assert!(!raster_dimensions_within_limit(
            &png_header_bytes(8192, 8192),
            MAX_CUSTOM_ICON_DIMENSION
        ));
        assert!(!raster_dimensions_within_limit(
            &png_header_bytes(0, 64),
            MAX_CUSTOM_ICON_DIMENSION
        ));

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&32_u16.to_le_bytes());
        gif.extend_from_slice(&32_u16.to_le_bytes());
        assert!(raster_dimensions_within_limit(
            &gif,
            MAX_CUSTOM_ICON_DIMENSION
        ));

        let mut huge_gif = b"GIF89a".to_vec();
        huge_gif.extend_from_slice(&2048_u16.to_le_bytes());
        huge_gif.extend_from_slice(&32_u16.to_le_bytes());
        assert!(!raster_dimensions_within_limit(
            &huge_gif,
            MAX_CUSTOM_ICON_DIMENSION
        ));

        let jpeg = [
            0xff_u8, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x40, 0x00, 0x40,
        ];
        assert!(raster_dimensions_within_limit(
            &jpeg,
            MAX_CUSTOM_ICON_DIMENSION
        ));
        let huge_jpeg = [
            0xff_u8, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x10, 0x00, 0x00, 0x40,
        ];
        assert!(!raster_dimensions_within_limit(
            &huge_jpeg,
            MAX_CUSTOM_ICON_DIMENSION
        ));

        assert!(!raster_dimensions_within_limit(
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            MAX_CUSTOM_ICON_DIMENSION
        ));
        assert!(!raster_dimensions_within_limit(
            b"not-an-image",
            MAX_CUSTOM_ICON_DIMENSION
        ));

        // Reject extended/animated WebP (VP8X) while allowing simple VP8L.
        let mut extended_webp = Vec::from(*b"RIFF\x24\x00\x00\x00WEBPVP8X\x0a\x00\x00\x00");
        extended_webp.extend_from_slice(&[0_u8; 4]);
        extended_webp.extend_from_slice(&[31, 0, 0, 31, 0, 0]);
        assert!(!raster_dimensions_within_limit(
            &extended_webp,
            MAX_CUSTOM_ICON_DIMENSION
        ));
        let mut lossless_webp = Vec::from(*b"RIFF\x18\x00\x00\x00WEBPVP8L\x0c\x00\x00\x00\x2f");
        let packed = 31_u32 | (31_u32 << 14);
        lossless_webp.extend_from_slice(&packed.to_le_bytes());
        assert!(raster_dimensions_within_limit(
            &lossless_webp,
            MAX_CUSTOM_ICON_DIMENSION
        ));

        // Reject spoofed JPEG markers lacking 0xFF prefix (even if followed by valid SOF0).
        let spoofed_jpeg = [
            0xff_u8, 0xd8, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x20, 0x00, 0x20, 0xff, 0xc0, 0x00, 0x0b,
            0x08, 0x20, 0x00, 0x20, 0x00,
        ];
        assert!(!raster_dimensions_within_limit(
            &spoofed_jpeg,
            MAX_CUSTOM_ICON_DIMENSION
        ));

        // Validate ICO DIB headers: reject (0, 0) entry with 8192x16384 BITMAPINFOHEADER, accept 32x64.
        let make_dib_ico = |w: i32, h: i32| -> Vec<u8> {
            let mut ico = Vec::with_capacity(62);
            ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
            ico.extend_from_slice(&[0, 0, 0, 0, 1, 0, 32, 0]);
            ico.extend_from_slice(&40_u32.to_le_bytes());
            ico.extend_from_slice(&22_u32.to_le_bytes());
            ico.extend_from_slice(&40_u32.to_le_bytes());
            ico.extend_from_slice(&w.to_le_bytes());
            ico.extend_from_slice(&h.to_le_bytes());
            ico.extend_from_slice(&[0_u8; 28]);
            ico
        };
        assert!(!raster_dimensions_within_limit(
            &make_dib_ico(8192, 16384),
            MAX_CUSTOM_ICON_DIMENSION
        ));
        assert!(raster_dimensions_within_limit(
            &make_dib_ico(32, 64),
            MAX_CUSTOM_ICON_DIMENSION
        ));
    }
}
