//! Narrow, audited Win32 clipboard ownership boundary.
//!
//! These operations require a console window because `EmptyClipboard` needs an
//! owner window. In pseudoconsole/no-window environments they fail closed.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "Win32 clipboard FFI is isolated in this crate and each unsafe block documents its contract"
)]

use zeroize::Zeroizing;

/// Sanitized failure from a native clipboard operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClipboardError;

fn sequence_is_current(captured: u32, current: u32) -> bool {
    captured != 0 && captured == current
}
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::System::{
    Console::GetConsoleWindow,
    DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, SetClipboardData,
    },
    Memory::{GlobalAlloc, GlobalLock, GlobalUnlock},
};

const CF_UNICODETEXT: u32 = 13;
const GMEM_MOVEABLE: u32 = 0x0002;

/// Describes a clipboard write and whether ownership can be tracked.
///
/// A successful write can still be partial from the caller's perspective:
/// `closed` is false if the clipboard could not be closed, or `sequence` is
/// `None` if Windows did not provide a usable sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetResult {
    /// Sequence number identifying the installed clipboard contents, if available.
    pub sequence: Option<u32>,
    /// Whether `CloseClipboard` succeeded after the write.
    pub closed: bool,
}

/// Writes UTF-16 text and captures the clipboard sequence while locked.
///
/// Embedded NULs are rejected. Requires a valid console window; returns an
/// error when no console window exists. A successful result can still indicate
/// partial success; clear only when both `closed` is true and `sequence` exists.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(windows)] {
/// let result = windows_clipboard::set_text_and_get_sequence("secret")?;
/// if result.closed {
///     if let Some(sequence) = result.sequence {
///         let _ = windows_clipboard::clear_if_sequence(sequence)?;
///     }
/// }
/// # }
/// # Ok::<(), windows_clipboard::ClipboardError>(())
/// ```
pub fn set_text_and_get_sequence(value: &str) -> Result<SetResult, ClipboardError> {
    if value.contains('\0') {
        return Err(ClipboardError);
    }
    let mut wide = Zeroizing::new(value.encode_utf16().collect::<Vec<u16>>());
    wide.push(0);
    let bytes = wide
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(ClipboardError)?;

    // GetConsoleWindow provides the owner required by EmptyClipboard;
    // in pseudoconsole/no-window mode we fail closed.
    // SAFETY: GetConsoleWindow has no preconditions or pointer arguments.
    let owner = unsafe { GetConsoleWindow() };
    if owner.is_null() {
        return Err(ClipboardError);
    }
    // SAFETY: The HWND came from GetConsoleWindow and remains valid while
    // the console process is running. OpenClipboard locks out other writers.
    if unsafe { OpenClipboard(owner) } == 0 {
        return Err(ClipboardError);
    }

    // Clipboard memory must be movable and remain owned by us until
    // SetClipboardData succeeds.
    // SAFETY: The allocation size is the checked Vec length in bytes.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
    let result = if memory.is_null() {
        Err(ClipboardError)
    } else {
        // SAFETY: memory is a live GlobalAlloc handle; clipboard is locked.
        let destination = unsafe { GlobalLock(memory) }.cast::<u16>();
        if destination.is_null() {
            // SAFETY: SetClipboardData has not taken ownership.
            unsafe { GlobalFree(memory) };
            Err(ClipboardError)
        } else {
            // SAFETY: destination has enough bytes for wide and is aligned
            // for u16; source/destination do not overlap.
            unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), destination, wide.len()) };
            // SAFETY: memory is locked above. Unlock before transferring it.
            unsafe { GlobalUnlock(memory) };
            // SAFETY: Clipboard is open and memory contains nul-terminated
            // CF_UNICODETEXT. On success the system owns the allocation.
            if unsafe { EmptyClipboard() } == 0
                || unsafe { SetClipboardData(CF_UNICODETEXT, memory) }.is_null()
            {
                // SAFETY: SetClipboardData failure leaves ownership with us.
                // EmptyClipboard failure also means transfer was not attempted.
                unsafe { GlobalFree(memory) };
                Err(ClipboardError)
            } else {
                // The lock excludes other writers through this capture, so
                // this sequence identifies the contents we just installed.
                // SAFETY: Read-only API with no pointer arguments.
                let sequence = unsafe { GetClipboardSequenceNumber() };
                Ok((sequence != 0).then_some(sequence))
            }
        }
    };

    // SAFETY: This process successfully opened the clipboard above.
    let closed = unsafe { CloseClipboard() } != 0;
    result.map(|sequence| SetResult { sequence, closed })
}

/// Clears the clipboard only if its current sequence still equals `expected`.
///
/// The comparison and clear happen while the clipboard is locked, so newer
/// contents are preserved. Requires a valid console window; returns `Ok(false)`
/// when the sequence differs.
pub fn clear_if_sequence(expected: u32) -> Result<bool, ClipboardError> {
    // A console window is a valid clipboard owner HWND for this console TUI.
    // In pseudoconsole/no-window mode there is no valid owner and we fail safe.
    // SAFETY: GetConsoleWindow has no preconditions or pointer arguments.
    let owner = unsafe { GetConsoleWindow() };
    if owner.is_null() {
        return Err(ClipboardError);
    }
    // SAFETY: The HWND came from GetConsoleWindow and remains valid while the
    // console process is running. Clipboard access is process-global.
    if unsafe { OpenClipboard(owner) } == 0 {
        return Err(ClipboardError);
    }
    let result = {
        // The clipboard lock excludes writers between validation and Empty.
        // SAFETY: OpenClipboard succeeded and remains held for this scope.
        if sequence_is_current(expected, unsafe { GetClipboardSequenceNumber() }) {
            // SAFETY: Clipboard is open and owner is a valid window handle.
            (unsafe { EmptyClipboard() } != 0)
                .then_some(true)
                .ok_or(ClipboardError)
        } else {
            Ok(false)
        }
    };
    // SAFETY: This process successfully opened the clipboard above.
    let closed = unsafe { CloseClipboard() } != 0;
    if closed { result } else { Err(ClipboardError) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_embedded_nul_before_accessing_the_clipboard() {
        assert_eq!(
            set_text_and_get_sequence("before\0after"),
            Err(ClipboardError)
        );
    }
}
