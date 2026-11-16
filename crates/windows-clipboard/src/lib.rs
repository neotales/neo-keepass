//! Narrow, audited Win32 clipboard ownership boundary.
//!
//! These operations pass `GetConsoleWindow()` as the clipboard owner and fail
//! closed only when it returns null. A non-null result does not establish that
//! the process is running in a conventional console rather than a pseudoconsole.

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
/// `None` if Windows did not provide a usable sequence number. A sequence is
/// still useful for conditional cleanup when `closed` is false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetResult {
    /// Sequence number identifying the installed clipboard contents, if available.
    pub sequence: Option<u32>,
    /// Whether `CloseClipboard` succeeded after the write.
    pub closed: bool,
}

/// Writes UTF-16 text and captures the clipboard sequence while locked.
///
/// Embedded NULs are rejected. Returns an error if `GetConsoleWindow()` is
/// null or a native clipboard operation fails. Note that Windows may already
/// have emptied the clipboard before `SetClipboardData` fails; in that case
/// this returns an error after the previous clipboard contents have been lost.
///
/// A successful result may report `closed == false` after the text was written.
/// If `sequence` is `Some`, the caller can still use it for conditional cleanup;
/// the application's lease retains that sequence even when close failed.
///
/// # Examples
///
/// ```no_run
/// # #[cfg(windows)] {
/// let result = windows_clipboard::set_text_and_get_sequence("secret")?;
/// if let Some(sequence) = result.sequence {
///     // The sequence remains usable for conditional cleanup even if `closed`
///     // is false; a failed close is reported as partial success, not rollback.
///     let _cleared = windows_clipboard::clear_if_sequence(sequence)?;
/// }
/// let _close_succeeded = result.closed;
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

    // Pass GetConsoleWindow's result as the owner required by EmptyClipboard.
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
/// contents are preserved. Returns an error if `GetConsoleWindow()` is null
/// or a native clipboard operation fails, and returns `Ok(false)` when the
/// sequence differs.
pub fn clear_if_sequence(expected: u32) -> Result<bool, ClipboardError> {
    // Use the HWND reported by GetConsoleWindow as clipboard owner.
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
