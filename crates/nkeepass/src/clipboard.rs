//! Short-lived clipboard leases for explicitly copied secrets.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

#[cfg(any(windows, test))]
fn sequence_is_current(captured: u32, current: u32) -> bool {
    captured != 0 && captured == current
}

/// Clipboard operations deliberately expose no backend error details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(not(windows))]
pub(crate) struct ClipboardError;
#[cfg(windows)]
pub(crate) use windows_clipboard::ClipboardError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClipboardSetOutcome {
    Copied,
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "partial native write outcome exists only on Windows"
        )
    )]
    MayHaveCopied {
        can_clear: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClipboardCopyOutcome {
    Copied,
    MayHaveCopied,
    RejectedNul,
    TimedClearFailed,
}

/// Small injectable surface used by the lease and its tests.
pub(crate) trait ClipboardAdapter {
    fn set_text(&mut self, value: &str) -> Result<ClipboardSetOutcome, ClipboardError>;
    /// Clears only when the backend can atomically verify the app still owns the copy.
    fn clear_if_current(&mut self, value: &str) -> Result<bool, ClipboardError>;
    fn supports_timed_clear(&self) -> bool {
        false
    }
}

/// Native desktop clipboard adapter provided by arboard.
#[derive(Default)]
pub(crate) struct ArboardAdapter {
    #[cfg(not(windows))]
    clipboard: Option<arboard::Clipboard>,
    #[cfg(windows)]
    sequence: Option<u32>,
}

impl ArboardAdapter {
    #[cfg(not(windows))]
    fn clipboard(&mut self) -> Result<&mut arboard::Clipboard, ClipboardError> {
        if self.clipboard.is_none() {
            self.clipboard = Some(arboard::Clipboard::new().map_err(|_| ClipboardError)?);
        }
        self.clipboard.as_mut().ok_or(ClipboardError)
    }
}

impl ClipboardAdapter for ArboardAdapter {
    fn set_text(&mut self, value: &str) -> Result<ClipboardSetOutcome, ClipboardError> {
        if value.contains('\0') {
            return Err(ClipboardError);
        }
        #[cfg(windows)]
        {
            // Keep the clipboard locked across EmptyClipboard, SetClipboardData,
            // and sequence capture. arboard's Windows implementation clears
            // then sets in separate operations, so a sequence sampled around
            // it cannot prove ownership if another app writes in between.
            let result = windows_clipboard::set_text_and_get_sequence(value)?;
            self.sequence = result.sequence;
            if !result.closed {
                return Ok(ClipboardSetOutcome::MayHaveCopied {
                    can_clear: self.sequence.is_some(),
                });
            }
            if self.sequence.is_none() {
                return Ok(ClipboardSetOutcome::MayHaveCopied { can_clear: false });
            }
        }
        #[cfg(not(windows))]
        self.clipboard()?
            .set_text(value.to_owned())
            .map_err(|_| ClipboardError)?;
        Ok(ClipboardSetOutcome::Copied)
    }

    fn clear_if_current(&mut self, _value: &str) -> Result<bool, ClipboardError> {
        #[cfg(windows)]
        {
            let Some(sequence) = self.sequence.take() else {
                return Ok(false);
            };
            windows_clipboard::clear_if_sequence(sequence)
        }
        #[cfg(not(windows))]
        {
            // arboard exposes separate read and clear calls, so compare-then-clear
            // can erase clipboard data written by another application in between.
            Err(ClipboardError)
        }
    }

    fn supports_timed_clear(&self) -> bool {
        cfg!(windows)
    }
}

#[cfg(windows)]
use windows_clipboard;

struct Lease {
    value: Zeroizing<String>,
    expires: Instant,
}

/// Keeps the app's copied value only until the configured deadline.
pub(crate) struct ClipboardLease<A> {
    adapter: A,
    ttl: Duration,
    lease: Option<Lease>,
}

impl<A: ClipboardAdapter> ClipboardLease<A> {
    pub(crate) fn new(adapter: A, ttl: Duration) -> Self {
        Self {
            adapter,
            ttl,
            lease: None,
        }
    }

    /// Sets the clipboard and retains a zeroizing copy when ownership can be tracked.
    pub(crate) fn copy(
        &mut self,
        value: Zeroizing<String>,
    ) -> Result<ClipboardCopyOutcome, ClipboardError> {
        // CF_UNICODETEXT consumers stop at the first NUL. Refuse the string
        // before releasing an existing lease or touching any clipboard backend.
        if value.contains('\0') {
            return Ok(ClipboardCopyOutcome::RejectedNul);
        }
        let _ = self.release();
        match self.adapter.set_text(&value)? {
            ClipboardSetOutcome::Copied => {
                self.lease = Some(Lease {
                    value,
                    expires: Instant::now() + self.ttl,
                });
                Ok(ClipboardCopyOutcome::Copied)
            }
            ClipboardSetOutcome::MayHaveCopied { can_clear } => {
                if can_clear {
                    self.lease = Some(Lease {
                        value,
                        expires: Instant::now() + self.ttl,
                    });
                }
                Ok(ClipboardCopyOutcome::MayHaveCopied)
            }
        }
    }

    /// Expires the lease and clears only if the clipboard still matches it.
    /// Returns `None` while active, and whether the clipboard was cleared on expiry.
    pub(crate) fn tick(&mut self, now: Instant) -> Result<Option<bool>, ClipboardError> {
        if self
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.expires)
        {
            self.clear_if_unchanged().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Drops the in-process secret and attempts a conditional clear; it may remain.
    pub(crate) fn release(&mut self) -> Result<bool, ClipboardError> {
        if self.lease.is_some() {
            self.clear_if_unchanged()
        } else {
            Ok(false)
        }
    }

    pub(crate) fn supports_timed_clear(&self) -> bool {
        self.adapter.supports_timed_clear()
    }

    pub(crate) fn has_lease(&self) -> bool {
        self.lease.is_some()
    }

    fn clear_if_unchanged(&mut self) -> Result<bool, ClipboardError> {
        let Some(lease) = self.lease.take() else {
            return Ok(false);
        };
        self.adapter.clear_if_current(&lease.value)
    }
}

/// Copies a value and keeps the owner process alive when a desktop clipboard
/// needs it to serve paste requests. Windows leases are conditionally cleared
/// after `ttl`; `wait` is injectable so the lifetime contract can be tested
/// without sleeping.
pub(crate) fn copy_with_lifetime<A, W>(
    adapter: A,
    value: Zeroizing<String>,
    ttl: Duration,
    owner_must_live: bool,
    wait: W,
) -> Result<ClipboardCopyOutcome, ClipboardError>
where
    A: ClipboardAdapter,
    W: FnOnce(Duration),
{
    let mut lease = ClipboardLease::new(adapter, ttl);
    let outcome = lease.copy(value)?;
    if lease.has_lease() && (owner_must_live || lease.supports_timed_clear()) {
        wait(ttl);
        if lease.supports_timed_clear() {
            if lease.tick(Instant::now() + ttl).is_err() {
                return Ok(ClipboardCopyOutcome::TimedClearFailed);
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        ClipboardAdapter, ClipboardCopyOutcome, ClipboardError, ClipboardLease,
        ClipboardSetOutcome, copy_with_lifetime,
    };
    use zeroize::Zeroizing;

    #[test]
    fn captured_write_sequence_does_not_assume_one_increment() {
        // EmptyClipboard plus SetClipboardData may increment more than once.
        // Ownership is the sequence captured while the write lock is held,
        // not an arithmetic relationship to the sequence before the write.
        let captured_during_write = 42;
        assert!(super::sequence_is_current(captured_during_write, 42));
        assert!(!super::sequence_is_current(captured_during_write, 43));
        assert!(!super::sequence_is_current(0, 0));
    }

    #[derive(Default)]
    struct MockClipboard {
        text: Option<String>,
        fail_set: bool,
        fail_clear: bool,
        partial_set: bool,
        partial_can_clear: bool,
        timed_clear: bool,
        clear_calls: usize,
    }

    impl ClipboardAdapter for MockClipboard {
        fn set_text(&mut self, value: &str) -> Result<ClipboardSetOutcome, ClipboardError> {
            if self.fail_set {
                return Err(ClipboardError);
            }
            self.text = Some(value.to_owned());
            if self.partial_set {
                Ok(ClipboardSetOutcome::MayHaveCopied {
                    can_clear: self.partial_can_clear,
                })
            } else {
                Ok(ClipboardSetOutcome::Copied)
            }
        }

        fn clear_if_current(&mut self, expected: &str) -> Result<bool, ClipboardError> {
            self.clear_calls += 1;
            if self.fail_clear {
                return Err(ClipboardError);
            }
            if self.text.as_deref() != Some(expected) {
                return Ok(false);
            }
            self.text = None;
            Ok(true)
        }

        fn supports_timed_clear(&self) -> bool {
            self.timed_clear
        }
    }

    #[test]
    fn sets_text_and_holds_until_expiry() {
        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(2));
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        assert_eq!(lease.adapter.text.as_deref(), Some("secret"));
        assert!(lease.has_lease());
    }

    #[test]
    fn unchanged_clipboard_is_cleared_at_expiry() {
        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(1));
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        let later = Instant::now() + Duration::from_secs(2);
        assert_eq!(lease.tick(later).unwrap(), Some(true));
        assert_eq!(lease.adapter.text, None);
        assert!(!lease.has_lease());
    }

    #[test]
    fn newer_clipboard_content_is_not_cleared() {
        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(1));
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        lease.adapter.text = Some("user's newer copy".to_owned());
        assert_eq!(
            lease.tick(Instant::now() + Duration::from_secs(2)).unwrap(),
            Some(false)
        );
        assert_eq!(lease.adapter.text.as_deref(), Some("user's newer copy"));
        assert_eq!(lease.adapter.clear_calls, 1);
        assert!(!lease.has_lease());
    }

    #[test]
    fn backend_errors_are_returned_and_lease_is_cleaned_up() {
        let mut failing_set = MockClipboard {
            fail_set: true,
            ..MockClipboard::default()
        };
        assert_eq!(failing_set.set_text("secret"), Err(ClipboardError));

        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(1));
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        lease.adapter.fail_clear = true;
        assert_eq!(
            lease.tick(Instant::now() + Duration::from_secs(2)),
            Err(ClipboardError)
        );
        assert!(!lease.has_lease());
    }

    #[test]
    fn failed_set_does_not_create_a_lease() {
        let mut lease = ClipboardLease::new(
            MockClipboard {
                fail_set: true,
                ..MockClipboard::default()
            },
            Duration::from_secs(1),
        );
        assert_eq!(
            lease.copy(Zeroizing::new("secret".to_owned())),
            Err(ClipboardError)
        );
        assert!(!lease.has_lease());
    }

    #[test]
    fn nul_is_refused_before_releasing_or_modifying_clipboard() {
        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(1));
        lease.copy(Zeroizing::new("existing".to_owned())).unwrap();
        let previous_clear_calls = lease.adapter.clear_calls;
        assert_eq!(
            lease.copy(Zeroizing::new("before\0after".to_owned())),
            Ok(ClipboardCopyOutcome::RejectedNul)
        );
        assert_eq!(lease.adapter.text.as_deref(), Some("existing"));
        assert_eq!(lease.adapter.clear_calls, previous_clear_calls);
        assert!(lease.has_lease());
    }

    #[test]
    fn partial_success_warns_and_retains_only_a_conditionally_clearable_lease() {
        let mut lease = ClipboardLease::new(
            MockClipboard {
                partial_set: true,
                partial_can_clear: true,
                ..MockClipboard::default()
            },
            Duration::from_secs(1),
        );
        assert_eq!(
            lease.copy(Zeroizing::new("secret".to_owned())),
            Ok(ClipboardCopyOutcome::MayHaveCopied)
        );
        assert_eq!(lease.adapter.text.as_deref(), Some("secret"));
        assert!(lease.has_lease());
        assert_eq!(
            lease.tick(Instant::now() + Duration::from_secs(2)),
            Ok(Some(true))
        );
        assert_eq!(lease.adapter.text, None);

        let mut unowned = ClipboardLease::new(
            MockClipboard {
                partial_set: true,
                ..MockClipboard::default()
            },
            Duration::from_secs(1),
        );
        assert_eq!(
            unowned.copy(Zeroizing::new("secret".to_owned())),
            Ok(ClipboardCopyOutcome::MayHaveCopied)
        );
        assert!(!unowned.has_lease());
    }

    #[test]
    fn clear_error_still_zeroizes_the_expired_lease() {
        let mut lease = ClipboardLease::new(
            MockClipboard {
                fail_clear: true,
                ..MockClipboard::default()
            },
            Duration::from_secs(1),
        );
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        assert_eq!(
            lease.tick(Instant::now() + Duration::from_secs(2)),
            Err(ClipboardError)
        );
        assert!(!lease.has_lease());
    }

    #[test]
    #[cfg(not(windows))]
    fn arboard_adapter_fails_safe_without_atomic_ownership_clear() {
        let mut adapter = super::ArboardAdapter::default();
        assert_eq!(adapter.clear_if_current("secret"), Err(ClipboardError));
    }

    #[test]
    fn active_lease_is_not_reported_as_expired() {
        let mut lease = ClipboardLease::new(MockClipboard::default(), Duration::from_secs(10));
        lease.copy(Zeroizing::new("secret".to_owned())).unwrap();
        assert_eq!(lease.tick(Instant::now()).unwrap(), None);
    }

    #[test]
    fn copy_lifetime_is_injected_and_bounded_for_owner_backed_clipboards() {
        let mut waited = None;
        let outcome = copy_with_lifetime(
            MockClipboard::default(),
            Zeroizing::new("secret".to_owned()),
            Duration::from_secs(30),
            true,
            |duration| waited = Some(duration),
        )
        .unwrap();
        assert_eq!(outcome, ClipboardCopyOutcome::Copied);
        assert_eq!(waited, Some(Duration::from_secs(30)));
    }

    #[test]
    fn unavailable_nul_and_partial_copies_have_deterministic_outcomes() {
        let mut waited = false;
        assert_eq!(
            copy_with_lifetime(
                MockClipboard {
                    fail_set: true,
                    ..MockClipboard::default()
                },
                Zeroizing::new("secret".to_owned()),
                Duration::from_secs(30),
                true,
                |_| waited = true,
            ),
            Err(ClipboardError)
        );
        assert!(!waited);

        assert_eq!(
            copy_with_lifetime(
                MockClipboard::default(),
                Zeroizing::new("bad\0value".to_owned()),
                Duration::from_secs(30),
                true,
                |_| waited = true,
            ),
            Ok(ClipboardCopyOutcome::RejectedNul)
        );
        assert!(!waited);

        assert_eq!(
            copy_with_lifetime(
                MockClipboard {
                    partial_set: true,
                    partial_can_clear: true,
                    timed_clear: true,
                    ..MockClipboard::default()
                },
                Zeroizing::new("secret".to_owned()),
                Duration::from_secs(30),
                true,
                |duration| {
                    assert_eq!(duration, Duration::from_secs(30));
                    waited = true;
                },
            ),
            Ok(ClipboardCopyOutcome::MayHaveCopied)
        );
        assert!(waited);
    }

    #[test]
    fn timed_clear_failure_reports_that_the_copy_may_remain() {
        let outcome = copy_with_lifetime(
            MockClipboard {
                timed_clear: true,
                fail_clear: true,
                ..MockClipboard::default()
            },
            Zeroizing::new("secret".to_owned()),
            Duration::from_secs(30),
            false,
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome, ClipboardCopyOutcome::TimedClearFailed);
    }
}
