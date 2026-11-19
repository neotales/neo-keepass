//! Runs in a disposable child console, never the developer's terminal.
#![cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Console::{
    AllocConsole, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, FreeConsole,
    GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD, STD_INPUT_HANDLE,
    SetConsoleMode, SetStdHandle, WriteConsoleInputW,
};

#[test]
fn console_worker() {
    let Ok(scenario) = std::env::var("TERMINAL_PASSWORD_WINDOWS_TEST") else {
        return;
    };
    // SAFETY: this isolated subprocess owns the newly allocated console. The
    // file outlives every handle use; all FFI pointers refer to local values.
    unsafe {
        FreeConsole();
        assert_ne!(AllocConsole(), 0);
        let input = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .unwrap();
        let handle = input.as_raw_handle();
        assert_ne!(SetStdHandle(STD_INPUT_HANDLE, handle), 0);
        let mut original = 0;
        assert_ne!(GetConsoleMode(handle, &mut original), 0);
        // Deliberately nondefault saved mode: processed input off but line and
        // echo on. Restoration must not guess the usual cooked-mode bits.
        original = (original | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) & !ENABLE_PROCESSED_INPUT;
        assert_ne!(SetConsoleMode(handle, original), 0);
        let units: &[u16] = match scenario.as_str() {
            "enter" => &[83, 101, 99, 114, 101, 116, 13],
            "cancel" => &[3],
            "escape" => &[27],
            "timeout" => &[],
            _ => panic!("unknown scenario"),
        };
        for unit in units {
            let mut record: INPUT_RECORD = std::mem::zeroed();
            record.EventType = KEY_EVENT as u16;
            let mut key: KEY_EVENT_RECORD = std::mem::zeroed();
            key.bKeyDown = 1;
            key.wRepeatCount = 1;
            key.uChar.UnicodeChar = *unit;
            record.Event.KeyEvent = key;
            let mut written = 0;
            assert_ne!(WriteConsoleInputW(handle, &record, 1, &mut written), 0);
            assert_eq!(written, 1);
        }
        let result = terminal_password::read(Duration::from_millis(100));
        let mut restored = 0;
        assert_ne!(
            GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut restored),
            0
        );
        assert_eq!(restored, original);
        match scenario.as_str() {
            "enter" => assert_eq!(&*result.unwrap(), "Secret"),
            "cancel" | "escape" => {
                assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted)
            }
            "timeout" => assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut),
            _ => unreachable!(),
        }
        FreeConsole();
    }
}

#[test]
fn isolated_console_submission_cancellation_timeout_restore_exact_mode() {
    for scenario in ["enter", "cancel", "escape", "timeout"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "console_worker", "--nocapture"])
            .env("TERMINAL_PASSWORD_WINDOWS_TEST", scenario)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "console scenario {scenario} failed: {status}"
                );
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("console scenario {scenario} stalled");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
