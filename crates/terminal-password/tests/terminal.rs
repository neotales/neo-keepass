#![cfg(unix)]
use nix::pty::openpty;
use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn worker() {
    let Ok(scenario) = std::env::var("TERMINAL_PASSWORD_TEST") else {
        return;
    };
    let stdin = std::io::stdin();
    let original = tcgetattr(&stdin).unwrap();
    let mut prior_actions = Vec::new();
    if scenario == "prior" {
        use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGUSR1);
        let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::SA_RESTART, mask);
        for signal in [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ] {
            // SAFETY: isolated child test; SIG_IGN contains no callback.
            prior_actions.push((signal, unsafe { sigaction(signal, &ignored).unwrap() }));
        }
    }
    // Signal readiness only after the input mode was set: the parent observes
    // the slave's flags before sending anything, so no typed secret can echo.
    eprintln!("ready");
    let result = terminal_password::read(Duration::from_millis(300));
    assert_eq!(
        tcgetattr(&stdin).unwrap(),
        original,
        "restore every termios bit"
    );
    match scenario.as_str() {
        "enter" | "post-enter" => assert_eq!(&*result.unwrap(), "Sëcret"),
        "cancel" | "escape" | "eof" | "signal" | "post-cancel" => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted)
        }
        "timeout" | "post-timeout" | "prior" => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut)
        }
        _ => panic!("unknown scenario"),
    }
    for (signal, original) in prior_actions {
        use nix::sys::signal::{SaFlags, SigHandler, Signal, sigaction};
        // SAFETY: restore the saved action in this isolated child.
        let restored = unsafe { sigaction(signal, &original).unwrap() };
        assert_eq!(restored.handler(), SigHandler::SigIgn);
        assert!(restored.flags().contains(SaFlags::SA_RESTART));
        assert!(restored.mask().contains(Signal::SIGUSR1));
    }
    if scenario.starts_with("post-") {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
        panic!("SIGTERM was swallowed after read returned");
    }
}

#[test]
fn submission_cancellation_and_timeout_restore_exact_modes_without_echo() {
    for (scenario, input) in [
        ("enter", "SëcreX\u{7f}t\n".as_bytes()),
        ("cancel", b"\x03".as_slice()),
        ("escape", b"\x1b".as_slice()),
        ("eof", b"\x04".as_slice()),
        ("signal", b"".as_slice()),
        ("timeout", b"".as_slice()),
        ("post-enter", "SëcreX\u{7f}t\n".as_bytes()),
        ("post-cancel", b"\x03".as_slice()),
        ("post-timeout", b"".as_slice()),
        ("prior", b"".as_slice()),
    ] {
        let pty = openpty(None, None).unwrap();
        let mut mode = tcgetattr(&pty.slave).unwrap();
        mode.local_flags
            .insert(LocalFlags::ECHO | LocalFlags::ICANON);
        tcsetattr(&pty.slave, SetArg::TCSANOW, &mode).unwrap();
        let mut master = std::fs::File::from(pty.master);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "worker", "--nocapture"])
            .env("TERMINAL_PASSWORD_TEST", scenario)
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
            .stderr(Stdio::from(pty.slave.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while tcgetattr(&pty.slave)
            .unwrap()
            .local_flags
            .contains(LocalFlags::ECHO)
        {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker did not enter no-echo mode");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        master.write_all(input).unwrap();
        if scenario == "signal" {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
                nix::sys::signal::Signal::SIGTERM,
            )
            .unwrap();
        }
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker leaked or stalled");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(tcgetattr(&pty.slave).unwrap(), mode);
        drop(pty.slave);
        let mut output = Vec::new();
        // Linux PTY masters return EIO when the last slave closes.
        let _ = master.read_to_end(&mut output);
        assert!(
            if scenario.starts_with("post-") {
                status.signal() == Some(15)
            } else {
                status.success()
            },
            "worker {scenario}: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(
            !output.windows(6).any(|part| part == b"S\xc3\xabcre"),
            "secret echoed"
        );
    }
}
