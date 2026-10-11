//! Pomocnicze funkcje: uruchamianie procesow (PowerShell) z limitem czasu.
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Tworzy Command bez migajacego okna konsoli (Windows).
pub fn new_command(program: &str) -> Command {
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

/// Uruchamia proces, przechwytuje stdout+stderr, egzekwuje limit czasu.
pub fn run_capture(mut cmd: Command, timeout: Duration) -> Result<String, String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;

    let mut out = child.stdout.take().ok_or("brak stdout")?;
    let mut err = child.stderr.take().ok_or("brak stderr")?;

    let out_h = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let err_h = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("timeout".into());
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    }

    let o = out_h.join().unwrap_or_default();
    let e = err_h.join().unwrap_or_default();
    let so = String::from_utf8_lossy(&o).to_string();
    let se = String::from_utf8_lossy(&e).to_string();
    if so.trim().is_empty() && !se.trim().is_empty() {
        Ok(se)
    } else {
        Ok(so)
    }
}

/// Wykonuje skrypt PowerShell i zwraca stdout.
pub fn ps(script: &str, timeout_secs: u64) -> Result<String, String> {
    let full = format!(
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;{}",
        script
    );
    let mut c = new_command("powershell");
    c.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &full,
    ]);
    run_capture(c, Duration::from_secs(timeout_secs))
}

/// Uruchamia polecenie w tle (bez czekania na wynik). Przydatne dla VPN.
pub fn spawn_detached(mut cmd: Command) -> Result<(), String> {
    cmd.stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null());
    cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    Ok(())
}

/// Pierwsza niepusta linia tekstu.
pub fn first_line(s: &str) -> String {
    s.lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}
