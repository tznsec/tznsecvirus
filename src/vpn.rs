//! Wykrywanie, uruchamianie i weryfikacja VPN (WireGuard / OpenVPN / Tailscale).
use crate::util::{new_command, ps, run_capture, spawn_detached};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Serialize, Clone)]
pub struct Adapter {
    pub name: String,
    pub desc: String,
    pub status: String,
}

#[derive(Serialize, Clone)]
pub struct Profile {
    pub kind: String,
    pub name: String,
    pub path: String,
}

#[derive(Serialize, Clone)]
pub struct VpnState {
    pub adapters: Vec<Adapter>,
    pub profiles: Vec<Profile>,
    pub active: bool,
    pub active_name: String,
    pub admin: bool,
    pub note: String,
}

fn program_files() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()))
}

pub fn is_admin() -> bool {
    ps(
        r#"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"#,
        20,
    )
    .map(|s| s.trim().eq_ignore_ascii_case("true"))
    .unwrap_or(false)
}

pub fn detect() -> VpnState {
    let mut adapters: Vec<Adapter> = Vec::new();
    let script = r#"Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|WireGuard|Wintun|TAP|OpenVPN|Tailscale|ZeroTier|SoftEther|AnyConnect|FortiClient|Proton|NordLynx|Mullvad|IKEv2|L2TP|PPTP|SSTP' -or $_.Name -match 'VPN|WireGuard|Tailscale|ZeroTier|Mullvad|Proton|Nord' } | ForEach-Object { $_.Name + '|' + $_.InterfaceDescription + '|' + $_.Status }"#;
    if let Ok(out) = ps(script, 35) {
        for l in out.lines() {
            let l = l.trim();
            if l.is_empty() {
                continue;
            }
            let p: Vec<&str> = l.split('|').collect();
            if p.len() >= 3 {
                adapters.push(Adapter {
                    name: p[0].trim().to_string(),
                    desc: p[1].trim().to_string(),
                    status: p[2].trim().to_string(),
                });
            }
        }
    }

    let active = adapters.iter().any(|a| a.status.eq_ignore_ascii_case("up"));
    let active_name = adapters
        .iter()
        .find(|a| a.status.eq_ignore_ascii_case("up"))
        .map(|a| a.name.clone())
        .unwrap_or_default();

    let profiles = find_profiles();

    let note = if profiles.is_empty() && adapters.is_empty() {
        "Nie wykryto zainstalowanego VPN ani profili. Dodaj plik .conf (WireGuard) lub .ovpn (OpenVPN), aby moc sie polaczyc.".to_string()
    } else if profiles.is_empty() {
        "Wykryto adaptery VPN, ale nie znaleziono profili do polaczenia.".to_string()
    } else {
        format!("Wykryto {} profili VPN gotowych do uzycia.", profiles.len())
    };

    VpnState {
        adapters,
        profiles,
        active,
        active_name,
        admin: is_admin(),
        note,
    }
}

fn find_profiles() -> Vec<Profile> {
    let mut out: Vec<Profile> = Vec::new();
    let pf = program_files();
    let pfx86 = PathBuf::from(
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".into()),
    );

    scan_dir(&mut out, "wireguard", pf.join("WireGuard").join("Data").join("Configurations"), ".conf.dpapi");
    scan_dir(&mut out, "wireguard", pf.join("WireGuard").join("Data").join("Configurations"), ".conf");
    scan_dir(&mut out, "openvpn", pf.join("OpenVPN").join("config"), ".ovpn");
    scan_dir(&mut out, "openvpn", pfx86.join("OpenVPN").join("config"), ".ovpn");
    if let Some(home) = dirs::home_dir() {
        scan_dir(&mut out, "openvpn", home.join("OpenVPN").join("config"), ".ovpn");
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

fn scan_dir(out: &mut Vec<Profile>, kind: &str, dir: PathBuf, suffix: &str) {
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.to_lowercase().ends_with(suffix) {
            out.push(Profile {
                kind: kind.to_string(),
                name: name.trim_end_matches(suffix).to_string(),
                path: p.display().to_string(),
            });
        }
    }
}

/// Zwraca liste wykrytych narzedzi VPN (sciezki do .exe).
pub fn tools() -> Vec<String> {
    let pf = program_files();
    let mut v = Vec::new();
    for p in [
        pf.join("WireGuard").join("wireguard.exe"),
        pf.join("OpenVPN").join("bin").join("openvpn.exe"),
        pf.join("OpenVPN").join("bin").join("openvpn-gui.exe"),
        pf.join("Tailscale").join("tailscale.exe"),
    ] {
        if p.exists() {
            v.push(p.display().to_string());
        }
    }
    v
}

pub fn launch(kind: &str, path: &str, name: &str) -> Result<String, String> {
    let pf = program_files();
    match kind {
        "wireguard" => {
            let exe = pf.join("WireGuard").join("wireguard.exe");
            if !exe.exists() {
                return Err("Nie znaleziono wireguard.exe".into());
            }
            let mut c = new_command(&exe.display().to_string());
            c.args(["/installtunnelservice", path]);
            let out = run_capture(c, Duration::from_secs(45))?;
            Ok(format!("WireGuard: uruchomiono tunel '{name}'. {}", out.trim()))
        }
        "openvpn" => {
            let gui = pf.join("OpenVPN").join("bin").join("openvpn-gui.exe");
            let exe = pf.join("OpenVPN").join("bin").join("openvpn.exe");
            if gui.exists() {
                let mut c = new_command(&gui.display().to_string());
                c.args(["--connect", &format!("{name}.ovpn")]);
                spawn_detached(c)?;
                Ok(format!("OpenVPN GUI: zainicjowano polaczenie '{name}'."))
            } else if exe.exists() {
                let mut c = new_command(&exe.display().to_string());
                c.args(["--config", path]);
                spawn_detached(c)?;
                Ok(format!("OpenVPN: uruchomiono '{name}' w tle."))
            } else {
                Err("Nie znaleziono OpenVPN".into())
            }
        }
        "tailscale" => {
            let exe = pf.join("Tailscale").join("tailscale.exe");
            if !exe.exists() {
                return Err("Nie znaleziono tailscale.exe".into());
            }
            let mut c = new_command(&exe.display().to_string());
            c.arg("up");
            let out = run_capture(c, Duration::from_secs(45))?;
            Ok(format!("Tailscale: {}", out.trim()))
        }
        _ => Err(format!("Nieznany typ VPN: {kind}")),
    }
}

pub fn stop(kind: &str, name: &str) -> Result<String, String> {
    let pf = program_files();
    match kind {
        "wireguard" => {
            let exe = pf.join("WireGuard").join("wireguard.exe");
            if !exe.exists() {
                return Err("Nie znaleziono wireguard.exe".into());
            }
            let mut c = new_command(&exe.display().to_string());
            c.args(["/uninstalltunnelservice", name]);
            let out = run_capture(c, Duration::from_secs(45))?;
            Ok(format!("WireGuard: zatrzymano tunel '{name}'. {}", out.trim()))
        }
        "tailscale" => {
            let exe = pf.join("Tailscale").join("tailscale.exe");
            if !exe.exists() {
                return Err("Nie znaleziono tailscale.exe".into());
            }
            let mut c = new_command(&exe.display().to_string());
            c.arg("down");
            let out = run_capture(c, Duration::from_secs(45))?;
            Ok(format!("Tailscale: {}", out.trim()))
        }
        _ => Err("Zatrzymanie nieobslugiwane dla tego typu VPN (uzyj GUI).".into()),
    }
}

/// Publiczne IP + kraj/dostawca (do weryfikacji, czy VPN faktycznie dziala).
pub fn ip_geo() -> Option<(String, String, String)> {
    let agent = agent();
    let mut r = agent
        .get("http://ip-api.com/json/?fields=status,query,country,isp")
        .call()
        .ok()?;
    let v: serde_json::Value = r.body_mut().read_json().ok()?;
    let ip = v.get("query").and_then(|x| x.as_str())?.to_string();
    let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let isp = v.get("isp").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some((ip, country, isp))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into()
}
