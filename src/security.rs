//! Kontrole bezpieczenstwa systemu Windows wykonywane przez PowerShell.
use crate::util::{first_line, ps};
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Check {
    pub id: String,
    pub name: String,
    pub status: String, // ok | warn | fail | info
    pub detail: String,
    pub weight: u32,
}

fn ck(id: &str, name: &str, status: &str, detail: impl Into<String>, weight: u32) -> Check {
    Check {
        id: id.into(),
        name: name.into(),
        status: status.into(),
        detail: detail.into(),
        weight,
    }
}

fn add(out: &mut Vec<Check>, emit: &dyn Fn(Check), c: Check) {
    emit(c.clone());
    out.push(c);
}

pub fn run_all(emit: &dyn Fn(Check)) -> Vec<Check> {
    let mut out: Vec<Check> = Vec::new();
    add(&mut out, emit, check_admin());
    add(&mut out, emit, check_defender());
    add(&mut out, emit, check_threats());
    add(&mut out, emit, check_firewall());
    add(&mut out, emit, check_uac());
    add(&mut out, emit, check_secureboot());
    add(&mut out, emit, check_bitlocker());
    add(&mut out, emit, check_os_update());
    add(&mut out, emit, check_rdp());
    add(&mut out, emit, check_smb1());
    add(&mut out, emit, check_listening());
    add(&mut out, emit, check_startup());
    add(&mut out, emit, check_tasks());
    add(&mut out, emit, check_hosts());
    out
}

fn check_admin() -> Check {
    let out = ps(
        r#"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"#,
        25,
    )
    .unwrap_or_default();
    if out.trim().eq_ignore_ascii_case("true") {
        ck("admin", "Uprawnienia administratora", "ok",
           "Program dziala z pelnymi uprawnieniami - wszystkie kontrole sa dostepne.", 5)
    } else {
        ck("admin", "Uprawnienia administratora", "warn",
           "Brak uprawnien administratora. VPN oraz czesc kontroli moga byc ograniczone - uruchom program jako administrator.", 5)
    }
}

fn check_defender() -> Check {
    let script = r#"$s=Get-MpComputerStatus -ErrorAction SilentlyContinue; if($s){ @($s.RealTimeProtectionEnabled,$s.AntivirusEnabled,$s.AntispywareEnabled,$s.AMServiceEnabled,$s.IsTamperProtected,$s.AntivirusSignatureAge) -join ',' } else { 'NA' }"#;
    let out = match ps(script, 60) {
        Ok(o) => o,
        Err(e) => return ck("defender", "Microsoft Defender", "info", format!("Nie udalo sie sprawdzic: {e}"), 25),
    };
    let out = out.trim();
    if out.is_empty() || out == "NA" {
        return ck("defender", "Microsoft Defender", "warn",
                  "Usluga Defender niedostepna (wylaczona lub zastepuje ja inny antywirus).", 25);
    }
    let parts: Vec<String> = out.split(',').map(|s| s.trim().to_string()).collect();
    let b = |i: usize| parts.get(i).map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(false);
    let (rtp, av, asp, am, tamper) = (b(0), b(1), b(2), b(3), b(4));
    let sigage: i64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(-1);

    let mut problems: Vec<String> = Vec::new();
    if !rtp { problems.push("ochrona w czasie rzeczywistym wylaczona".into()); }
    if !av { problems.push("antywirus wylaczony".into()); }
    if !asp { problems.push("antyspyware wylaczone".into()); }
    if !am { problems.push("usluga AM wylaczona".into()); }
    if !tamper { problems.push("brak ochrony antysabotazowej (tamper protection)".into()); }
    if sigage > 7 { problems.push(format!("sygnatury maja {sigage} dni")); }

    if problems.is_empty() {
        ck("defender", "Microsoft Defender", "ok",
           format!("Aktywna ochrona: real-time, antywirus, antyspyware. Sygnatury: {sigage} dni. Tamper protection: tak."), 25)
    } else {
        ck("defender", "Microsoft Defender", "fail",
           format!("Wykryto problemy: {}.", problems.join(", ")), 25)
    }
}

fn check_threats() -> Check {
    let script = r#"$t=@(Get-MpThreatDetection -ErrorAction SilentlyContinue); if($t.Count -gt 0){ 'count=' + $t.Count; $t | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5 | ForEach-Object { ($_.InitialDetectionTime.ToString('yyyy-MM-dd')) + ' ThreatID=' + $_.ThreatID } } else { 'count=0' }"#;
    let out = ps(script, 60).unwrap_or_default();
    let mut count = 0i64;
    let mut lines: Vec<String> = Vec::new();
    for l in out.lines() {
        let l = l.trim();
        if let Some(c) = l.strip_prefix("count=") {
            count = c.trim().parse().unwrap_or(0);
        } else if !l.is_empty() {
            lines.push(l.to_string());
        }
    }
    if count > 0 {
        ck("threats", "Historia wykrytych zagrozen", "fail",
           format!("Defender zarejestrowal {count} wykryc. Ostatnie: {}", lines.join(" | ")), 20)
    } else {
        ck("threats", "Historia wykrytych zagrozen", "ok",
           "Brak zarejestrowanych wykryc zagrozen.", 20)
    }
}

fn check_firewall() -> Check {
    let script = r#"Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '=' + $_.Enabled }"#;
    let out = ps(script, 35).unwrap_or_default();
    let mut off: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for l in out.lines() {
        let l = l.trim();
        if let Some((name, val)) = l.split_once('=') {
            seen += 1;
            if val.trim().eq_ignore_ascii_case("false") {
                off.push(name.trim().to_string());
            }
        }
    }
    if seen == 0 {
        ck("firewall", "Zapora sieciowa (firewall)", "info", "Nie udalo sie odczytac stanu zapory.", 20)
    } else if off.is_empty() {
        ck("firewall", "Zapora sieciowa (firewall)", "ok",
           "Wszystkie profile zapory (Domain/Private/Public) sa wlaczone.", 20)
    } else {
        ck("firewall", "Zapora sieciowa (firewall)", "fail",
           format!("Wylaczone profile zapory: {}.", off.join(", ")), 20)
    }
}

fn check_uac() -> Check {
    let script = r#"$v=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA; if($null -eq $v){'NA'}else{$v}"#;
    let out = ps(script, 25).unwrap_or_default();
    match out.trim() {
        "1" => ck("uac", "Kontrola konta uzytkownika (UAC)", "ok", "UAC jest wlaczone.", 15),
        "0" => ck("uac", "Kontrola konta uzytkownika (UAC)", "fail",
                  "UAC jest wylaczone - to powazne obnizenie bezpieczenstwa.", 15),
        _ => ck("uac", "Kontrola konta uzytkownika (UAC)", "info", "Nie udalo sie odczytac stanu UAC.", 15),
    }
}

fn check_secureboot() -> Check {
    let script = r#"try{ if(Confirm-SecureBootUEFI -ErrorAction Stop){'ON'}else{'OFF'} }catch{'NA'}"#;
    let out = ps(script, 25).unwrap_or_default();
    match out.trim() {
        "ON" => ck("secureboot", "Secure Boot", "ok", "Secure Boot jest wlaczone.", 15),
        "OFF" => ck("secureboot", "Secure Boot", "warn", "Secure Boot jest wylaczone.", 15),
        _ => ck("secureboot", "Secure Boot", "info",
                "Nie mozna odczytac Secure Boot (BIOS/CSM lub brak uprawnien).", 15),
    }
}

fn check_bitlocker() -> Check {
    let script = r#"try{ (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus }catch{'NA'}"#;
    let out = ps(script, 35).unwrap_or_default();
    match out.trim() {
        "On" => ck("bitlocker", "Szyfrowanie dysku (BitLocker)", "ok",
                   "Dysk systemowy jest zaszyfrowany (BitLocker).", 15),
        "Off" => ck("bitlocker", "Szyfrowanie dysku (BitLocker)", "warn",
                    "Dysk systemowy nie jest zaszyfrowany.", 15),
        _ => ck("bitlocker", "Szyfrowanie dysku (BitLocker)", "info",
                "BitLocker niedostepny (Windows Home lub brak modulu TPM).", 15),
    }
}

fn check_os_update() -> Check {
    let script = r#"$os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; $hf=Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1; $age=if($hf -and $hf.InstalledOn){[int]((Get-Date)-$hf.InstalledOn).TotalDays}else{-1}; (($os.Caption) + '|' + ($os.BuildNumber) + '|' + $age)"#;
    let out = ps(script, 70).unwrap_or_default();
    let line = first_line(&out);
    let parts: Vec<&str> = line.split('|').collect();
    let caption = parts.first().copied().unwrap_or("Windows").trim().to_string();
    let build = parts.get(1).copied().unwrap_or("").trim().to_string();
    let age: i64 = parts.get(2).and_then(|s| s.trim().parse().ok()).unwrap_or(-1);
    let base = format!("{caption} (build {build})");
    if age < 0 {
        ck("osupdate", "Aktualizacje systemu", "info",
           format!("{base}. Nie udalo sie ustalic daty ostatniej aktualizacji."), 15)
    } else if age <= 35 {
        ck("osupdate", "Aktualizacje systemu", "ok",
           format!("{base}. Ostatnia aktualizacja: {age} dni temu."), 15)
    } else if age <= 90 {
        ck("osupdate", "Aktualizacje systemu", "warn",
           format!("{base}. Ostatnia aktualizacja: {age} dni temu - zalecana aktualizacja."), 15)
    } else {
        ck("osupdate", "Aktualizacje systemu", "fail",
           format!("{base}. Ostatnia aktualizacja: {age} dni temu - system moze byc nieaktualny."), 15)
    }
}

fn check_rdp() -> Check {
    let script = r#"$v=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; if($null -eq $v){'NA'}else{$v}"#;
    let out = ps(script, 25).unwrap_or_default();
    match out.trim() {
        "1" => ck("rdp", "Pulpit zdalny (RDP)", "ok", "Polaczenia RDP sa zablokowane.", 10),
        "0" => ck("rdp", "Pulpit zdalny (RDP)", "warn",
                  "RDP jest wlaczony (port 3389). Upewnij sie, ze nie jest wystawiony do internetu.", 10),
        _ => ck("rdp", "Pulpit zdalny (RDP)", "info", "Nie udalo sie odczytac stanu RDP.", 10),
    }
}

fn check_smb1() -> Check {
    let script = r#"$v=(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol; if($null -eq $v){'NA'}else{$v}"#;
    let out = ps(script, 35).unwrap_or_default();
    match out.trim() {
        "False" => ck("smb1", "Przestarzaly protokol SMBv1", "ok", "SMBv1 jest wylaczony.", 10),
        "True" => ck("smb1", "Przestarzaly protokol SMBv1", "fail",
                     "SMBv1 jest wlaczony - podatny na exploity (np. EternalBlue). Nalezy go wylaczyc.", 10),
        _ => ck("smb1", "Przestarzaly protokol SMBv1", "info", "Nie udalo sie odczytac stanu SMBv1.", 10),
    }
}

fn check_listening() -> Check {
    let script = r#"$c=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue); 'count=' + $c.Count; $r=@($c | Where-Object { $_.LocalPort -in 21,23,135,139,445,3389,5900,1433,3306 }); if($r.Count -gt 0){ 'risky=' + (($r | ForEach-Object { $_.LocalPort } | Sort-Object -Unique) -join ',') } else { 'risky=' }"#;
    let out = ps(script, 45).unwrap_or_default();
    let mut count = 0i64;
    let mut risky: Vec<String> = Vec::new();
    for l in out.lines() {
        let l = l.trim();
        if let Some(c) = l.strip_prefix("count=") {
            count = c.trim().parse().unwrap_or(0);
        } else if let Some(r) = l.strip_prefix("risky=") {
            if !r.trim().is_empty() {
                risky = r.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
    }
    if !risky.is_empty() {
        ck("ports", "Nasluchujace porty", "warn",
           format!("{count} portow nasluchuje. Wrazliwe porty otwarte: {}.", risky.join(", ")), 12)
    } else {
        ck("ports", "Nasluchujace porty", "ok",
           format!("{count} portow nasluchuje. Brak typowo niebezpiecznych portow."), 12)
    }
}

fn check_startup() -> Check {
    let script = r#"$r=@(); foreach($p in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'){ if(Test-Path $p){ $k=Get-Item $p; foreach($n in $k.GetValueNames()){ $r += ($n + ' :: ' + [string]$k.GetValue($n)) } } }; if($r.Count -gt 0){ $r } else { '' }"#;
    let out = ps(script, 40).unwrap_or_default();
    let entries: Vec<String> = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let sus: Vec<String> = entries
        .iter()
        .filter(|l| {
            let l = l.to_lowercase();
            l.contains("\\temp\\")
                || l.contains("\\users\\public")
                || l.contains("windows\\temp")
                || l.contains("powershell")
                || l.contains("wscript")
                || l.contains("mshta")
                || l.contains("rundll32")
                || l.contains("regsvr32")
                || l.contains("cmd /c")
                || l.contains("cmd.exe /c")
                || l.contains("http://")
                || l.contains("https://")
        })
        .cloned()
        .collect();
    if !sus.is_empty() {
        let list = sus.iter().take(5).cloned().collect::<Vec<_>>().join(" | ");
        ck("startup", "Autostart systemu", "warn",
           format!("{} wpisow w Autostart; {} podejrzanych: {}", entries.len(), sus.len(), list), 15)
    } else if entries.is_empty() {
        ck("startup", "Autostart systemu", "info", "Brak wpisow w kluczach Run.", 15)
    } else {
        ck("startup", "Autostart systemu", "ok",
           format!("{} wpisow w Autostart - brak oczywiscie podejrzanych.", entries.len()), 15)
    }
}

fn check_tasks() -> Check {
    let script = r#"$t=@(Get-ScheduledTask -ErrorAction SilentlyContinue); 'total=' + $t.Count; $s=@($t | Where-Object { $_.State -ne 'Disabled' -and ($_.Actions | Where-Object { $_.Execute -match 'wscript|mshta|cscript|powershell|cmd\.exe' -or $_.Execute -match '\\Temp\\|\\Users\\Public\\' }) }); 'sus=' + $s.Count; if($s.Count -gt 0){ $s | Select-Object -First 8 | ForEach-Object { $_.TaskName + ' -> ' + (($_.Actions | ForEach-Object { $_.Execute }) -join ';') } }"#;
    let out = ps(script, 50).unwrap_or_default();
    let mut total = 0i64;
    let mut sus = 0i64;
    let mut examples: Vec<String> = Vec::new();
    for l in out.lines() {
        let l = l.trim();
        if let Some(c) = l.strip_prefix("total=") {
            total = c.trim().parse().unwrap_or(0);
        } else if let Some(c) = l.strip_prefix("sus=") {
            sus = c.trim().parse().unwrap_or(0);
        } else if !l.is_empty() {
            examples.push(l.to_string());
        }
    }
    if sus > 0 {
        ck("tasks", "Zaplanowane zadania", "warn",
           format!("{sus} z {total} zadan uruchamia podejrzane komendy. Przyklady: {}",
                   examples.iter().take(4).cloned().collect::<Vec<_>>().join(" | ")), 12)
    } else {
        ck("tasks", "Zaplanowane zadania", "ok",
           format!("{total} zadan; brak oczywiscie podejrzanych akcji."), 12)
    }
}

fn check_hosts() -> Check {
    let script = r#"Get-Content ($env:SystemRoot + '\System32\drivers\etc\hosts') -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*\d' } | Select-Object -First 60"#;
    let out = ps(script, 25).unwrap_or_default();
    let entries: Vec<String> = out
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if entries.is_empty() {
        return ck("hosts", "Plik hosts", "ok", "Brak niestandardowych wpisow w pliku hosts.", 10);
    }
    // Wpisy wskazujace na publiczne adresy (przekierowanie ruchu) sa podejrzane;
    // lokalne wpisy (Docker/Tailscale/0.0.0.0) traktujemy jako informacyjne.
    let external: Vec<String> = entries
        .iter()
        .filter(|e| {
            let ip = e.split_whitespace().next().unwrap_or("");
            !is_private_ip(ip)
        })
        .cloned()
        .collect();
    if !external.is_empty() {
        let list = external.iter().take(5).cloned().collect::<Vec<_>>().join(" | ");
        ck("hosts", "Plik hosts", "warn",
           format!("{} wpisow; {} wskazuje na zewnetrzne adresy (mozliwe przekierowanie ruchu): {}.",
                   entries.len(), external.len(), list), 10)
    } else {
        ck("hosts", "Plik hosts", "info",
           format!("{} lokalnych wpisow w pliku hosts (typowo Docker/Tailscale) - bez przekierowan na zewnatrz.",
                   entries.len()), 10)
    }
}

fn is_private_ip(ip: &str) -> bool {
    if ip == "0.0.0.0" || ip == "::1" || ip == "255.255.255.255" {
        return true;
    }
    if ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.")
        || ip.starts_with("169.254.") || ip.starts_with("100.")
    {
        return true;
    }
    if ip.starts_with("172.") {
        if let Some(o) = ip.split('.').nth(1).and_then(|x| x.parse::<u32>().ok()) {
            return (16..=31).contains(&o);
        }
    }
    if ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd") {
        return true;
    }
    false
}
