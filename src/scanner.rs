//! Skaner najczesciej infekowanych katalogow z heurystyka oparta na rozszerzeniach,
//! nazwach, entropii pliku oraz sygnaturach w skryptach.
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::{DirEntry, WalkDir};

const DANGEROUS_EXT: &[&str] = &[
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "jar", "msi", "com", "pif", "reg", "cpl", "lnk", "src", "drv", "sys", "psm1", "psd1",
];
const EXEC_EXT: &[&str] = &["exe", "dll", "scr", "sys", "drv", "com", "cpl"];
const SCRIPT_EXT: &[&str] = &["ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "psm1", "psd1"];
const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif",
    "zip", "rar", "7z", "mp3", "mp4", "csv", "rtf", "htm", "html", "xml", "json", "iso",
];
const NAME_KEYWORDS: &[&str] = &[
    "crack", "keygen", "activator", "warez", "nulled", "cheat", "hacktool", "miner", "xmr",
    "mimikatz", "ransom", "locky", "wannacry", "trojan", "backdoor", "botnet", "stealer",
    "keylogger", "kmspico", "kmsauto", "autokms", "redline", "raccoon", "njrat", "quasar",
    "remcos", "dcrat", "agenttesla", "formbook", "lokibot", "gcleaner",
];
const SCRIPT_SIGNATURES: &[&str] = &[
    "downloadstring", "downloadfile", "invoke-webrequest", "invoke-expression", "iex(",
    "frombase64string", "-encodedcommand", "bitsadmin", "certutil -decode", "certutil -urlcache",
    "vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set", "netsh advfirewall set",
    "schtasks /create", "new-object net.webclient", "-windowstyle hidden", "start-process -windowstyle hidden",
    "set-mppreference -disable", "add-mppreference -exclusionpath", "sekurlsa", "mimikatz",
    "invoke-mimikatz", "amsiinitfailed", "reflection.assembly",
];
const NOISE_DIRS: &[&str] = &[
    "node_modules", ".git", ".svn", ".hg", "cache", "cachestorage", "code cache", "gpucache",
    "service worker", "shadercache", "component cache", "jump lists", "inetcache", ".vscode",
    "target", ".next", ".nuxt", "vendor",
];

#[derive(Serialize, Clone)]
pub struct Finding {
    pub path: String,
    pub file: String,
    pub severity: String,
    pub score: u32,
    pub size: u64,
    pub modified: String,
    pub reasons: Vec<String>,
}

#[derive(Serialize, Clone, Default)]
pub struct ScanReport {
    pub scanned_files: usize,
    pub elapsed_ms: u128,
    pub findings: Vec<Finding>,
    pub dirs: Vec<String>,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub limit_hit: bool,
}

/// Domyslne katalogi najczesciej infekowane przez malware.
pub fn default_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if p.exists() {
            let s = p.to_string_lossy().to_lowercase();
            if !v.iter().any(|q| q.to_string_lossy().to_lowercase() == s) {
                v.push(p);
            }
        }
    };

    push(std::env::temp_dir());
    push(PathBuf::from("C:\\Windows\\Temp"));
    push(PathBuf::from("C:\\Users\\Public"));
    if let Ok(pd) = std::env::var("ProgramData") {
        push(PathBuf::from(pd));
    }
    if let Some(p) = dirs::home_dir() {
        push(p.join("Downloads"));
        push(p.join("Desktop"));
        push(p.join("Documents"));
    }
    if let Some(p) = dirs::data_dir() {
        push(p.clone());
        push(p
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup"));
        push(p.join("Mozilla").join("Firefox").join("Profiles"));
    }
    if let Some(p) = dirs::data_local_dir() {
        push(p.clone());
        push(p.join("Temp"));
        push(p
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default")
            .join("Extensions"));
        push(p
            .join("Microsoft")
            .join("Edge")
            .join("User Data")
            .join("Default")
            .join("Extensions"));
    }
    push(PathBuf::from("C:\\Windows\\System32\\Tasks"));
    v
}

pub fn scan(dirs: &[PathBuf], max_files: usize, max_depth: usize, cb: &dyn Fn(usize, &str)) -> ScanReport {
    let start = std::time::Instant::now();
    let mut report = ScanReport::default();
    let mut count = 0usize;

    'outer: for d in dirs {
        if !d.exists() {
            continue;
        }
        report.dirs.push(d.display().to_string());
        let walker = WalkDir::new(d)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_noise(e));

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            count += 1;
            if count % 150 == 0 {
                cb(count, &entry.path().display().to_string());
            }
            if count > max_files {
                report.limit_hit = true;
                break 'outer;
            }
            if let Some(f) = analyze_file(entry.path()) {
                report.findings.push(f);
            }
        }
    }

    report.scanned_files = count;
    report.elapsed_ms = start.elapsed().as_millis();
    report.findings.sort_by(|a, b| b.score.cmp(&a.score));
    report.findings.truncate(500);
    for f in &report.findings {
        match f.severity.as_str() {
            "high" => report.high += 1,
            "medium" => report.medium += 1,
            _ => report.low += 1,
        }
    }
    report
}

fn is_noise(e: &DirEntry) -> bool {
    if !e.file_type().is_dir() {
        return false;
    }
    let name = e.file_name().to_string_lossy().to_lowercase();
    NOISE_DIRS.contains(&name.as_str())
}

fn analyze_file(path: &Path) -> Option<Finding> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let lower = name.to_lowercase();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let size = meta.len();
    let modified = meta.modified().ok();
    let hidden = is_hidden(&meta);

    let mut score = 0u32;
    let mut reasons: Vec<String> = Vec::new();

    let risky_ext = DANGEROUS_EXT.contains(&ext.as_str());
    let exec = EXEC_EXT.contains(&ext.as_str());
    let script = SCRIPT_EXT.contains(&ext.as_str());

    let plow = path.to_string_lossy().to_lowercase();
    let in_startup = plow.contains("\\startup\\") || plow.contains("/startup/");
    let in_temp = plow.contains("\\temp\\") || plow.contains("\\tmp\\") || plow.contains("/temp/");

    // Podwojne rozszerzenie (np. faktura.pdf.exe)
    if exec {
        if let Some((stem, _)) = name.rsplit_once('.') {
            if let Some((_, stem_ext)) = stem.rsplit_once('.') {
                if DOC_EXT.contains(&stem_ext.to_lowercase().as_str()) {
                    score += 30;
                    reasons.push(format!("podwojne rozszerzenie (plik udaje dokument: .{}.{})", stem_ext.to_lowercase(), ext));
                }
            }
        }
    }

    // Podejrzane slowa w nazwie (tylko dla plikow wykonywalnych i skryptow - mniej falszywych trafien)
    if risky_ext || script {
        for kw in NAME_KEYWORDS {
            if lower.contains(kw) {
                score += 35;
                reasons.push(format!("podejrzana nazwa zawiera '{kw}'"));
                break;
            }
        }
    }

    // Autostart - kazdy plik wykonywalny/skrypt jest podejrzany
    if in_startup && (risky_ext || script) {
        score += 35;
        reasons.push("plik wykonywalny/skrypt w folderze Autostart".into());
    }

    // Plik wykonywalny w katalogu tymczasowym
    if in_temp && exec {
        score += 15;
        reasons.push("plik wykonywalny w katalogu tymczasowym".into());
    }

    // Ukryty plik wykonywalny/skrypt
    if hidden && (exec || script) {
        score += 12;
        reasons.push("ukryty plik wykonywalny/skrypt".into());
    }

    // Sygnatury w skryptach
    if script && size < 2_000_000 {
        let sigs = script_signatures(path);
        if !sigs.is_empty() {
            score += 30 + (sigs.len() as u32 * 5).min(30);
            reasons.push(format!("podejrzane komendy w skrypcie: {}", sigs.join(", ")));
        }
    }

    // Entropia dla plikow wykonywalnych (packing / szyfrowanie)
    if exec && size >= 4096 && size < 32_000_000 {
        if let Some(ent) = entropy(path, 262_144) {
            if ent > 7.35 {
                score += 20;
                reasons.push(format!("wysoka entropia {ent:.2} (mozliwy packing/szyfrowanie)"));
            }
        }
    }

    if score == 0 {
        return None;
    }

    let severity = if score >= 60 {
        "high"
    } else if score >= 32 {
        "medium"
    } else {
        "low"
    };

    Some(Finding {
        path: path.display().to_string(),
        file: name,
        severity: severity.into(),
        score,
        size,
        modified: fmt_time(modified),
        reasons,
    })
}

fn script_signatures(path: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return hits,
    };
    let mut buf = vec![0u8; 262_144];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return hits,
    };
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf).to_lowercase();
    for s in SCRIPT_SIGNATURES {
        if text.contains(s) {
            hits.push((*s).to_string());
        }
    }
    hits
}

fn entropy(path: &Path, max: usize) -> Option<f64> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    let mut counts = [0u64; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }
    let len = n as f64;
    let mut e = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    Some(e)
}

#[cfg(windows)]
fn is_hidden(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x2 != 0
}

#[cfg(not(windows))]
fn is_hidden(_meta: &std::fs::Metadata) -> bool {
    false
}

fn fmt_time(t: Option<SystemTime>) -> String {
    let secs = match t {
        Some(t) => t
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        None => return String::new(),
    };
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 }.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yy = if m <= 2 { y + 1 } else { y };
    format!("{yy:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}
