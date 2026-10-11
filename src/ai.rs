//! Panel AI z wyborem dostawcy:
//!   - "free"  -> Pollinations, dziala BEZ klucza API
//!   - "xkiro" -> twoje konto xkiro.com (klucz w USTAWIENIACH)
//!   - "local" -> Ollama na twoim kompie (bez klucza, bez limitow)
//! Gdy model padnie z limitem, automatycznie uzywamy modelu zastepczego.
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Lista dostepnych dostawcow.
#[derive(Serialize, Clone)]
pub struct ProviderDef {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub needs_key: bool,
    pub models: Vec<String>,
    pub note: String,
}

pub const FREE_MODELS: &[&str] = &["openai", "openai-fast", "llama", "qwen-coder"];

/// Klucz Pollinations - opcjonalny (daje wyzsze limity, ale API dziala i bez niego).
pub const POLLINATIONS_KEY: &str = "sk_cJEqIK4XxlPgTqtDOOBFGY0NcxKSchLv";
/// Klucz xkiro.com (dla dostawcy "xkiro").
pub const XKIRO_KEY: &str = "sk-xt-145eec03f100f3eb0b95e82ff42c24acf49cff0f45a03486";

pub fn providers() -> Vec<ProviderDef> {
    vec![
        ProviderDef {
            id: "free".into(),
            name: "Darmowe API (bez klucza)".into(),
            base_url: "https://gen.pollinations.ai/v1".into(),
            needs_key: false,
            models: FREE_MODELS.iter().map(|s| s.to_string()).collect(),
            note: "Pollinations - bez klucza i bez limitow. Dziala od razu.".into(),
        },
        ProviderDef {
            id: "xkiro".into(),
            name: "xkiro.com".into(),
            base_url: "https://api.xkiro.com/v1".into(),
            needs_key: true,
            models: crate_free_panel(),
            note: "Twoje konto xkiro - modele :free (wymaga klucza API).".into(),
        },
        ProviderDef {
            id: "local".into(),
            name: "Lokalne (Ollama)".into(),
            base_url: "http://localhost:11434".into(),
            needs_key: false,
            models: vec![],
            note: "Model na twoim kompie - bez klucza, dziala offline.".into(),
        },
    ]
}

fn crate_free_panel() -> Vec<String> {
    [
        "qwen/qwen3.8-max:free",
        "qwen/qwen3.7-max:free",
        "qwen/qwen3.6-max-preview:free",
        "qwen/qwen3.5-plus:free",
        "qwen/qwen3.7-plus:free",
        "qwen/qwen3.6-plus:free",
        "qwen/qwen3-max:free",
        "qwen/qwen3.5-397b-a17b:free",
        "qwen/qwen3.7-flash:free",
        "qwen/qwen3.5-flash:free",
        "meituan/longcat-2.5-preview:free",
        "inclusionai/ling-3.0-flash-sante:free",
        "liquid/lfm-2.5-2.6b:free",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn provider_by_id(id: &str) -> ProviderDef {
    providers()
        .into_iter()
        .find(|p| p.id == id)
        .unwrap_or_else(|| providers().remove(0))
}

const SYS: &str = r#"Jestes ekspertem cyberbezpieczenstwa specjalizujacym sie w systemach Windows. Otrzymasz raport z lokalnego skanera (kontrole bezpieczenstwa systemu, stan VPN, podejrzane pliki z najczesciej infekowanych katalogow). Ocen ogolne ryzyko infekcji lub kompromitacji komputera i odpowiedz WYLACZNIE poprawnym JSON-em, bez znacznikow markdown, w formacie: {"risk": 0-100, "verdict": "krotki werdykt", "summary": "2-3 zdania podsumowania", "findings": ["najwazniejsze obserwacje"], "recommendation": "konkretne kroki naprawcze"}. Pisz po polsku."#;

const SYS_FILES: &str = r#"Jestes analitykiem malware. Otrzymasz raport z skanera plikow: lista podejrzanych plikow z powodami (podwojne rozszerzenia, skrypty w Autostarcie, wysoka entropia, sygnatury skryptow, podejrzane nazwy). Dla KAZDEGO z plikow na liscie ocen, czy to wirus/trojan/script malware, czy nieskodliwy element systemu. Odpowiedz WYLACZNIE poprawnym JSON-em bez markdown, w formacie: {"risk": 0-100, "verdict": "krotki werdykt o zlosliwosci plikow", "summary": "2-3 zdania", "findings": ["sciezka - ocena i dlaczego"], "recommendation": "co zrobic: usunac/odizolowac/zbadac recznie"}. Jesli raport jest pusty, zwroc risk 0. Pisz po polsku."#;

const CHAT_SYS: &str = r#"Jestes pomocnym asystentem bezpieczenstwa komputerowego w aplikacji TZNSECVIRUS. Pomagasz uzytkownikowi z problemami z jego komputerem. W kontekście masz raport z skanera jego systemu - korzystaj z tych danych. Odpowiadaj zwiezle, konkretnie, po polsku. Podawaj kroki po kolei. Jesli czegos nie wiesz, powiedz to wprost. Formatuj czytelnie: krotkie akapity i listy punktowane."#;

#[derive(Serialize, Deserialize, Clone)]
pub struct AiSettings {
    pub api_key: String,
    pub base_url: String,
    pub provider: String,
    pub panel: Vec<String>,
    /// Dodatkowe klucze - uzywane automatycznie gdy pierwszy odmowi lub wyczerpie limit.
    pub alt_keys: Vec<String>,
}

impl Default for AiSettings {
    fn default() -> Self {
        let p = provider_by_id("free");
        Self {
            api_key: POLLINATIONS_KEY.to_string(),
            base_url: p.base_url.clone(),
            provider: p.id.clone(),
            panel: p.models.clone(),
            alt_keys: Vec::new(),
        }
    }
}

impl AiSettings {
    /// Lista kluczy do probowania po kolei (aktywny + zapisane).
    pub fn key_chain(&self) -> Vec<String> {
        let mut v = Vec::new();
        if !self.api_key.trim().is_empty() {
            v.push(self.api_key.trim().to_string());
        }
        for k in &self.alt_keys {
            let t = k.trim();
            if !t.is_empty() && !v.iter().any(|x| x == t) {
                v.push(t.to_string());
            }
        }
        v
    }

    pub fn is_local(&self) -> bool {
        let p = self.provider.to_lowercase();
        if p == "local" || p == "ollama" {
            return true;
        }
        if p == "free" || p == "xkiro" {
            return false;
        }
        let b = self.base_url.to_lowercase();
        b.contains("11434") || b.contains("localhost:1234")
    }

    /// Przelacza dostawce i ustawia jego modele + klucz.
    pub fn set_provider(&mut self, id: &str) {
        let p = provider_by_id(id);
        self.provider = p.id.clone();
        self.base_url = p.base_url.clone();
        self.panel = p.models.clone();
        if p.id == "local" {
            self.api_key = String::new();
        } else if p.id == "xkiro" {
            self.api_key = XKIRO_KEY.to_string();
        } else {
            self.api_key = POLLINATIONS_KEY.to_string();
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMsg {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Clone)]
pub struct AiModelResult {
    pub model: String,
    pub used_model: String,
    pub ok: bool,
    pub limited: bool,
    pub ms: u128,
    pub risk: Option<i64>,
    pub verdict: String,
    pub summary: String,
    pub findings: Vec<String>,
    pub recommendation: String,
    pub raw: String,
    pub error: String,
}

impl AiModelResult {
    pub fn err(model: &str, msg: &str) -> Self {
        Self {
            model: model.into(),
            used_model: String::new(),
            ok: false,
            limited: is_limit_error(msg),
            ms: 0,
            risk: None,
            verdict: String::new(),
            summary: String::new(),
            findings: Vec::new(),
            recommendation: String::new(),
            raw: String::new(),
            error: msg.into(),
        }
    }
}

pub fn is_limit_error(msg: &str) -> bool {
    let m = msg.to_lowercase();
    const MARKERS: &[&str] = &[
        "limit", "quota", "rate limit", "too many requests", "429", "capacity",
        "exhausted", "wyczerp", "przekrocz", "za duzo zadan", "no credits",
        "insufficient", "overloaded",
    ];
    MARKERS.iter().any(|k| m.contains(k))
}

/// Czy na blad warto uzyc modelu zastepczego.
/// Obejmuje limity, puste odpowiedzi i problemy z siecia.
fn should_retry(msg: &str) -> bool {
    if is_limit_error(msg) {
        return true;
    }
    let m = msg.to_lowercase();
    m.contains("pusta odpowiedz")
        || m.contains("pusta odpowied")
        || m.contains("timeout")
        || m.contains("connection")
        || m.contains("error sending request")
}

#[derive(Serialize, Clone, Default)]
pub struct AiAgg {
    pub total: usize,
    pub ok: usize,
    pub substituted: usize,
    pub limited: usize,
    pub risk_avg: f64,
    pub risk_min: i64,
    pub risk_max: i64,
    pub consensus: String,
    pub consensus_risk: i64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Default)]
struct Parsed {
    risk: Option<i64>,
    verdict: String,
    summary: String,
    findings: Vec<String>,
    recommendation: String,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Modele lokalne z Ollamy (bez klucza).
pub fn detect_local_models() -> Result<Vec<String>, String> {
    let agent = agent();
    let mut resp = agent
        .get("http://localhost:11434/api/tags")
        .call()
        .map_err(|_| "Ollama nie odpowiada na localhost:11434".to_string())?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| format!("{e}"))?;
    if status >= 400 {
        return Err(format!("HTTP {status}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{e}"))?;
    let mut out = Vec::new();
    if let Some(arr) = v.get("models").and_then(|d| d.as_array()) {
        for m in arr {
            if let Some(name) = m.get("name").and_then(|i| i.as_str()) {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Lista modeli dla wybranego dostawcy.
pub fn list_models(provider: &str, base: &str, key: &str) -> Result<Vec<String>, String> {
    if provider == "local" {
        return detect_local_models();
    }
    if key.trim().is_empty() {
        // bez klucza pokazujemy statyczna liste
        return Ok(provider_by_id(provider).models);
    }
    let url = format!("{}/models", base.trim_end_matches('/'));
    let agent = agent();
    let mut resp = agent
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .call()
        .map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| format!("{e}"))?;
    if status >= 400 {
        return Err(format!("HTTP {status}: {}", first_chars(&text, 160)));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{e}"))?;
    let mut out = Vec::new();
    if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
        for m in arr {
            if let Some(id) = m.get("id").and_then(|i| i.as_str()) {
                out.push(id.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

pub fn analyze<F: Fn(AiModelResult)>(s: &AiSettings, report: &str, emit: &F) -> AiAgg {
    analyze_with(s, report, SYS, emit)
}

pub fn analyze_files<F: Fn(AiModelResult)>(s: &AiSettings, report: &str, emit: &F) -> AiAgg {
    analyze_with(s, report, SYS_FILES, emit)
}

pub fn analyze_with<F: Fn(AiModelResult)>(
    s: &AiSettings,
    report: &str,
    sys_prompt: &str,
    emit: &F,
) -> AiAgg {
    let sys = sys_prompt.to_string();
    let user = format!(
        "RAPORT ZE SKANERA (JSON):\n{report}\n\nOdpowiedz wylacznie JSON-em zgodnym ze schematem."
    );
    let results: Vec<AiModelResult> = std::thread::scope(|scope| {
        let fallbacks: Vec<String> = s.panel.iter().skip(1).cloned().collect();
        let keys: Vec<String> = s.key_chain();
        let mut handles = Vec::new();
        for m in &s.panel {
            let model = m.clone();
            let sys_c = sys.clone();
            let user_c = user.clone();
            let base = s.base_url.clone();
            let local = s.is_local();
            let fb = fallbacks.clone();
            let kc = keys.clone();
            handles.push(scope.spawn(move || run_one(&base, &kc, local, &model, &fb, &sys_c, &user_c)));
        }
        let mut out = Vec::new();
        for h in handles {
            let r = h
                .join()
                .unwrap_or_else(|_| AiModelResult::err("?", "blad watku"));
            emit(r.clone());
            out.push(r);
        }
        out
    });
    aggregate(&results)
}

fn run_one(
    base: &str,
    keys: &[String],
    local: bool,
    model: &str,
    fallbacks: &[String],
    sys: &str,
    user: &str,
) -> AiModelResult {
    let start = Instant::now();
    let mut first_err = String::new();

    // 1) probujemy kolejnych kluczy dla glownego modelu
    for k in keys {
        match call(base, k, local, model, sys, user) {
            Ok((content, parsed)) => return build_result(model, model, content, parsed, start, false),
            Err(e) => {
                if first_err.is_empty() {
                    first_err = e;
                }
                if !should_retry(&first_err) {
                    return failed(model, start, first_err, false);
                }
            }
        }
    }

    // 2) glowny model odmowil - probujemy modeli zastepczych (tez z innymi kluczami)
    for fb in fallbacks.iter().take(4) {
        for k in keys {
            if let Ok((content, parsed)) = call(base, k, local, fb, sys, user) {
                return build_result(model, fb, content, parsed, start, true);
            }
        }
    }

    failed(model, start, first_err, true)
}

fn failed(model: &str, start: Instant, err: String, limited: bool) -> AiModelResult {
    AiModelResult {
        model: model.into(),
        used_model: String::new(),
        ok: false,
        limited,
        ms: start.elapsed().as_millis(),
        risk: None,
        verdict: String::new(),
        summary: String::new(),
        findings: Vec::new(),
        recommendation: String::new(),
        raw: String::new(),
        error: err,
    }
}

fn build_result(
    model: &str,
    used_model: &str,
    content: String,
    parsed: Option<Parsed>,
    start: Instant,
    substituted: bool,
) -> AiModelResult {
    let ms = start.elapsed().as_millis();
    match parsed {
        Some(p) => AiModelResult {
            model: model.into(),
            used_model: used_model.into(),
            ok: true,
            limited: substituted,
            ms,
            risk: p.risk,
            verdict: p.verdict,
            summary: p.summary,
            findings: p.findings,
            recommendation: p.recommendation,
            raw: first_chars(&content, 4000),
            error: String::new(),
        },
        None => AiModelResult {
            model: model.into(),
            used_model: used_model.into(),
            ok: true,
            limited: substituted,
            ms,
            risk: None,
            verdict: String::new(),
            summary: first_chars(&content, 800),
            findings: Vec::new(),
            recommendation: String::new(),
            raw: first_chars(&content, 4000),
            error: String::new(),
        },
    }
}

/// Wysyla zapytanie. Klucz jest opcjonalny - endpointy bez klucza dzialaja bez naglowka.
fn call(
    base: &str,
    key: &str,
    local: bool,
    model: &str,
    sys: &str,
    user: &str,
) -> Result<(String, Option<Parsed>), String> {
    let msgs = vec![
        json!({"role": "system", "content": sys}),
        json!({"role": "user", "content": user}),
    ];
    let txt = call_raw(base, key, local, model, &msgs)?;
    Ok((txt.clone(), parse_ai_json(&txt)))
}

pub fn call_raw(
    base: &str,
    key: &str,
    local: bool,
    model: &str,
    msgs: &[serde_json::Value],
) -> Result<String, String> {
    let agent = agent();
    if local {
        let body = json!({
            "model": model, "messages": msgs, "stream": false,
            "options": {"temperature": 0.2, "num_predict": 1200}
        });
        let mut resp = agent
            .post("http://localhost:11434/api/chat")
            .header("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("Ollama: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().map_err(|e| format!("{e}"))?;
        if status >= 400 {
            return Err(format!("Ollama HTTP {status}: {}", first_chars(&text, 160)));
        }
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{e}"))?;
        return v
            .pointer("/message/content")
            .and_then(|c| c.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Ollama zwrocila pusta odpowiedz".to_string());
    }

    let url = format!("{}/chat/completions", base.trim_end_matches('/'));
    let body = json!({
        "model": model, "messages": msgs, "temperature": 0.2, "max_tokens": 1200
    });
    let mut req = agent
        .post(&url)
        .header("Content-Type", "application/json");
    if !key.trim().is_empty() {
        req = req.header("Authorization", format!("Bearer {key}"));
    }
    let mut resp = req.send_json(&body).map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| format!("{e}"))?;
    if status >= 400 {
        return Err(format!("HTTP {status}: {}", first_chars(&text, 200)));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{e}"))?;
    v.pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .or_else(|| v.pointer("/choices/0/text").and_then(|c| c.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "pusta odpowiedz modelu".to_string())
}

fn parse_ai_json(s: &str) -> Option<Parsed> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end <= start {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&s[start..=end]).ok()?;
    let risk = v.get("risk").and_then(|r| {
        r.as_i64()
            .or_else(|| r.as_f64().map(|f| f as i64))
            .or_else(|| r.as_str().and_then(|x| x.trim().parse().ok()))
    });
    Some(Parsed {
        risk,
        verdict: v.get("verdict").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        summary: v.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        findings: v
            .get("findings")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        recommendation: v.get("recommendation").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

fn aggregate(results: &[AiModelResult]) -> AiAgg {
    let mut agg = AiAgg { total: results.len(), ..Default::default() };
    let mut risks: Vec<i64> = Vec::new();
    let mut findings: Vec<String> = Vec::new();
    let mut recs: Vec<String> = Vec::new();
    for r in results {
        if r.limited && !r.used_model.is_empty() {
            agg.substituted += 1;
        }
        if !r.ok {
            if r.limited {
                agg.limited += 1;
            }
            continue;
        }
        agg.ok += 1;
        if let Some(rk) = r.risk {
            risks.push(rk.clamp(0, 100));
        }
        findings.extend(r.findings.iter().cloned());
        if !r.recommendation.is_empty() {
            recs.push(r.recommendation.clone());
        }
        if r.summary.is_empty() && !r.verdict.is_empty() {
            recs.push(r.verdict.clone());
        }
    }
    if risks.is_empty() {
        agg.consensus = "BRAK DANYCH".into();
    } else {
        let sum: i64 = risks.iter().sum();
        agg.risk_avg = sum as f64 / risks.len() as f64;
        agg.risk_min = *risks.iter().min().unwrap();
        agg.risk_max = *risks.iter().max().unwrap();
        agg.consensus_risk = agg.risk_avg.round() as i64;
        agg.consensus = majority_label(&risks).to_string();
    }
    agg.findings = dedup_cap(findings, 15);
    agg.recommendations = dedup_cap(recs, 8);
    agg
}

fn majority_label(risks: &[i64]) -> &'static str {
    let mut counts = [0usize; 4];
    for &r in risks {
        counts[match r {
            r if r < 25 => 0,
            r if r < 50 => 1,
            r if r < 75 => 2,
            _ => 3,
        }] += 1;
    }
    let mut best = 0usize;
    for i in 1..4 {
        if counts[i] > counts[best] {
            best = i;
        }
    }
    ["NISKIE", "SREDNIE", "WYSOKIE", "KRYTYCZNE"][best]
}

fn dedup_cap(items: Vec<String>, cap: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for i in items {
        let i = i.trim().to_string();
        if i.is_empty() {
            continue;
        }
        if seen.insert(i.to_lowercase()) {
            out.push(i);
        }
        if out.len() >= cap {
            break;
        }
    }
    out
}

fn first_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Czat z automatycznym fallbackiem. Zwraca (model, odpowiedz).
pub fn chat(
    s: &AiSettings,
    history: &[ChatMsg],
    context: &str,
    model: &str,
) -> Result<(String, String), String> {
    let sys = format!(
        "{CHAT_SYS}\n\n=== STAN KOMPUTERA (raport skanera) ===\n{}",
        first_chars(context, 3000)
    );
    let mut msgs = vec![json!({"role": "system", "content": sys})];
    for m in history {
        msgs.push(json!({"role": m.role, "content": m.content}));
    }
    let keys = s.key_chain();
    let local = s.is_local();
    let mut first_err = String::new();

    // 1) wybrany model, kolejne klucze
    for k in &keys {
        match call_raw(&s.base_url, k, local, model, &msgs) {
            Ok(t) => return Ok((model.to_string(), t)),
            Err(e) => {
                if first_err.is_empty() {
                    first_err = e;
                }
                if !should_retry(&first_err) {
                    return Err(first_err);
                }
            }
        }
    }
    // 2) modele zastepcze x kolejne klucze
    for fb in s.panel.iter().skip(1).take(4) {
        for k in &keys {
            if let Ok(t) = call_raw(&s.base_url, k, local, fb, &msgs) {
                return Ok((fb.clone(), t));
            }
        }
    }
    Err(format!("{} (limity wyczerpane)", first_err))
}