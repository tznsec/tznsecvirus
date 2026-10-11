//! TZNSECVIRUS - okno aplikacji (tao + wry webview) i spiecie modulow.
//! Jeden przycisk "SKANUJ" uruchamia caly pipeline: kontrole systemu -> VPN -> skan katalogow -> panel AI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod scanner;
mod security;
mod util;
mod vpn;

use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::WindowBuilder;
use wry::WebViewBuilder;

const UI_HTML: &str = include_str!("../ui/index.html");

#[derive(Clone)]
enum UserEvent {
    Emit(String),
}

struct AppState {
    settings: ai::AiSettings,
    last_security: Vec<security::Check>,
    last_scan: Option<scanner::ScanReport>,
    last_vpn: Option<vpn::VpnState>,
    chat: Vec<ai::ChatMsg>,
    busy: bool,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Podkomendy. "run" jest obslugiwane jawnie - tznsecvirus run po instalacji
    // przez winget (PortableCommandAlias) uruchamia aplikacje.
    let sub = args.iter().skip(1).find(|a| !a.starts_with('-')).cloned();
    match sub.as_deref() {
        Some("run") => {}
        Some(other) => {
            eprintln!("nieznana komenda: {other}");
            print_help();
            return;
        }
        None => {}
    }

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--selftest") {
        let with_ai = !args.iter().any(|a| a == "--no-ai");
        selftest(with_ai);
        return;
    }
    if args.iter().any(|a| a == "--models") {
        for p in ai::providers() {
            println!("{} | {} | {}", p.id, p.name, p.base_url);
        }
        return;
    }

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("TZNSECVIRUS")
        .with_inner_size(tao::dpi::LogicalSize::new(1240.0, 840.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(960.0, 620.0))
        .build(&event_loop)
        .expect("nie udalo sie utworzyc okna");

    let state = Arc::new(Mutex::new(AppState {
        settings: ai::AiSettings::default(),
        last_security: Vec::new(),
        last_scan: None,
        last_vpn: None,
        chat: Vec::new(),
        busy: false,
    }));

    let proxy = event_loop.create_proxy();
    let ipc_proxy = proxy.clone();
    let ipc_state = state.clone();

    let builder = WebViewBuilder::new()
        .with_html(UI_HTML)
        .with_devtools(true)
        .with_background_color((6, 8, 13, 255))
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let body = req.body().clone();
            let state = ipc_state.clone();
            let proxy = ipc_proxy.clone();
            std::thread::spawn(move || handle_command(&body, state, proxy));
        });

    let webview = match builder.build(&window) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("Blad tworzenia webview: {e}");
            std::process::exit(1);
        }
    };

    let mut webview = webview;

    // Splash zamyka watek std::thread - WebView2 throttluje setTimeout/rAF w oknie
    // ktore nie ma fokusu, ale ten watek dziala zawsze.
    let splash_proxy = proxy.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(2500));
        emit(&splash_proxy, json!({"type": "hide_splash"}));
    });

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        let _keep_window = &window;
        match event {
            Event::UserEvent(UserEvent::Emit(payload)) => {
                if let Some(wv) = &webview {
                    let js = format!("window.__tnsEvent && window.__tnsEvent({payload});");
                    let _ = wv.evaluate_script(&js);
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                webview = None;
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}

fn emit(proxy: &EventLoopProxy<UserEvent>, v: Value) {
    let _ = proxy.send_event(UserEvent::Emit(v.to_string()));
}

fn risk_from_checks(checks: &[security::Check]) -> i64 {
    let mut penalty = 0u32;
    let mut total = 0u32;
    for c in checks {
        total += c.weight;
        match c.status.as_str() {
            "fail" => penalty += c.weight,
            "warn" => penalty += c.weight / 2,
            _ => {}
        }
    }
    if total == 0 {
        return 0;
    }
    ((penalty as f64 / total as f64) * 100.0).round() as i64
}

fn handle_command(body: &str, state: Arc<Mutex<AppState>>, proxy: EventLoopProxy<UserEvent>) {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return,
    };
    let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or("");

    match cmd {
        "ready" => {
            let (provs, models, provider, has_key) = {
                let s = state.lock().unwrap();
                (
                    ai::providers(),
                    s.settings.panel.clone(),
                    s.settings.provider.clone(),
                    !s.settings.api_key.trim().is_empty(),
                )
            };
            let wiped = privacy_wipe();
            let keys = {
                let s = state.lock().unwrap();
                mask_keys(&s.settings)
            };
            emit(&proxy, json!({
                "type": "ready", "providers": provs, "models": models,
                "provider": provider, "has_key": has_key, "wiped": wiped, "keys": keys
            }));
        }
        "set_provider" => {
            let id = v.get("provider").and_then(|x| x.as_str()).unwrap_or("free").to_string();
            {
                let mut s = state.lock().unwrap();
                s.settings.set_provider(&id);
            }
            let (provs, models, provider) = {
                let s = state.lock().unwrap();
                (ai::providers(), s.settings.panel.clone(), s.settings.provider.clone())
            };
            emit(&proxy, json!({
                "type": "provider_changed", "providers": provs,
                "models": models, "provider": provider
            }));
        }
        "detect_local" => {
            emit(&proxy, json!({"type": "log", "level": "info", "msg": "Szukam Ollamy..."}));
            match ai::detect_local_models() {
                Ok(mut m) => {
                    m.sort();
                    let n = m.len();
                    if n > 0 {
                        let mut s = state.lock().unwrap();
                        s.settings.provider = "local".into();
                        s.settings.base_url = "http://localhost:11434".into();
                        s.settings.panel = m.clone();
                    }
                    let provs = ai::providers();
                    emit(&proxy, json!({
                        "type": "provider_changed", "providers": provs, "models": m,
                        "provider": if n > 0 { "local" } else { "free" }
                    }));
                    if n == 0 {
                        emit(&proxy, json!({"type": "log", "level": "warn",
                            "msg": "Ollama nie zainstalowana lub brak modeli (ollama pull llama3)"}));
                    }
                }
                Err(e) => emit(&proxy, json!({"type": "log", "level": "warn", "msg": format!("Brak Ollamy: {e}")})),
            }
        }
        "models" => {
            // UI wybralo modele - zapisujemy i lecimy z calym skanowaniem
            if let Some(p) = v.get("panel").and_then(|x| x.as_array()) {
                let selected: Vec<String> = p
                    .iter()
                    .filter_map(|i| i.as_str().map(|x| x.to_string()))
                    .collect();
                if selected.is_empty() {
                    emit(&proxy, json!({"type": "log", "level": "warn",
                        "msg": "Nie wybrano zadnego modelu - skanowanie AI pominiete."}));
                } else {
                    let mut s = state.lock().unwrap();
                    s.settings.panel = selected;
                }
            }
            run_full(state, proxy);
        }
        "settings" => {
            {
                let mut s = state.lock().unwrap();
                if let Some(k) = v.get("api_key").and_then(|x| x.as_str()) {
                    if !k.trim().is_empty() {
                        s.settings.api_key = k.trim().to_string();
                    }
                }
                if let Some(b) = v.get("base_url").and_then(|x| x.as_str()) {
                    if !b.trim().is_empty() {
                        s.settings.base_url = b.trim().to_string();
                    }
                }
                if let Some(p) = v.get("panel").and_then(|x| x.as_array()) {
                    let list: Vec<String> = p
                        .iter()
                        .filter_map(|i| i.as_str().map(|x| x.to_string()))
                        .collect();
                    if !list.is_empty() {
                        s.settings.panel = list;
                    }
                }
            }
            emit(&proxy, json!({"type": "log", "level": "ok", "msg": "Zapisano ustawienia."}));
        }
        "refresh_models" => {
            let (prov, base, key) = {
                let s = state.lock().unwrap();
                (s.settings.provider.clone(), s.settings.base_url.clone(), s.settings.api_key.clone())
            };
            emit(&proxy, json!({"type": "log", "level": "info", "msg": "Pobieram modele..."}));
            match ai::list_models(&prov, &base, &key) {
                Ok(models) => {
                    if !models.is_empty() {
                        let mut s = state.lock().unwrap();
                        s.settings.panel = models.clone();
                    }
                    let provs = ai::providers();
                    emit(&proxy, json!({
                        "type": "provider_changed", "providers": provs,
                        "models": models, "provider": prov
                    }));
                }
                Err(e) => emit(&proxy, json!({"type": "log", "level": "error",
                    "msg": format!("Nie mozna pobrac modeli: {e}")})),
            }
        }
        "key_add" => {
            let key = v.get("key").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if key.is_empty() {
                return;
            }
            let keys = {
                let mut s = state.lock().unwrap();
                if !s.settings.alt_keys.iter().any(|k| k == &key)
                    && s.settings.api_key != key
                {
                    s.settings.alt_keys.push(key.clone());
                }
                mask_keys(&s.settings)
            };
            emit(&proxy, json!({"type": "keys", "keys": keys}));
        }
        "key_use" => {
            let idx = v.get("index").and_then(|x| x.as_i64()).unwrap_or(-1);
            let keys = {
                let mut s = state.lock().unwrap();
                if idx == 0 {
                    // klucz wbudowany / aktywny domyslny dla dostawcy
                    s.settings.api_key = match s.settings.provider.as_str() {
                        "xkiro" => ai::XKIRO_KEY.to_string(),
                        "local" => String::new(),
                        _ => ai::POLLINATIONS_KEY.to_string(),
                    };
                } else if let Some(k) = s.settings.alt_keys.get((idx - 1) as usize) {
                    s.settings.api_key = k.clone();
                }
                mask_keys(&s.settings)
            };
            emit(&proxy, json!({"type": "keys", "keys": keys}));
            emit(&proxy, json!({"type": "log", "level": "ok", "msg": "Zmieniono aktywny klucz API."}));
        }
        "key_del" => {
            let idx = v.get("index").and_then(|x| x.as_i64()).unwrap_or(-1);
            let keys = {
                let mut s = state.lock().unwrap();
                if idx > 0 {
                    if let Some(i) = (idx - 1).try_into().ok() {
                        if i < s.settings.alt_keys.len() {
                            s.settings.alt_keys.remove(i);
                        }
                    }
                }
                mask_keys(&s.settings)
            };
            emit(&proxy, json!({"type": "keys", "keys": keys}));
        }
        "stop" => {
            emit(&proxy, json!({"type": "log", "level": "info", "msg": "Zglaszam anulowanie..."}));
        }
        "export" => {
            let (report, host) = {
                let s = state.lock().unwrap();
                (build_report(&s), std::env::var("COMPUTERNAME").unwrap_or_else(|_| "pc".into()))
            };
            let dir = dirs::download_dir()
                .or_else(dirs::desktop_dir)
                .or_else(|| Some(std::env::temp_dir()))
                .unwrap();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let path = dir.join(format!("tznsecvirus_{host}_{ts}.json"));
            match std::fs::write(&path, report) {
                Ok(_) => emit(&proxy, json!({"type": "log", "level": "ok", "msg": format!("Zapisano raport: {}", path.display())})),
                Err(e) => emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Blad zapisu raportu: {e}")})),
            }
        }
        "scan_path" => {
            let raw = v.get("path").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            let expanded = expand_env(&raw);
            let p = PathBuf::from(&expanded);
            if expanded.is_empty() {
                emit(&proxy, json!({"type": "log", "level": "warn", "msg": "Podaj sciezke do folderu."}));
                return;
            }
            if !p.exists() {
                emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Sciezka nie istnieje: {expanded}")}));
                return;
            }
            let dirs: Vec<PathBuf> = if p.is_dir() {
                vec![p.clone()]
            } else {
                p.parent().map(|x| vec![x.to_path_buf()]).unwrap_or_default()
            };
            emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("Skanuje: {}", p.display())}));
            let pr = proxy.clone();
            let report = scanner::scan(&dirs, 60000, 5, &|n: usize, path: &str| {
                emit(&pr, json!({"type": "scan_progress", "count": n, "path": path}));
            });
            state.lock().unwrap().last_scan = Some(report.clone());
            emit(&proxy, json!({"type": "scan_done", "report": report}));
            emit(&proxy, json!({"type": "done"}));
        }
        "pick_folder" => {
            let script = r#"Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Wybierz folder do skanowania'; if($d.ShowDialog() -eq 'OK'){ Write-Output $d.SelectedPath }"#;
            match crate::util::ps(script, 300) {
                Ok(out) => {
                    let chosen = crate::util::first_line(&out);
                    if chosen.is_empty() {
                        emit(&proxy, json!({"type": "log", "level": "warn", "msg": "Nie wybrano folderu."}));
                    } else {
                        emit(&proxy, json!({"type": "path_picked", "path": chosen}));
                    }
                }
                Err(e) => emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Blad okna dialogowego: {e}")})),
            }
        }
        "chat" => {
            let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if msg.is_empty() {
                return;
            }
            let (settings, history, context, model) = {
                let mut s = state.lock().unwrap();
                s.chat.push(ai::ChatMsg { role: "user".into(), content: msg.clone() });
                if s.chat.len() > 16 {
                    let cut = s.chat.len() - 16;
                    s.chat.drain(0..cut);
                }
                let m = match v.get("model").and_then(|x| x.as_str()) {
                    Some(want) if !want.trim().is_empty() => want.trim().to_string(),
                    _ => s
                        .settings
                        .panel
                        .first()
                        .cloned()
                        .unwrap_or_else(|| ai::FREE_MODELS[0].to_string()),
                };
                (s.settings.clone(), s.chat.clone(), build_report(&s), m)
            };
            emit(&proxy, json!({"type": "chat_user", "message": msg}));
            match ai::chat(&settings, &history, &context, &model) {
                Ok((used, reply)) => {
                    let mut s = state.lock().unwrap();
                    s.chat.push(ai::ChatMsg { role: "assistant".into(), content: reply.clone() });
                    drop(s);
                    emit(&proxy, json!({"type": "chat_reply", "message": reply, "model": used}));
                }
                Err(e) => emit(&proxy, json!({"type": "chat_error", "message": e})),
            }
        }
        "chat_clear" => {
            state.lock().unwrap().chat.clear();
            emit(&proxy, json!({"type": "chat_cleared"}));
        }
        "scan_path_ai" => {
            let raw = v.get("path").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            let expanded = expand_env(&raw);
            let p = PathBuf::from(&expanded);
            if !p.exists() {
                emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Sciezka nie istnieje: {expanded}")}));
                return;
            }
            let dirs: Vec<PathBuf> = if p.is_dir() { vec![p.clone()] }
                else { p.parent().map(|x| vec![x.to_path_buf()]).unwrap_or_default() };
            emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("Skanuje: {}", p.display())}));
            let pr = proxy.clone();
            let report = scanner::scan(&dirs, 60000, 5, &|n: usize, path: &str| {
                emit(&pr, json!({"type": "scan_progress", "count": n, "path": path}));
            });
            state.lock().unwrap().last_scan = Some(report.clone());
            emit(&proxy, json!({"type": "scan_done", "report": report}));

            let settings = state.lock().unwrap().settings.clone();
            if settings.panel.is_empty() {
                emit(&proxy, json!({"type": "log", "level": "warn", "msg": "Brak wybranych modeli AI - pomijam ocene."}));
            } else {
                let rep = {
                    let s = state.lock().unwrap();
                    build_report(&s)
                };
                emit(&proxy, json!({"type": "ai_start", "models": settings.panel.clone()}));
                let pa = proxy.clone();
                let agg = ai::analyze_files(&settings, &rep, &|r: ai::AiModelResult| {
                    emit(&pa, json!({"type": "ai_model", "result": r}));
                });
                emit(&proxy, json!({"type": "ai_done", "agg": agg}));
            }
            emit(&proxy, json!({"type": "done"}));
        }
        "scan_files" => {
            let dirs = scanner::default_dirs();
            emit(&proxy, json!({"type": "phase", "phase": "scan", "label": "Skan katalogow"}));
            emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("Skanuje {} katalogow...", dirs.len())}));
            let p = proxy.clone();
            let report = scanner::scan(&dirs, 60000, 4, &|n: usize, path: &str| {
                emit(&p, json!({"type": "scan_progress", "count": n, "path": path}));
            });
            state.lock().unwrap().last_scan = Some(report.clone());
            emit(&proxy, json!({"type": "scan_done", "report": report}));
            emit(&proxy, json!({"type": "done"}));
        }
        "vpn_launch" => {
            let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("Uruchamiam VPN: {name}...")}));
            match vpn::launch(&kind, &path, &name) {
                Ok(msg) => emit(&proxy, json!({"type": "log", "level": "ok", "msg": msg})),
                Err(e) => emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Blad VPN: {e}")})),
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
            let st = vpn::detect();
            let geo = vpn::ip_geo();
            state.lock().unwrap().last_vpn = Some(st.clone());
            let geo_json = match &geo {
                Some((ip, c, isp)) => json!({"ip": ip, "country": c, "isp": isp}),
                None => Value::Null,
            };
            emit(&proxy, json!({"type": "vpn", "vpn": st, "tools": vpn::tools(), "geo": geo_json}));
        }
        "vpn_stop" => {
            let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            match vpn::stop(&kind, &name) {
                Ok(msg) => emit(&proxy, json!({"type": "log", "level": "ok", "msg": msg})),
                Err(e) => emit(&proxy, json!({"type": "log", "level": "error", "msg": format!("Blad VPN: {e}")})),
            }
        }
        "vpn_verify" => {
            let geo = vpn::ip_geo();
            match geo {
                Some((ip, c, isp)) => emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("Publiczne IP: {ip} ({c}, {isp})")})),
                None => emit(&proxy, json!({"type": "log", "level": "warn", "msg": "Nie udalo sie pobrac publicznego IP."})),
            }
        }
        _ => {}
    }
}

/// Pelny pipeline jednym przyciskiem.
fn run_full(state: Arc<Mutex<AppState>>, proxy: EventLoopProxy<UserEvent>) {
    {
        let mut s = state.lock().unwrap();
        if s.busy {
            return;
        }
        s.busy = true;
    }
    emit(&proxy, json!({"type": "scan_start"}));
    emit(&proxy, json!({"type": "log", "level": "info", "msg": "== KONTROLE SYSTEMU =="}));

    // 1. Kontrole bezpieczenstwa
    emit(&proxy, json!({"type": "phase", "phase": "security", "label": "Kontrole systemu"}));
    let p = proxy.clone();
    let checks = security::run_all(&|c: security::Check| emit(&p, json!({"type": "check", "check": c})));
    let score = risk_from_checks(&checks);
    state.lock().unwrap().last_security = checks.clone();
    emit(&proxy, json!({"type": "security_done", "score": score, "count": checks.len()}));

    // 2. VPN
    emit(&proxy, json!({"type": "phase", "phase": "vpn", "label": "Wykrywanie VPN"}));
    emit(&proxy, json!({"type": "log", "level": "info", "msg": "== VPN =="}));
    let vpn_state = vpn::detect();
    let vtools = vpn::tools();
    let geo = vpn::ip_geo();
    state.lock().unwrap().last_vpn = Some(vpn_state.clone());
    let geo_json = match &geo {
        Some((ip, country, isp)) => json!({"ip": ip, "country": country, "isp": isp}),
        None => Value::Null,
    };
    emit(&proxy, json!({"type": "vpn", "vpn": vpn_state, "tools": vtools, "geo": geo_json}));

    // 3. Skan katalogow
    emit(&proxy, json!({"type": "phase", "phase": "scan", "label": "Skan katalogow"}));
    emit(&proxy, json!({"type": "log", "level": "info", "msg": "== SKAN KATALOGOW =="}));
    let dirs = scanner::default_dirs();
    let p2 = proxy.clone();
    let report = scanner::scan(&dirs, 60000, 4, &|n: usize, path: &str| {
        emit(&p2, json!({"type": "scan_progress", "count": n, "path": path}));
    });
    state.lock().unwrap().last_scan = Some(report.clone());
    emit(&proxy, json!({"type": "scan_done", "report": report}));

    // 4. Panel AI
    let (settings, rep) = {
        let s = state.lock().unwrap();
        (s.settings.clone(), build_report(&s))
    };
    if settings.panel.is_empty() {
        emit(&proxy, json!({"type": "log", "level": "warn", "msg": "== AI: pominieto (brak wybranych modeli) =="}));
    } else {
        emit(&proxy, json!({"type": "phase", "phase": "ai", "label": "Analiza AI"}));
        emit(&proxy, json!({"type": "log", "level": "info", "msg": format!("== AI: {} modeli ==", settings.panel.len())}));
        emit(&proxy, json!({"type": "ai_start", "models": settings.panel.clone()}));
        let p3 = proxy.clone();
        let agg = ai::analyze(&settings, &rep, &|r: ai::AiModelResult| {
            emit(&p3, json!({"type": "ai_model", "result": r}));
        });
        emit(&proxy, json!({"type": "ai_done", "agg": agg}));
    }

    state.lock().unwrap().busy = false;
    emit(&proxy, json!({"type": "log", "level": "ok", "msg": "== SKANOWANIE ZAKONCZONE =="}));
    emit(&proxy, json!({"type": "done"}));
}

/// Lista kluczy z maskowaniem (tylko 4 ostatnie znaki) - indeks 0 = aktywny klucz.
fn mask_keys(s: &ai::AiSettings) -> Vec<Value> {
    let mut out = vec![json!({
        "index": 0,
        "masked": mask_key(&s.api_key),
        "builtin": true
    })];
    for (i, k) in s.alt_keys.iter().enumerate() {
        out.push(json!({
            "index": i as i64 + 1,
            "masked": mask_key(k),
            "builtin": false
        }));
    }
    out
}

fn mask_key(k: &str) -> String {
    let t = k.trim();
    if t.is_empty() {
        return "(brak klucza)".into();
    }
    if t.len() <= 10 {
        return format!("{t}");
    }
    format!("{}...{}", &t[..6], &t[t.len() - 4..])
}

/// Prywatnosc: usuwa pozostalosci poprzednich raportow (dane o uzytkowniku).
/// Wywolywane przy kazdym uruchomieniu programu.
fn privacy_wipe() -> usize {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(d) = dirs::download_dir() {
        dirs.push(d);
    }
    if let Some(d) = dirs::desktop_dir() {
        dirs.push(d);
    }
    if let Some(d) = dirs::document_dir() {
        dirs.push(d);
    }
    dirs.push(std::env::temp_dir());
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent() {
            dirs.push(p.to_path_buf());
        }
    }
    let mut removed = 0usize;
    for d in dirs {
        let rd = match std::fs::read_dir(&d) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if name.starts_with("tznsecvirus_") || name.starts_with("tznsecvirus-report") {
                if std::fs::remove_file(&p).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

/// Rozwija %ZMIENNE% oraz ~ w podanej sciezce.
fn expand_env(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '%' {
            if let Some(pos) = chars[i + 1..].iter().position(|&c| c == '%') {
                let name: String = chars[i + 1..i + 1 + pos].iter().collect();
                if !name.is_empty() {
                    if let Ok(val) = std::env::var(&name) {
                        out.push_str(&val);
                        i = i + pos + 2;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    if out == "~" || out.starts_with("~/") || out.starts_with("~\\") {
        if let Some(h) = dirs::home_dir() {
            let rest: String = out.chars().skip(1).collect();
            return format!("{}{}", h.display(), rest);
        }
    }
    out
}

fn build_report(s: &AppState) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("host".into(), json!(std::env::var("COMPUTERNAME").unwrap_or_default()));
    obj.insert("user".into(), json!(std::env::var("USERNAME").unwrap_or_default()));
    obj.insert(
        "security".into(),
        serde_json::to_value(&s.last_security).unwrap_or(Value::Null),
    );
    obj.insert("vpn".into(), serde_json::to_value(&s.last_vpn).unwrap_or(Value::Null));
    if let Some(scan) = &s.last_scan {
        obj.insert(
            "scan_summary".into(),
            json!({
                "scanned_files": scan.scanned_files,
                "high": scan.high,
                "medium": scan.medium,
                "low": scan.low,
                "dirs": scan.dirs,
                "elapsed_ms": scan.elapsed_ms,
            }),
        );
        let top: Vec<&scanner::Finding> = scan.findings.iter().take(40).collect();
        obj.insert("findings".into(), serde_json::to_value(&top).unwrap_or(Value::Null));
    }
    serde_json::to_string_pretty(&Value::Object(obj)).unwrap_or_else(|_| "{}".into())
}

fn print_help() {
    println!("TZNSECVIRUS - pelne skanowanie bezpieczenstwa komputera z analiza AI (Rust + WebView)");
    println!();
    println!("Uzycie:");
    println!("  tznsecvirus              uruchamia aplikacje z interfejsem graficznym");
    println!("  tznsecvirus run          jw. (alias po instalacji przez winget)");
    println!("  tznsecvirus --selftest    tryb tekstowy: kontrole + VPN + skan + AI, bez okna");
    println!("  tznsecvirus --selftest --no-ai   bez zapytan do modeli AI");
    println!("  tznsecvirus --models      lista dostepnych dostawcow AI");
    println!("  tznsecvirus --help        ta pomoc");
}

/// Tryb weryfikacji bez interfejsu graficznego - drukuje wyniki wszystkich modulow.
fn selftest(with_ai: bool) {
    println!("=== TZNSECVIRUS SELFTEST ===");

    println!("[1/4] Kontrole bezpieczenstwa systemu...");
    let checks = security::run_all(&|c: security::Check| {
        println!("    {:>5}  {}", c.status.to_uppercase(), c.name);
        println!("           {}", c.detail);
    });
    println!(
        "  -> {} kontroli, indeks ryzyka konfiguracji: {}/100",
        checks.len(),
        risk_from_checks(&checks)
    );

    println!("[2/4] Wykrywanie VPN...");
    let v = vpn::detect();
    println!("  adaptery: {}", v.adapters.len());
    for a in &v.adapters {
        println!("    - {} [{}] {}", a.name, a.status, a.desc);
    }
    println!("  profile: {}", v.profiles.len());
    for p in &v.profiles {
        println!("    - ({}) {} -> {}", p.kind, p.name, p.path);
    }
    println!("  narzedzia: {:?}", vpn::tools());
    println!("  admin: {} | {}", v.admin, v.note);

    println!("[3/4] Skan niebezpiecznych katalogow...");
    let dirs = scanner::default_dirs();
    println!("  katalogi ({}):", dirs.len());
    for d in &dirs {
        println!("    - {}", d.display());
    }
    let report = scanner::scan(&dirs, 12000, 4, &|n: usize, p: &str| {
        if n % 3000 == 0 {
            println!("    ... {n} plikow ({p})");
        }
    });
    println!(
        "  przeskanowano: {} plikow w {} ms | {} wysokich, {} srednich, {} niskich",
        report.scanned_files, report.elapsed_ms, report.high, report.medium, report.low
    );
    for f in report.findings.iter().take(12) {
        println!("    [{:>6}] {} ({} kB)", f.severity, f.path, f.size / 1024);
        println!("             {}", f.reasons.join("; "));
    }

    println!("[4/4] Panel AI (xkiro, darmowe modele)...");
    let settings = ai::AiSettings::default();
    let st = AppState {
        settings: settings.clone(),
        last_security: checks.clone(),
        last_scan: Some(report.clone()),
        last_vpn: Some(v.clone()),
        chat: Vec::new(),
        busy: false,
    };
    let report_json = build_report(&st);
    println!("  rozmiar raportu: {} bajtow", report_json.len());

    if !with_ai {
        println!("  (pominieto zapytania AI - uzyto --no-ai)");
        println!("=== KONIEC SELFTEST ===");
        return;
    }

    println!("  modele w panelu: {}", settings.panel.len());
    let agg = ai::analyze(&settings, &report_json, &|r: ai::AiModelResult| {
        if r.ok {
            println!("    OK  {:<40} -> ryzyko {:?} {}", r.model, r.risk, r.verdict);
        } else {
            println!("    ERR {:<40} -> {}", r.model, r.error);
        }
    });
    println!(
        "  KONSENSUS: {} (srednia {:.1}, min {}, max {}, OK {}/{})",
        agg.consensus, agg.risk_avg, agg.risk_min, agg.risk_max, agg.ok, agg.total
    );
    for f in &agg.findings {
        println!("    * {f}");
    }
    for r in &agg.recommendations {
        println!("    -> {r}");
    }
    println!("=== KONIEC SELFTEST ===");
}