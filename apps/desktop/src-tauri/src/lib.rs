use std::fs;
use std::path::PathBuf;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    Emitter, Manager, WindowEvent,
};

// ─── Config helpers ──────────────────────────────────────────────────────────

fn config_dir() -> PathBuf {
    let home = dirs_next();
    home.join(".config").join("pyhall")
}

fn dirs_next() -> PathBuf {
    // $HOME fallback
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn enrolled_dir() -> PathBuf {
    config_dir().join("enrolled")
}

fn config_file() -> PathBuf {
    config_dir().join("config.json")
}

fn ensure_dirs() {
    let _ = fs::create_dir_all(config_dir());
    let _ = fs::create_dir_all(enrolled_dir());
}

// ─── Default config ───────────────────────────────────────────────────────────

fn default_config() -> serde_json::Value {
    serde_json::json!({
        "hall_url": "http://localhost:8765",
        "poll_interval": 3,
        "auth_token": null,
        "default_profile": "prof.dev.permissive",
        "notifications": {
            "hall_offline": true,
            "worker_failure": true,
            "steward_hold": true,
            "every_denial": false
        },
        "display": {
            "tray_on_minimize": true,
            "launch_at_login": false,
            "feed_max_rows": 500
        }
    })
}

// ─── Tauri commands ───────────────────────────────────────────────────────────

/// Poll the Hall server health endpoint.
/// Returns live data or offline mock if request fails.
#[tauri::command]
async fn get_hall_status(url: String) -> Result<serde_json::Value, String> {
    let target = format!("{}/api/health", url.trim_end_matches('/'));
    match reqwest::get(&target).await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(data) => Ok(serde_json::json!({
                        "online": true,
                        "url": url,
                        "version": data.get("version").cloned().unwrap_or(serde_json::Value::Null),
                        "workers": data.get("workers").cloned().unwrap_or(serde_json::json!(0)),
                        "dispatches_today": data.get("dispatches_today").cloned().unwrap_or(serde_json::json!(0)),
                        "refusals_today": data.get("refusals_today").cloned().unwrap_or(serde_json::json!(0)),
                        "uptime_seconds": data.get("uptime_seconds").cloned().unwrap_or(serde_json::json!(0)),
                        "rules_loaded": data.get("rules_loaded").cloned().unwrap_or(serde_json::json!(0)),
                        "profile": data.get("profile").cloned().unwrap_or(serde_json::Value::Null),
                        "latency_ms": data.get("latency_ms").cloned().unwrap_or(serde_json::json!(null))
                    })),
                    Err(e) => Err(format!("Parse error: {}", e)),
                }
            } else {
                Ok(serde_json::json!({ "online": false, "url": url, "error": resp.status().as_u16() }))
            }
        }
        Err(_) => Ok(serde_json::json!({ "online": false, "url": url })),
    }
}

/// Get recent dispatch events from Hall telemetry endpoint.
/// Returns mock feed rows if server unreachable.
#[tauri::command]
async fn get_dispatch_feed(url: String, limit: u32) -> Result<serde_json::Value, String> {
    let target = format!("{}/api/dispatches/recent?n={}", url.trim_end_matches('/'), limit);
    match reqwest::get(&target).await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(serde_json::json!({ "events": [], "source": "server_error" }))
            }
        }
        Err(_) => Ok(serde_json::json!({ "events": [], "source": "offline" })),
    }
}

/// Get active dispatches from Hall.
#[tauri::command]
async fn get_active_dispatches(url: String) -> Result<serde_json::Value, String> {
    let target = format!("{}/api/dispatches/active", url.trim_end_matches('/'));
    match reqwest::get(&target).await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(serde_json::json!({ "active": [], "source": "server_error" }))
            }
        }
        Err(_) => Ok(serde_json::json!({ "active": [], "source": "offline" })),
    }
}

/// Get enrolled workers from Hall server.
#[tauri::command]
async fn get_workers(url: String) -> Result<serde_json::Value, String> {
    let target = format!("{}/api/workers", url.trim_end_matches('/'));
    match reqwest::get(&target).await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(serde_json::json!({ "workers": [], "source": "server_error" }))
            }
        }
        Err(_) => Ok(serde_json::json!({ "workers": [], "source": "offline" })),
    }
}

/// Get active alerts from Hall.
#[tauri::command]
async fn get_alerts(url: String) -> Result<serde_json::Value, String> {
    let target = format!("{}/api/alerts", url.trim_end_matches('/'));
    match reqwest::get(&target).await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("Parse error: {}", e))
            } else {
                Ok(serde_json::json!({ "alerts": [], "source": "server_error" }))
            }
        }
        Err(_) => Ok(serde_json::json!({ "alerts": [], "source": "offline" })),
    }
}

/// Enroll a worker by saving its registry_record.json to the local enrolled dir.
#[tauri::command]
fn enroll_worker(record_json: String) -> Result<bool, String> {
    ensure_dirs();

    // Parse to validate JSON and extract species_id
    let record: serde_json::Value = serde_json::from_str(&record_json)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let species_id = record
        .get("species_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required field: species_id".to_string())?;

    // Sanitize species_id for use as filename
    let safe_name: String = species_id
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();

    let file_path = enrolled_dir().join(format!("{}.json", safe_name));
    fs::write(&file_path, &record_json).map_err(|e| format!("Write failed: {}", e))?;

    Ok(true)
}

/// List locally enrolled workers from $HOME/.config/pyhall/enrolled/
#[tauri::command]
fn list_enrolled_workers() -> Result<serde_json::Value, String> {
    ensure_dirs();

    let dir = enrolled_dir();
    let mut workers: Vec<serde_json::Value> = Vec::new();

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(record) = serde_json::from_str::<serde_json::Value>(&content) {
                        workers.push(record);
                    }
                }
            }
        }
    }

    Ok(serde_json::json!({ "workers": workers, "source": "local" }))
}

/// Read app config from $HOME/.config/pyhall/config.json
#[tauri::command]
fn read_config() -> serde_json::Value {
    ensure_dirs();

    let path = config_file();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                return config;
            }
        }
    }
    default_config()
}

/// Save app config to $HOME/.config/pyhall/config.json
#[tauri::command]
fn save_config(config: serde_json::Value) -> Result<bool, String> {
    ensure_dirs();

    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Serialize error: {}", e))?;

    fs::write(config_file(), content).map_err(|e| format!("Write failed: {}", e))?;
    Ok(true)
}

/// Validate a registry_record.json before enrollment
#[tauri::command]
fn validate_registry_record(record_json: String) -> Result<serde_json::Value, String> {
    let record: serde_json::Value = serde_json::from_str(&record_json)
        .map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut valid = true;

    // Check species_id
    if let Some(sid) = record.get("species_id").and_then(|v| v.as_str()) {
        let sid_valid = sid.starts_with("wrk.");
        checks.push(serde_json::json!({
            "field": "species_id",
            "ok": sid_valid,
            "message": if sid_valid { "Species ID format valid" } else { "Species ID must start with 'wrk.'" }
        }));
        if !sid_valid { valid = false; }
    } else {
        checks.push(serde_json::json!({
            "field": "species_id",
            "ok": false,
            "message": "Missing required field: species_id"
        }));
        valid = false;
    }

    // Check capabilities
    if let Some(caps) = record.get("capabilities") {
        let has_caps = caps.as_array().map(|a| !a.is_empty()).unwrap_or(false);
        checks.push(serde_json::json!({
            "field": "capabilities",
            "ok": has_caps,
            "message": if has_caps { "Capabilities declared" } else { "No capabilities declared" }
        }));
        if !has_caps { valid = false; }
    } else {
        checks.push(serde_json::json!({
            "field": "capabilities",
            "ok": false,
            "message": "Missing required field: capabilities"
        }));
        valid = false;
    }

    // Check blast_score bounds
    if let Some(score) = record.get("blast_score").and_then(|v| v.as_f64()) {
        let in_bounds = score >= 0.0 && score <= 100.0;
        checks.push(serde_json::json!({
            "field": "blast_score",
            "ok": in_bounds,
            "message": if in_bounds { format!("Blast score in bounds ({}/100)", score as u32) } else { "Blast score must be 0–100".to_string() }
        }));
        if !in_bounds { valid = false; }
    } else {
        checks.push(serde_json::json!({
            "field": "blast_score",
            "ok": false,
            "message": "Missing or invalid blast_score (required, 0–100)"
        }));
        valid = false;
    }

    // Check guarantee field
    if let Some(g) = record.get("guarantee").and_then(|v| v.as_str()) {
        let valid_g = matches!(g, "best-effort" | "at-least-once" | "exactly-once");
        checks.push(serde_json::json!({
            "field": "guarantee",
            "ok": valid_g,
            "message": if valid_g { format!("Guarantee '{}' is valid", g) } else { "Guarantee must be: best-effort | at-least-once | exactly-once".to_string() }
        }));
        if !valid_g { valid = false; }
    } else {
        checks.push(serde_json::json!({
            "field": "guarantee",
            "ok": false,
            "message": "Missing required field: guarantee"
        }));
        valid = false;
    }

    // Warn if no dlq_handler
    let has_dlq = record.get("dlq_handler").is_some();
    checks.push(serde_json::json!({
        "field": "dlq_handler",
        "ok": true,
        "warning": !has_dlq,
        "message": if has_dlq { "DLQ handler declared" } else { "WARNING: No DLQ handler declared (recommended for production workers)" }
    }));

    Ok(serde_json::json!({
        "valid": valid,
        "checks": checks,
        "record": record
    }))
}

// ─── App entry ────────────────────────────────────────────────────────────────

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Build tray menu
            let show = MenuItemBuilder::with_id("show", "Open Dashboard").build(app)?;
            let feed = MenuItemBuilder::with_id("feed", "Live Feed").build(app)?;
            let crew = MenuItemBuilder::with_id("crew", "Crew on Books").build(app)?;
            let alerts = MenuItemBuilder::with_id("alerts", "Alerts").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&show)
                .separator()
                .item(&feed)
                .item(&crew)
                .item(&alerts)
                .separator()
                .item(&quit)
                .build()?;

            let icon = Image::from_path("icons/icon.png")
                .or_else(|_| Image::from_path("src-tauri/icons/icon.png"))
                .unwrap_or_else(|_| {
                    Image::from_bytes(include_bytes!("../icons/32x32.png")).unwrap()
                });

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&menu)
                .tooltip("pyhall — Hall Monitor")
                .on_menu_event(move |app, event| {
                    let id = event.id().as_ref();
                    match id {
                        "show" | "feed" | "crew" | "alerts" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                                // Emit nav event for frontend to handle
                                let screen = match id {
                                    "feed" => "feed",
                                    "crew" => "crew",
                                    "alerts" => "alerts",
                                    _ => "status",
                                };
                                let _ = w.emit("navigate", screen);
                            }
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_hall_status,
            get_dispatch_feed,
            get_active_dispatches,
            get_workers,
            get_alerts,
            enroll_worker,
            list_enrolled_workers,
            read_config,
            save_config,
            validate_registry_record,
        ])
        .run(tauri::generate_context!())
        .expect("error while running pyhall desktop");
}
