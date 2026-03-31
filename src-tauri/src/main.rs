// CernisPro - Tauri v2
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{Manager, WindowEvent};

const BACKEND_PORT: u16 = 8765;
const BACKEND_URL:  &str = "http://127.0.0.1:8765";
const STARTUP_TIMEOUT_SECS: u64 = 30;

struct BackendProcess(Arc<Mutex<Option<Child>>>);

fn find_backend_exe() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let bin_name = if cfg!(target_os = "windows") {
        "cernis-backend.exe"
    } else {
        "cernis-backend"
    };
    let candidates: Vec<std::path::PathBuf> = vec![
        dir.join(bin_name),
        dir.join("resources").join(bin_name),
        std::path::PathBuf::from("/usr/bin").join(bin_name),
        dir.join("..").join(bin_name),
    ];
    for path in &candidates {
        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        if resolved.exists() { return Some(resolved); }
    }
    None
}

fn start_backend() -> Option<Child> {
    let backend = find_backend_exe()?;
    let data_dir = dirs::data_dir().unwrap_or_default().join("CernisPro");
    std::fs::create_dir_all(&data_dir).ok();
    let mut cmd = Command::new(&backend);
    cmd.env("CERNIS_PORT", BACKEND_PORT.to_string())
       .env("CERNIS_DATA_DIR", data_dir.to_string_lossy().to_string());
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    cmd.spawn().ok()
}

fn wait_for_backend() -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < STARTUP_TIMEOUT_SECS {
        if let Ok(r) = ureq::get(&format!("{}/api/status", BACKEND_URL)).call() {
            if r.status() == 200 { return true; }
        }
        thread::sleep(Duration::from_millis(300));
    }
    false
}

fn main() {
    // Backend starten und warten BEVOR das Fenster geöffnet wird.
    // tauri.conf.json url = "http://127.0.0.1:8765" — Fenster lädt direkt.
    let child = start_backend();
    wait_for_backend();

    let backend_process = Arc::new(Mutex::new(child));
    let backend_cleanup = Arc::clone(&backend_process);

    tauri::Builder::default()
        .manage(BackendProcess(backend_process))
        .on_window_event(move |_window, event| {
            if let WindowEvent::Destroyed = event {
                if let Ok(mut g) = backend_cleanup.lock() {
                    if let Some(mut c) = g.take() { c.kill().ok(); }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error running app");
}
