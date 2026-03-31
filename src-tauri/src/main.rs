// CernisPro - Tauri v2
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Manager, WindowEvent};

const BACKEND_PORT: u16 = 8765;
const BACKEND_URL: &str = "http://127.0.0.1:8765";
const STARTUP_TIMEOUT_SECS: u64 = 45;
const LOG_FILE: &str = "/tmp/cernis-backend.log";

fn log(msg: &str) {
    let timestamp = chrono_lite();
    let line = format!("[{}] {}\n", timestamp, msg);
    eprint!("{}", line);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn chrono_lite() -> String {
    // Simple timestamp without chrono dependency
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

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

    log(&format!("Looking for backend binary '{}'", bin_name));
    log(&format!("Executable dir: {:?}", dir));

    for path in &candidates {
        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        log(&format!("  Checking: {:?} → exists={}", resolved, resolved.exists()));
        if resolved.exists() {
            log(&format!("  Found backend: {:?}", resolved));
            return Some(resolved);
        }
    }
    log("ERROR: Backend binary not found in any candidate path!");
    None
}

fn kill_stale_backend() {
    // Check if something is already listening on the backend port.
    // If so, kill it — it's a leftover from a previous run.
    match std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", BACKEND_PORT).parse().unwrap(),
        Duration::from_millis(500),
    ) {
        Ok(_) => {
            log(&format!(
                "Port {} already in use — killing stale process",
                BACKEND_PORT
            ));
            #[cfg(unix)]
            {
                // Use fuser to find and kill the process holding the port
                let _ = Command::new("fuser")
                    .args(["-k", &format!("{}/tcp", BACKEND_PORT)])
                    .output();
                thread::sleep(Duration::from_millis(500));
            }
        }
        Err(_) => {
            log(&format!("Port {} is free", BACKEND_PORT));
        }
    }
}

fn start_backend() -> Option<Child> {
    kill_stale_backend();

    let backend = match find_backend_exe() {
        Some(p) => p,
        None => {
            log("ERROR: Cannot start backend — binary not found");
            return None;
        }
    };

    let data_dir = dirs::data_dir().unwrap_or_default().join("CernisPro");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log(&format!("WARN: Could not create data dir {:?}: {}", data_dir, e));
    }
    log(&format!("Data dir: {:?}", data_dir));

    // Open log file for backend stdout/stderr
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .ok();
    let stderr_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .ok();

    let mut cmd = Command::new(&backend);
    cmd.env("CERNIS_PORT", BACKEND_PORT.to_string())
        .env("CERNIS_DATA_DIR", data_dir.to_string_lossy().to_string());

    // Redirect backend output to log file
    if let Some(f) = stdout_file {
        cmd.stdout(Stdio::from(f));
    }
    if let Some(f) = stderr_file {
        cmd.stderr(Stdio::from(f));
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }

    log(&format!("Starting backend: {:?}", backend));
    match cmd.spawn() {
        Ok(child) => {
            log(&format!("Backend process started (PID {})", child.id()));
            Some(child)
        }
        Err(e) => {
            log(&format!("ERROR: Failed to spawn backend: {}", e));
            None
        }
    }
}

fn wait_for_backend(child: &mut Option<Child>) -> bool {
    let start = Instant::now();
    let url = format!("{}/api/status", BACKEND_URL);
    let mut attempts = 0;

    log(&format!(
        "Waiting for backend at {} (timeout {}s)...",
        url, STARTUP_TIMEOUT_SECS
    ));

    while start.elapsed().as_secs() < STARTUP_TIMEOUT_SECS {
        attempts += 1;

        // Check if process is still alive
        if let Some(ref mut c) = child {
            match c.try_wait() {
                Ok(Some(status)) => {
                    log(&format!(
                        "ERROR: Backend process exited prematurely with status: {}",
                        status
                    ));
                    log(&format!("Check {} for details", LOG_FILE));
                    return false;
                }
                Ok(None) => {} // still running, good
                Err(e) => {
                    log(&format!("WARN: Could not check process status: {}", e));
                }
            }
        }

        // Try to reach the backend
        match ureq::get(&url).call() {
            Ok(r) if r.status() == 200 => {
                // Verify our process survived (not a stale leftover answering)
                thread::sleep(Duration::from_millis(500));
                if let Some(ref mut c) = child {
                    match c.try_wait() {
                        Ok(Some(status)) => {
                            log(&format!(
                                "ERROR: Backend died right after responding (port conflict?): {}",
                                status
                            ));
                            return false;
                        }
                        _ => {}
                    }
                }
                let elapsed = start.elapsed().as_millis();
                log(&format!(
                    "Backend ready after {}ms ({} attempts)",
                    elapsed, attempts
                ));
                return true;
            }
            Ok(r) => {
                log(&format!(
                    "  Attempt {}: HTTP {} (not ready yet)",
                    attempts,
                    r.status()
                ));
            }
            Err(_) => {
                if attempts % 10 == 0 {
                    log(&format!(
                        "  Attempt {}: not reachable ({}s elapsed)",
                        attempts,
                        start.elapsed().as_secs()
                    ));
                }
            }
        }
        thread::sleep(Duration::from_millis(300));
    }

    log(&format!(
        "ERROR: Backend did not respond within {}s ({} attempts). Giving up.",
        STARTUP_TIMEOUT_SECS, attempts
    ));
    log(&format!("Check {} for backend errors", LOG_FILE));
    false
}

fn main() {
    // Clear previous log
    let _ = std::fs::write(LOG_FILE, "");
    log("=== CERNIS PRO starting ===");

    let mut child = start_backend();
    let backend_ok = wait_for_backend(&mut child);

    if !backend_ok {
        log("WARNING: Opening window despite backend failure — user will see error page");
    }

    let backend_process = Arc::new(Mutex::new(child));
    let backend_cleanup = Arc::clone(&backend_process);

    tauri::Builder::default()
        .manage(BackendProcess(backend_process))
        .on_window_event(move |_window, event| {
            if let WindowEvent::Destroyed = event {
                log("Window destroyed — killing backend");
                if let Ok(mut g) = backend_cleanup.lock() {
                    if let Some(mut c) = g.take() {
                        let _ = c.kill();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error running app");
}

struct BackendProcess(Arc<Mutex<Option<Child>>>);
