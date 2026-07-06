// CernisPro - Tauri v2
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tauri::path::BaseDirectory;
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const BACKEND_PORT: u16 = 8765;
const BACKEND_URL: &str = "http://127.0.0.1:8765";
const STARTUP_TIMEOUT_SECS: u64 = 45;

/// Ergebnis des Backend-Starts: entweder bereit oder ein kategorisierter
/// Fehlercode (E-1xx), den der Ladebildschirm menschenlesbar anzeigt.
enum BackendStatus {
    Ready,
    /// Port 8765 belegt, aber kein sauberer 200 (Fremdprozess).
    Error101,
    /// Backend-Prozess vorzeitig beendet.
    Error102,
    /// Timeout ohne Prozess-Exit.
    Error103,
    /// Backend-Binary nicht gefunden.
    Error104,
}

impl BackendStatus {
    /// Fehlercode-String fuers Splash-Fenster (leer, wenn bereit).
    fn code(&self) -> &'static str {
        match self {
            BackendStatus::Ready => "",
            BackendStatus::Error101 => "E-101",
            BackendStatus::Error102 => "E-102",
            BackendStatus::Error103 => "E-103",
            BackendStatus::Error104 => "E-104",
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self, BackendStatus::Ready)
    }
}

/// Pfad der Startup-Status-Datei im temp_dir. Der Splash pollt diese Datei
/// (plugin-frei, ohne withGlobalTauri), main.rs schreibt sie nach dem Warten.
fn startup_status_path() -> &'static str {
    static STATUS_PATH: OnceLock<String> = OnceLock::new();
    STATUS_PATH.get_or_init(|| {
        std::env::temp_dir()
            .join("cernis-startup.json")
            .to_string_lossy()
            .into_owned()
    })
}

/// Schreibt {"ready":bool,"code":string} in die Startup-Status-Datei.
/// Der Ladebildschirm pollt sie als primaeren Signalweg.
fn write_startup_status(status: &BackendStatus) {
    let json = format!(
        "{{\"ready\":{},\"code\":\"{}\"}}",
        status.is_ready(),
        status.code()
    );
    match std::fs::write(startup_status_path(), &json) {
        Ok(_) => log(&format!("Startup-Status geschrieben: {}", json)),
        Err(e) => log(&format!("WARN: Startup-Status nicht schreibbar: {}", e)),
    }
}

fn log_path() -> &'static str {
    static LOG_PATH: OnceLock<String> = OnceLock::new();
    LOG_PATH.get_or_init(|| {
        std::env::temp_dir()
            .join("cernis-backend.log")
            .to_string_lossy()
            .into_owned()
    })
}

fn log(msg: &str) {
    let timestamp = chrono_lite();
    let line = format!("[{}] {}\n", timestamp, msg);
    eprint!("{}", line);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path()) {
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
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                // Find PID holding the port via netstat, then taskkill the tree
                if let Ok(out) = Command::new("netstat")
                    .args(["-ano", "-p", "TCP"])
                    .creation_flags(0x08000000)
                    .output()
                {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        if line.contains(&format!(":{}", BACKEND_PORT))
                            && line.contains("LISTENING")
                        {
                            if let Some(pid_str) = line.split_whitespace().last() {
                                log(&format!("  Killing stale PID {}", pid_str));
                                let _ = Command::new("taskkill")
                                    .args(["/F", "/T", "/PID", pid_str])
                                    .creation_flags(0x08000000)
                                    .output();
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
        Err(_) => {
            log(&format!("Port {} is free", BACKEND_PORT));
        }
    }
}

fn start_backend() -> Result<Child, BackendStatus> {
    kill_stale_backend();

    let backend = match find_backend_exe() {
        Some(p) => p,
        None => {
            log("ERROR: Cannot start backend — binary not found");
            // Backend-Binary nicht gefunden -> E-104.
            return Err(BackendStatus::Error104);
        }
    };

    let data_dir = dirs::data_dir().unwrap_or_default().join("cernis-pro");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log(&format!("WARN: Could not create data dir {:?}: {}", data_dir, e));
    }
    log(&format!("Data dir: {:?}", data_dir));

    // Open log file for backend stdout/stderr
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
        .ok();
    let stderr_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
        .ok();

    let mut cmd = Command::new(&backend);
    cmd.env("CERNIS_PORT", BACKEND_PORT.to_string())
        .env("CERNIS_DATA_DIR", data_dir.to_string_lossy().to_string());

    // Start in own process group so we can kill the entire tree on exit
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

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
            Ok(child)
        }
        Err(e) => {
            log(&format!("ERROR: Failed to spawn backend: {}", e));
            // Binary vorhanden, laesst sich aber nicht starten -> wie vorzeitiger
            // Prozess-Abbruch behandeln (E-102).
            Err(BackendStatus::Error102)
        }
    }
}

/// Prueft, ob auf dem Backend-Port ueberhaupt etwas lauscht (TCP-Connect).
/// Dient beim Timeout der Unterscheidung E-101 (Fremdprozess belegt Port)
/// vs. E-103 (niemand da / unser Prozess haengt).
fn port_belegt() -> bool {
    matches!(
        std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", BACKEND_PORT).parse().unwrap(),
            Duration::from_millis(500),
        ),
        Ok(_)
    )
}

/// Kurz-lockender Exit-Check auf dem geteilten Child. Gibt Some(true) zurueck,
/// wenn der Prozess beendet ist, Some(false) wenn er laeuft, None wenn kein
/// Child (mehr) vorhanden ist. Der Lock wird nur fuer die Dauer des try_wait
/// gehalten — nie ueber Netzwerk-Wartezeiten —, damit ein paralleles
/// kill_backend_tree beim Fenster-Schliessen nicht blockiert (kein Deadlock).
fn child_exited(process: &Arc<Mutex<Option<Child>>>) -> Option<bool> {
    let mut guard = process.lock().ok()?;
    let child = guard.as_mut()?;
    match child.try_wait() {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(e) => {
            log(&format!("WARN: Could not check process status: {}", e));
            Some(false)
        }
    }
}

fn wait_for_backend(process: &Arc<Mutex<Option<Child>>>) -> BackendStatus {
    let start = Instant::now();
    let url = format!("{}/api/status", BACKEND_URL);
    let mut attempts = 0;

    log(&format!(
        "Waiting for backend at {} (timeout {}s)...",
        url, STARTUP_TIMEOUT_SECS
    ));

    while start.elapsed().as_secs() < STARTUP_TIMEOUT_SECS {
        attempts += 1;

        // Check if process is still alive (kurzer Lock)
        if child_exited(process) == Some(true) {
            log("ERROR: Backend process exited prematurely");
            log(&format!("Check {} for details", log_path()));
            // Backend-Prozess vorzeitig beendet -> E-102.
            return BackendStatus::Error102;
        }

        // Try to reach the backend
        match ureq::get(&url).call() {
            Ok(r) if r.status() == 200 => {
                // Verify our process survived (not a stale leftover answering)
                thread::sleep(Duration::from_millis(500));
                if child_exited(process) == Some(true) {
                    log("ERROR: Backend died right after responding (port conflict?)");
                    // Sauberer 200 kam von einem Fremdprozess, unser Backend
                    // ist danach gestorben -> Port belegt -> E-101.
                    return BackendStatus::Error101;
                }
                let elapsed = start.elapsed().as_millis();
                log(&format!(
                    "Backend ready after {}ms ({} attempts)",
                    elapsed, attempts
                ));
                return BackendStatus::Ready;
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
    log(&format!("Check {} for backend errors", log_path()));

    // Timeout-Klassifikation: Lebt unser eigener Prozess noch, haengt also unser
    // Backend beim Start -> E-103. Ist unser Prozess weg/nie gestartet, aber der
    // Port ist dennoch belegt, haelt ihn ein Fremdprozess -> E-101.
    let eigener_prozess_lebt = child_exited(process) == Some(false);

    if !eigener_prozess_lebt && port_belegt() {
        log("Timeout: Port belegt, aber unser Prozess laeuft nicht -> E-101 (Fremdprozess)");
        BackendStatus::Error101
    } else {
        log("Timeout: kein sauberer 200, Prozess ohne Exit -> E-103 (Zeitueberschreitung)");
        BackendStatus::Error103
    }
}

fn detect_vm() -> Option<&'static str> {
    // 1. systemd-detect-virt (most reliable on Linux)
    if let Ok(out) = Command::new("systemd-detect-virt").output() {
        if out.status.success() {
            let virt = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            if virt != "none" && !virt.is_empty() {
                // Map to known hypervisors
                return match virt.as_str() {
                    "vmware" => Some("vmware"),
                    "oracle" | "virtualbox" => Some("virtualbox"),
                    "kvm" | "qemu" => Some("kvm"),
                    "microsoft" | "hyperv" => Some("hyperv"),
                    "xen" => Some("xen"),
                    _ => Some("unknown-vm"),
                };
            }
        }
    }

    // 2. Fallback: check DMI product name
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let p = product.trim().to_lowercase();
        if p.contains("vmware") { return Some("vmware"); }
        if p.contains("virtualbox") { return Some("virtualbox"); }
        if p.contains("kvm") || p.contains("qemu") { return Some("kvm"); }
        if p.contains("hyper-v") { return Some("hyperv"); }
    }

    None
}

fn get_webkit_version() -> (u32, u32) {
    // Try to read WebKit2GTK version from pkg-config or library
    if let Ok(out) = Command::new("pkg-config")
        .args(["--modversion", "webkit2gtk-4.1"])
        .output()
    {
        if out.status.success() {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let parts: Vec<&str> = ver.split('.').collect();
            if parts.len() >= 2 {
                let major = parts[0].parse().unwrap_or(0);
                let minor = parts[1].parse().unwrap_or(0);
                return (major, minor);
            }
        }
    }
    (0, 0)
}

fn get_distro() -> String {
    // Read /etc/os-release for distro identification
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(id) = line.strip_prefix("ID=") {
                return id.trim_matches('"').to_lowercase();
            }
        }
    }
    "unknown".to_string()
}

fn configure_rendering() {
    let vm = detect_vm();
    let (wk_major, wk_minor) = get_webkit_version();
    let distro = get_distro();

    log(&format!(
        "Environment: distro={}, vm={}, webkit={}.{}",
        distro,
        vm.unwrap_or("bare-metal"),
        wk_major, wk_minor
    ));

    // Decision matrix:
    // - Ubuntu + VM + WebKit >= 2.44: black screen confirmed → disable compositing
    // - Ubuntu + bare-metal: usually fine, but DMABUF can fail on some GPUs
    // - Debian + VM: works fine (older WebKit, different compositor defaults)
    // - Debian + bare-metal: works fine
    let need_sw_rendering = match (vm, distro.as_str()) {
        // Ubuntu in a VM with newer WebKit → always disable
        (Some(_), "ubuntu" | "pop" | "linuxmint") if wk_major >= 2 && wk_minor >= 44 => {
            log("→ Ubuntu VM with WebKit >= 2.44: disabling GPU compositing");
            true
        }
        // Any distro with very new WebKit in a VM → cautiously disable
        (Some(_), _) if wk_major >= 2 && wk_minor >= 46 => {
            log("→ VM with WebKit >= 2.46: disabling GPU compositing as precaution");
            true
        }
        // Bare metal but user explicitly requested software rendering
        _ if std::env::var("CERNIS_SOFTWARE_RENDER").is_ok() => {
            log("→ CERNIS_SOFTWARE_RENDER set: forcing software rendering");
            true
        }
        _ => {
            log("→ Hardware rendering (default)");
            false
        }
    };

    if need_sw_rendering {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        log("  Set WEBKIT_DISABLE_COMPOSITING_MODE=1");
        log("  Set WEBKIT_DISABLE_DMABUF_RENDERER=1");
    }
}

/// Lokale file://-URL des gebuendelten Splash-HTML. Wird im setup gesetzt und
/// beim Fenster-Schliessen wiederverwendet, um die Webview von der (dann toten)
/// Backend-URL wegzulenken -> kein rohes "Connection refused" beim Beenden.
fn splash_url() -> &'static OnceLock<String> {
    static SPLASH_URL: OnceLock<String> = OnceLock::new();
    &SPLASH_URL
}

fn main() {
    // Clear previous log
    let _ = std::fs::write(log_path(), "");
    log("=== CERNIS PRO starting ===");

    configure_rendering();

    // Startup-Status zuruecksetzen: bis der Hintergrund-Thread fertig ist, gilt
    // "noch nicht bereit". Der Splash pollt diese Datei.
    let _ = std::fs::remove_file(startup_status_path());

    // Der Backend-Prozess wird erst im Hintergrund-Thread gestartet und dort in
    // dieses Arc gelegt, damit kill_backend_tree ihn beim Beenden findet.
    let backend_process: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let backend_worker = Arc::clone(&backend_process);
    let backend_cleanup = Arc::clone(&backend_process);
    let backend_exit = Arc::clone(&backend_process);

    tauri::Builder::default()
        .manage(BackendProcess(Arc::clone(&backend_process)))
        .on_window_event(move |window, event| match event {
            // Beim Schliessen zuerst die Webview auf die lokale Splash lenken,
            // damit WebKit nicht mehr auf die gleich sterbende Backend-URL
            // zugreift (sonst rohes Connection-refused-Bild), DANN Backend killen.
            WindowEvent::CloseRequested { .. } => {
                // navigate() gibt es nur auf der WebviewWindow, nicht auf Window —
                // ueber den AppHandle beziehen.
                if let Some(url) = splash_url().get() {
                    if let (Some(webview), Ok(parsed)) = (
                        window.app_handle().get_webview_window("main"),
                        url.parse(),
                    ) {
                        let _ = webview.navigate(parsed);
                    }
                }
                kill_backend_tree(&backend_cleanup);
            }
            WindowEvent::Destroyed => {
                kill_backend_tree(&backend_cleanup);
            }
            _ => {}
        })
        .setup(move |app| {
            // Splash-HTML als gebuendelte Resource aufloesen -> lokale file://-URL.
            // So erscheint IMMER zuerst der Ladebildschirm, nie die rohe Backend-URL.
            let splash_path = app
                .path()
                .resolve("splash.html", BaseDirectory::Resource)?;
            let splash_file_url = format!("file://{}", splash_path.to_string_lossy());
            let _ = splash_url().set(splash_file_url.clone());
            log(&format!("Splash-Resource: {}", splash_file_url));

            let splash = splash_file_url
                .parse()
                .map(WebviewUrl::External)
                .unwrap_or_else(|_| WebviewUrl::App("splash.html".into()));

            WebviewWindowBuilder::new(app, "main", splash)
                .title("CERNIS PRO")
                .inner_size(1600.0, 900.0)
                .min_inner_size(1200.0, 700.0)
                .resizable(true)
                .center()
                .build()?;

            // Backend erst NACH dem Fenster starten und im Hintergrund abwarten,
            // damit der Splash sofort sichtbar ist. Ergebnis -> Status-Datei
            // (primaerer Signalweg, plugin-frei) + Tauri-Event an das Fenster.
            let app_handle = app.handle().clone();
            thread::spawn(move || {
                let status = match start_backend() {
                    Ok(child) => {
                        // Child ins geteilte Arc legen, damit er beim Beenden
                        // sauber gekillt werden kann. wait_for_backend lockt das
                        // Arc nur kurz pro Exit-Check (kein Deadlock beim Kill).
                        if let Ok(mut guard) = backend_worker.lock() {
                            *guard = Some(child);
                        }
                        wait_for_backend(&backend_worker)
                    }
                    Err(status) => status,
                };

                write_startup_status(&status);

                if status.is_ready() {
                    log("Backend bereit -> Event 'backend-ready'");
                    let _ = app_handle.emit("backend-ready", ());
                } else {
                    log(&format!("Backend-Fehler {} -> Event 'backend-error'", status.code()));
                    let _ = app_handle.emit("backend-error", status.code());
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running app");

    // App exited (window closed, signal, etc.) — ensure backend is dead
    kill_backend_tree(&backend_exit);
}

fn kill_backend_tree(process: &Arc<Mutex<Option<Child>>>) {
    if let Ok(mut guard) = process.lock() {
        if let Some(ref mut child) = *guard {
            let pid = child.id();
            log(&format!("Killing backend process tree (PID {})", pid));

            // Kill entire process group (backend + uvicorn workers)
            #[cfg(unix)]
            {
                unsafe {
                    // Send SIGTERM to the process group
                    libc::kill(-(pid as i32), libc::SIGTERM);
                }
                thread::sleep(Duration::from_millis(500));
                // Force kill if still alive
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }

            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                // taskkill /T kills entire process tree (PyInstaller wrapper + uvicorn workers)
                let _ = Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }

            #[cfg(not(any(unix, target_os = "windows")))]
            {
                let _ = child.kill();
            }

            let _ = child.wait(); // reap zombie
            log("Backend process tree killed");
        }
        *guard = None;
    }
}

struct BackendProcess(Arc<Mutex<Option<Child>>>);
