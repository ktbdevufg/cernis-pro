// CernisPro - Tauri v2
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const BACKEND_PORT: u16 = 8765;
const BACKEND_URL: &str = "http://127.0.0.1:8765";
const STARTUP_TIMEOUT_SECS: u64 = 45;

/// Backend-PID fuer den Signalhandler (async-signal-safe lesbar; 0 = keine).
/// Ein Mutex ist im Signalhandler nicht erlaubt -> die PID zusaetzlich hier
/// als Atomic, damit SIGTERM/SIGINT (Dock->Beenden) den Backend-Baum killen
/// kann, OHNE auf das Child-Arc (Mutex) zugreifen zu muessen.
static BACKEND_PID: AtomicI32 = AtomicI32::new(0);

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

    // KEIN CERNIS_DATA_DIR mehr setzen (Etappe 2c). Frueher legte der Wrapper hier
    // dirs::data_dir()/cernis-pro fest und gab es als CERNIS_DATA_DIR mit. Das war eine
    // ZWEITE, konkurrierende Aufloesung desselben Pfades: das Backend loest ihn bereits
    // in backend/modules/db_path.py auf, und CERNIS_DATA_DIR ist dort Prioritaet 1 --
    // der Wrapper ueberstimmte damit den Bundle-Zweig (de.cernis.pro), der nie erreicht
    // wurde. Gemessen geoeffnet wurde deshalb
    // ~/Library/Application Support/cernis-pro/cernis.db statt .../de.cernis.pro/.
    //
    // Es gibt jetzt genau EINE wirksame Quelle fuer den DB-Pfad: get_data_dir() im
    // Backend. CERNIS_DATA_DIR bleibt als bewusster Override bestehen (Tests, kuenftige
    // Wrapper), wird hier aber nicht mehr gesetzt.

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
    cmd.env("CERNIS_PORT", BACKEND_PORT.to_string());

    // Backend in EIGENE Session+Prozessgruppe legen, damit kill(-pid) beim Beenden
    // die ganze Gruppe trifft. process_group(0) wirkt auf macOS nicht zuverlaessig
    // (Child blieb in Parent-PGID) -> setsid() im Child vor exec ist der sichere Weg:
    // es macht den Child zum Session- und Prozessgruppenfuehrer (PGID == child-PID).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid ist async-signal-safe und der einzige Aufruf im Child
        // zwischen fork und exec (keine Allokation, kein Lock) -- pre_exec-konform.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
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
            let child_pid = child.id();
            log(&format!("Backend process started (PID {})", child_pid));
            // PID fuer den Signalhandler hinterlegen (Dock->Beenden-Weg).
            BACKEND_PID.store(child_pid as i32, Ordering::SeqCst);
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
    std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", BACKEND_PORT).parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
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

#[cfg(target_os = "linux")]
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

/// Ermittelte WebKit2GTK-Fassung. `None` heisst ausdruecklich "nicht
/// ermittelbar" -- ein Zahlenwert als Platzhalter fuer "unbekannt" ist
/// bewusst ausgeschlossen, weil ein solcher Platzhalter (frueher 0.0) sich in
/// Vergleichen wie eine SEHR ALTE Fassung verhaelt und damit still durch die
/// Renderpfad-Matrix faellt.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct WebkitVersion {
    major: u32,
    minor: u32,
}

#[cfg(target_os = "linux")]
impl WebkitVersion {
    /// Darstellung fuers Protokoll: eine ermittelte Fassung sieht nie aus wie
    /// "nicht ermittelbar" und umgekehrt.
    fn describe(version: Option<Self>) -> String {
        match version {
            Some(v) => format!("{}.{}", v.major, v.minor),
            None => "nicht-ermittelbar".to_string(),
        }
    }
}

/// Liest die WebKit2GTK-Fassung ueber pkg-config. Quelle ist eine Datei des
/// ENTWICKLUNGSPAKETS, die auf Anwendersystemen typischerweise fehlt -- ein
/// Fehlschlag ist hier also der Normalfall, kein Ausnahmefall. Jeder Weg, der
/// zu keinem Ergebnis fuehrt, protokolliert seinen eigenen, unterscheidbaren
/// Grund, statt still auf einen Zahlenwert zurueckzufallen.
#[cfg(target_os = "linux")]
fn get_webkit_version() -> Option<WebkitVersion> {
    let out = match Command::new("pkg-config")
        .args(["--modversion", "webkit2gtk-4.1"])
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            log(&format!(
                "WebKit-Fassung nicht ermittelbar: pkg-config nicht ausfuehrbar ({e})"
            ));
            return None;
        }
    };

    if !out.status.success() {
        log(&format!(
            "WebKit-Fassung nicht ermittelbar: pkg-config meldet Fehler fuer Modul \
             webkit2gtk-4.1 (Exitcode {}) -- Entwicklungspaket vermutlich nicht installiert",
            out.status.code().unwrap_or(-1)
        ));
        return None;
    }

    let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if ver.is_empty() {
        log("WebKit-Fassung nicht ermittelbar: pkg-config lieferte Exitcode 0, aber leere Ausgabe");
        return None;
    }

    let parts: Vec<&str> = ver.split('.').collect();
    if parts.len() < 2 {
        log(&format!(
            "WebKit-Fassung nicht ermittelbar: Ausgabe \"{ver}\" hat weniger als zwei Punktteile"
        ));
        return None;
    }

    let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) else {
        log(&format!(
            "WebKit-Fassung nicht ermittelbar: Ausgabe \"{ver}\" enthaelt nicht-numerische Teile"
        ));
        return None;
    };

    Some(WebkitVersion { major, minor })
}

#[cfg(target_os = "linux")]
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

/// Waehlt den Renderpfad. Die Erhebung von Distributions-ID, VM-Art und
/// WebKit-Fassung ist linuxeigen: /etc/os-release, systemd-detect-virt bzw.
/// DMI und pkg-config gibt es auf Windows und macOS nicht. Dort wird nichts
/// erhoben und nichts behauptet -- nur der ausdrueckliche Nutzerwunsch bleibt.
#[cfg(not(target_os = "linux"))]
fn configure_rendering() {
    let need_sw_rendering = if std::env::var("CERNIS_SOFTWARE_RENDER").is_ok() {
        log("→ CERNIS_SOFTWARE_RENDER gesetzt: erzwinge Software-Rendering");
        true
    } else {
        log("Environment: Erhebung nur unter Linux -- keine Aussage zu distro/vm/webkit");
        log("→ Hardware-Rendering (Standard)");
        false
    };

    if need_sw_rendering {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        log("  Set WEBKIT_DISABLE_COMPOSITING_MODE=1");
        log("  Set WEBKIT_DISABLE_DMABUF_RENDERER=1");
    }
}

#[cfg(target_os = "linux")]
fn configure_rendering() {
    let vm = detect_vm();
    let webkit = get_webkit_version();
    let distro = get_distro();

    log(&format!(
        "Environment: distro={}, vm={}, webkit={}",
        distro,
        vm.unwrap_or("bare-metal"),
        WebkitVersion::describe(webkit)
    ));

    // Decision matrix:
    // - Ubuntu + VM + WebKit >= 2.44: black screen confirmed → disable compositing
    // - Ubuntu + bare-metal: usually fine, but DMABUF can fail on some GPUs
    // - Debian + VM: works fine (older WebKit, different compositor defaults)
    // - Debian + bare-metal: works fine
    // - VM + Fassung nicht ermittelbar: eigener Zweig, siehe unten.
    let need_sw_rendering = match (vm, distro.as_str(), webkit) {
        // Ubuntu in a VM with newer WebKit → always disable
        (Some(_), "ubuntu" | "pop" | "linuxmint", Some(wk))
            if wk.major >= 2 && wk.minor >= 44 =>
        {
            log("→ Ubuntu VM with WebKit >= 2.44: disabling GPU compositing");
            true
        }
        // Any distro with very new WebKit in a VM → cautiously disable
        (Some(_), _, Some(wk)) if wk.major >= 2 && wk.minor >= 46 => {
            log("→ VM with WebKit >= 2.46: disabling GPU compositing as precaution");
            true
        }
        // VM, aber die Fassung ist nicht ermittelbar -- der ausdrueckliche
        // Unbekannt-Zweig. Begruendung: in einer VM ist der bekannte
        // schlechteste Fall der Ubuntu-VM mit WebKit >= 2.44, und der endet in
        // Software-Rendering (bestaetigter Schwarzbildschirm sonst). Ohne
        // Fassung koennen wir diesen Fall nicht ausschliessen; wir waehlen
        // deshalb denselben Pfad wie der bekannte schlechteste Fall. Das
        // kostet auf harmlosen VMs GPU-Beschleunigung, riskiert aber nirgends
        // ein unbedienbares Fenster. Auf Bare-Metal kennt die Matrix keinen
        // Problemfall -> dort bleibt es beim Standard weiter unten.
        (Some(vm_art), _, None) => {
            log(&format!(
                "→ VM ({vm_art}), WebKit-Fassung nicht ermittelbar: \
                 Software-Rendering wie im bekannten schlechtesten VM-Fall"
            ));
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

/// App-Protocol-URL des lokal ueber frontendDist ausgelieferten Splash-HTML
/// (tauri://localhost/splash.html auf Linux). Braucht kein Backend. Wird im
/// setup gesetzt und beim Fenster-Schliessen wiederverwendet, um die Webview von
/// der (dann sterbenden) Backend-http-URL auf diesen lokalen Splash zu lenken ->
/// kein rohes "Connection refused" beim Beenden.
fn splash_url() -> &'static OnceLock<String> {
    static SPLASH_URL: OnceLock<String> = OnceLock::new();
    &SPLASH_URL
}

/// Async-signal-safe Handler fuer SIGTERM/SIGINT: killt den Backend-Baum ueber
/// die im Atomic hinterlegte PID und beendet dann den eigenen Prozess. NUR
/// async-signal-safe Aufrufe (Atomic-Load, kill, _exit) -- KEIN Mutex, KEIN
/// log()/println (nicht signal-safe). Deckt den Dock->Beenden-Weg ab, bei dem
/// die WindowEvents nicht feuern.
#[cfg(unix)]
extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    let pid = BACKEND_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            // Prozessgruppe (setsid -> PGID == pid) und die PID direkt.
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
    // Eigenen Prozess beenden (Standard-Exit-Code fuer signalbedingtes Ende).
    unsafe {
        libc::_exit(0);
    }
}

/// Registriert den Signalhandler fuer SIGTERM und SIGINT (idempotent genug fuer
/// einen einmaligen Aufruf in main()).
#[cfg(unix)]
fn install_signal_handler() {
    unsafe {
        // Erst zu Funktions-Zeiger (*const ()), dann zu sighandler_t: der direkte
        // fn->integer-Cast loest den function_casts_as_integer-Lint aus; der Weg
        // ueber den Pointer ist die vom Compiler empfohlene, semantisch gleiche Form.
        libc::signal(
            libc::SIGTERM,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
    }
}

fn main() {
    // Clear previous log
    let _ = std::fs::write(log_path(), "");
    log("=== CERNIS PRO starting ===");

    configure_rendering();

    // Signalhandler fuer SIGTERM/SIGINT (Dock->Beenden killt sonst Tauri, ohne dass
    // die WindowEvents feuern -> Backend bliebe als Waise).
    #[cfg(unix)]
    install_signal_handler();

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
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
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
            // Fenster SOFORT auf dem Main-Thread erzeugen (setup laeuft auf dem
            // Main-Thread) und zunaechst auf den lokalen App-Protocol-Splash zeigen.
            // Dieser braucht KEIN Backend -> nie ein rohes Connection-refused-Bild.
            // Fuer den CloseRequested-Handler die zugehoerige tauri://-URL merken;
            // sie ist auch beim Beenden der sichere Zielort (Backend stirbt dann).
            let _ = splash_url().set("tauri://localhost/splash.html".to_string());
            log("Lokaler App-Protocol-Splash: splash.html");

            let splash = WebviewUrl::App("splash.html".into());

            let fenster = WebviewWindowBuilder::new(app, "main", splash)
                .title("CERNIS PRO")
                .inner_size(1600.0, 900.0)
                .min_inner_size(1200.0, 700.0)
                .resizable(true)
                .center()
                .build()?;

            // Backend erst NACH dem Fenster starten und im Hintergrund abwarten,
            // damit der Splash sofort sichtbar ist. Ergebnis -> Status-Datei
            // (plugin-freier Zweitweg) + native Navigation / Tauri-Event.
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
                    // Erfolg: Die Webview NATIV (Rust-seitig, nicht per JS) auf den
                    // vom Backend selbst ausgelieferten Splash lenken. navigate() geht
                    // ueber den threadsicheren Dispatcher und darf aus diesem
                    // Hintergrund-Thread aufgerufen werden (marshallt intern auf den
                    // Main-Thread) -- anders als WebviewWindowBuilder::build(). Eine
                    // native Navigation unterliegt NICHT der Cross-Origin-Sperre, die
                    // WebKit einer JS-Navigation (window.location) von tauri:// auf
                    // http:// auferlegt. Ab dann teilen Splash und App denselben
                    // http-Origin, sodass der Splash same-origin auf "/" navigieren darf.
                    let ziel = format!("{}/splash.html", BACKEND_URL);
                    log(&format!("Backend bereit -> native Navigation auf {}", ziel));
                    match ziel.parse() {
                        Ok(url) => {
                            if let Err(e) = fenster.navigate(url) {
                                log(&format!("WARN: navigate auf http-Splash fehlgeschlagen: {}", e));
                            }
                        }
                        Err(e) => log(&format!("WARN: http-Splash-URL nicht parsebar: {}", e)),
                    }
                } else {
                    // Fehler: Es gibt kein Backend -> der lokale App-Splash MUSS
                    // sichtbar bleiben. Fehlercode per Event an ihn schicken.
                    log(&format!("Backend-Fehler {} -> Event 'backend-error'", status.code()));
                    let _ = app_handle.emit("backend-error", status.code());
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building app")
        .run(move |_app_handle, event| {
            // RunEvent::ExitRequested UND ::Exit feuern auch beim macOS-Apple-Event-Quit
            // (Dock->Beenden, Cmd+Q) -- anders als die WindowEvents und der Unix-
            // Signalhandler. Hier den Backend zuverlaessig mitbeenden.
            if let tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit = event {
                kill_backend_tree(&backend_exit);
            }
        });
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
                    // Erst direkte PID killen (funktioniert unabhaengig von PGID).
                    libc::kill(pid as i32, libc::SIGTERM);
                    // Zusaetzlich Prozessgruppe (uvicorn-Worker-Children).
                    libc::kill(-(pid as i32), libc::SIGTERM);
                }
                thread::sleep(Duration::from_millis(500));
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
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
