// CernisPro - Tauri v2
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(unix)]
mod unix_prozesse;

use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const BACKEND_PORT: u16 = 8765;
const BACKEND_URL: &str = "http://127.0.0.1:8765";
const STARTUP_TIMEOUT_SECS: u64 = 45;

/// Frist, die dem Backend nach SIGTERM fuer den GEORDNETEN Abbau bleibt, bevor
/// SIGKILL folgt (Befund 45/57).
///
/// WOHER DIE ZAHL: der Abbauweg des Backends (app.py, lifespan-Shutdown)
/// enthaelt SELBST gestaffelte Fristen. Der laengste Einzelpfad ist das
/// Beenden des Sniff-Helfers in infrastructure/sniffd_client/base.py, das drei
/// eigene Stufen hat: 3 s freundliches Selbst-Ende
/// (_GRACEFUL_EXIT_TIMEOUT_SECS), danach 2 s nach terminate
/// (_TERMINATE_TIMEOUT_SECS), danach nochmals 2 s nach kill -- zusammen 7 s
/// allein fuer EINEN Helfer.
///
/// Dazu kommen die uebrigen Abbauschritte desselben Shutdowns (monitor-,
/// logging-, cve-, outbound-, scheduler-, capture-, dns-bypass-, poll-Task und
/// der sni-Thread-Join, je mit eigenem cancel+await). Die alten 500 ms konnten
/// diesen Weg an einer EINZIGEN Stelle nicht ueberstehen -- SIGKILL traf
/// mitten in den Abbau.
///
/// 15 s decken die 7 s des Helferpfads mit reichlicher Reserve fuer den Rest
/// des Shutdowns ab. Das ist eine OBERGRENZE, KEINE Wartedauer: gepollt wird
/// alle 20 ms, und der Normalfall kehrt lange vorher zurueck (GEMESSEN auf
/// diesem System: 0,16-0,23 s im rechtefreien Lauf).
const BACKEND_ABBAU_FRIST: Duration = Duration::from_secs(15);

/// Abfrageabstand beim Warten auf das tatsaechliche Prozessende. 20 ms sind
/// fein genug, dass der Normalfall (deutlich unter 1 s) nicht kuenstlich
/// verzoegert wird, und grob genug, dass das Warten keine Rechenzeit frisst.
const BACKEND_ABBAU_ABFRAGE: Duration = Duration::from_millis(20);

/// Marke des Signalhandlers (Befund 57). Der Handler darf NICHTS tun, was
/// nicht async-signal-safe ist -- kein Mutex, kein log(), kein sleep. Er setzt
/// deshalb nur dieses Flag; der geordnete Abbau laeuft im Wachposten-Thread
/// (siehe `starte_signal_wachposten`), der ausserhalb des Signalkontexts
/// laeuft und dort alles darf.
#[cfg(unix)]
static ABBRUCH_ANGEFORDERT: AtomicBool = AtomicBool::new(false);

// Das fruehere Atomic BACKEND_PID ist entfallen. Sein einziger Zweck war der
// Mutex-freie Zugriff des Signalhandlers auf die Backend-PID. Da der Handler
// jetzt nur noch eine Marke setzt und der Abbau im Wachposten-Thread laeuft --
// der den Child hinter dem Mutex ganz regulaer erreicht --, gab es keinen
// Leser mehr; ein nur noch beschriebener Zustand ist toter Zustand.

/// Rueckgabewert, mit dem sich das Backend selbst beendet, wenn es den Start
/// wegen eines unbrauchbaren Datenbank-Schemas VERWEIGERT (Datenbank aus einer
/// neueren Programmfassung oder gescheiterte Migration). Die Quelle des Wertes
/// ist backend/serve.py, Konstante EXIT_SCHEMA_UNBRAUCHBAR -- beide Seiten
/// muessen denselben Wert tragen. Ein eigener Wert (nicht 1) trennt diesen
/// geordneten Abbruch vom gewoehnlichen Absturz (E-102).
const BACKEND_EXIT_SCHEMA_UNBRAUCHBAR: i32 = 105;

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
    /// Backend hat den Start wegen unbrauchbaren Datenbank-Schemas verweigert
    /// (Rueckgabewert BACKEND_EXIT_SCHEMA_UNBRAUCHBAR).
    Error105,
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
            BackendStatus::Error105 => "E-105",
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
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
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
        log(&format!(
            "  Checking: {:?} → exists={}",
            resolved,
            resolved.exists()
        ));
        if resolved.exists() {
            log(&format!("  Found backend: {:?}", resolved));
            return Some(resolved);
        }
    }
    log("ERROR: Backend binary not found in any candidate path!");
    None
}

/// Ergebnis der Alt-Prozess-Behandlung auf dem Backend-Port.
enum Portlage {
    /// Der Port ist frei (oder war es nach einem beendeten eigenen Backend).
    Frei,
    /// Ein FREMDER oder nicht ermittelbarer Prozess haelt den Port. Der Start
    /// wird nicht erzwungen -- E-101, das der Splash bereits fuehrt.
    Fremdbelegt,
}

/// Behandelt einen Prozess, der beim Start bereits auf dem Backend-Port
/// lauscht (Befund 60 und 47).
///
/// FRUEHER: `fuser -k` schoss den Portinhaber blind ab -- ohne Programmnamen,
/// Pfad, Benutzer oder Kennung zu pruefen. Ein fremder Dienst auf 8765 wurde
/// vom Start der Anwendung erschossen, und E-101 war faktisch unerreichbar,
/// weil der Portinhaber vorher weg war.
///
/// JETZT wird ERST ermittelt, DANN entschieden:
/// * Gehoert der Prozess uns (selber Benutzer UND unser Backend-Binaerpfad),
///   wird er auf demselben GEORDNETEN Weg beendet wie ein eigenes Kind
///   (SIGTERM, gepolltes Warten, erst danach SIGKILL) -- nicht mit fuser -k.
/// * Ist er fremd, bleibt er UNANGETASTET. Der Start endet mit E-101.
/// * Laesst sich der Inhaber nicht ermitteln, wird ebenfalls nichts beendet
///   und E-101 gemeldet. Ein unbekannter Prozess ist kein eigener -- das ist
///   ausdruecklich KEIN Rueckfall auf das alte Verhalten.
#[cfg(unix)]
fn kill_stale_backend(eigenes_backend: &std::path::Path) -> Portlage {
    if !port_belegt() {
        log(&format!("Port {} ist frei", BACKEND_PORT));
        return Portlage::Frei;
    }

    let Some(inhaber) = unix_prozesse::portinhaber(BACKEND_PORT) else {
        log(&format!(
            "Port {} ist belegt, der Inhaber ist aber NICHT ermittelbar \
             (kein Eintrag in /proc/net/tcp oder fremder Benutzer) -- \
             es wird NICHTS beendet, Start endet mit E-101",
            BACKEND_PORT
        ));
        return Portlage::Fremdbelegt;
    };

    if !inhaber.ist_unser_backend(eigenes_backend) {
        log(&format!(
            "Port {} wird von PID {} gehalten (Programm {}, UID {}) -- das ist \
             NICHT unser Backend, der Prozess bleibt unangetastet, Start endet mit E-101",
            BACKEND_PORT,
            inhaber.pid,
            inhaber
                .programm
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "nicht lesbar".to_string()),
            inhaber
                .uid
                .map(|u| u.to_string())
                .unwrap_or_else(|| "nicht lesbar".to_string()),
        ));
        return Portlage::Fremdbelegt;
    }

    log(&format!(
        "Port {} wird von unserem eigenen Backend (PID {}) gehalten -- \
         geordneter Abbau wie beim Beenden",
        BACKEND_PORT, inhaber.pid
    ));
    beende_fremde_pid_geordnet(inhaber.pid);

    if port_belegt() {
        log(&format!(
            "Port {} ist nach dem Abbau des Alt-Backends WEITERHIN belegt -- \
             Start endet mit E-101",
            BACKEND_PORT
        ));
        Portlage::Fremdbelegt
    } else {
        log(&format!(
            "Port {} nach Abbau des Alt-Backends frei",
            BACKEND_PORT
        ));
        Portlage::Frei
    }
}

#[cfg(not(unix))]
fn kill_stale_backend(_eigenes_backend: &std::path::Path) -> Portlage {
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
            Portlage::Frei
        }
        Err(_) => {
            log(&format!("Port {} is free", BACKEND_PORT));
            Portlage::Frei
        }
    }
}

fn start_backend() -> Result<Child, BackendStatus> {
    // Reihenfolge getauscht: Der eigene Backend-Pfad wird JETZT ZUERST
    // ermittelt, weil die Portpruefung ihn braucht -- ohne ihn laesst sich
    // "gehoert der Portinhaber uns?" nicht beantworten (Befund 60).
    let backend = match find_backend_exe() {
        Some(p) => p,
        None => {
            log("ERROR: Cannot start backend — binary not found");
            // Backend-Binary nicht gefunden -> E-104.
            return Err(BackendStatus::Error104);
        }
    };

    // Rueckgabewert wird NICHT mehr verworfen: ob der Port frei wurde, ist eine
    // Aussage, die den Start entscheidet (Befund 47).
    if let Portlage::Fremdbelegt = kill_stale_backend(&backend) {
        return Err(BackendStatus::Error101);
    }

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

/// Lage des Backend-Kindes beim Exit-Check.
#[derive(PartialEq)]
enum Kindlage {
    /// Der Prozess laeuft noch.
    Laeuft,
    /// Der Prozess ist beendet. Traegt seinen Rueckgabewert, soweit einer
    /// vorliegt (None z. B. bei Beendigung durch ein Signal). Der Wert wird
    /// gebraucht, um die Startverweigerung wegen des Datenbank-Schemas
    /// (BACKEND_EXIT_SCHEMA_UNBRAUCHBAR -> E-105) vom gewoehnlichen
    /// vorzeitigen Abbruch (E-102) zu unterscheiden.
    Beendet(Option<i32>),
}

impl Kindlage {
    fn ist_beendet(&self) -> bool {
        matches!(self, Kindlage::Beendet(_))
    }
}

/// Kurz-lockender Exit-Check auf dem geteilten Child. Gibt Some(Beendet(code))
/// zurueck, wenn der Prozess beendet ist, Some(Laeuft) wenn er laeuft, None wenn
/// kein Child (mehr) vorhanden ist. Der Lock wird nur fuer die Dauer des try_wait
/// gehalten — nie ueber Netzwerk-Wartezeiten —, damit ein paralleles
/// kill_backend_tree beim Fenster-Schliessen nicht blockiert (kein Deadlock).
fn child_exited(process: &Arc<Mutex<Option<Child>>>) -> Option<Kindlage> {
    let mut guard = process.lock().ok()?;
    let child = guard.as_mut()?;
    match child.try_wait() {
        Ok(Some(status)) => Some(Kindlage::Beendet(status.code())),
        Ok(None) => Some(Kindlage::Laeuft),
        Err(e) => {
            log(&format!("WARN: Could not check process status: {}", e));
            Some(Kindlage::Laeuft)
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
        if let Some(Kindlage::Beendet(code)) = child_exited(process) {
            // Der Rueckgabewert entscheidet, WELCHER Fehler es ist: hat das
            // Backend den Start selbst wegen des Datenbank-Schemas verweigert
            // (serve.py, EXIT_SCHEMA_UNBRAUCHBAR), ist das E-105 und kein
            // Absturz. Alles andere bleibt der bisherige Fall E-102.
            if code == Some(BACKEND_EXIT_SCHEMA_UNBRAUCHBAR) {
                log(&format!(
                    "ERROR: Backend verweigert den Start wegen des Datenbank-Schemas \
                     (Rueckgabewert {})",
                    BACKEND_EXIT_SCHEMA_UNBRAUCHBAR
                ));
                log(&format!("Check {} for details", log_path()));
                return BackendStatus::Error105;
            }
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
                if child_exited(process).is_some_and(|lage| lage.ist_beendet()) {
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
    let eigener_prozess_lebt = child_exited(process) == Some(Kindlage::Laeuft);

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
        if p.contains("vmware") {
            return Some("vmware");
        }
        if p.contains("virtualbox") {
            return Some("virtualbox");
        }
        if p.contains("kvm") || p.contains("qemu") {
            return Some("kvm");
        }
        if p.contains("hyper-v") {
            return Some("hyperv");
        }
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
        (Some(_), "ubuntu" | "pop" | "linuxmint", Some(wk)) if wk.major >= 2 && wk.minor >= 44 => {
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

/// Async-signal-safe Handler fuer SIGTERM/SIGINT.
///
/// FRUEHER eskalierte er SOFORT auf SIGKILL und beendete danach den eigenen
/// Prozess mit _exit -- der geordnete Abbau des Backends kam nie zum Zug
/// (Befund 57).
///
/// JETZT tut der Handler nur noch das, was im Signalkontext ERLAUBT ist: er
/// setzt eine Marke. Ein Atomic-Store ist lock-frei und damit async-signal-safe;
/// alles Weitere -- SIGTERM, gepolltes Warten, Protokollzeilen -- laeuft im
/// Wachposten-Thread AUSSERHALB des Signalkontexts. Ausdruecklich NICHT hier:
/// Mutex (der Child sitzt hinter einem), log() (schreibt Dateien und
/// allokiert), sleep.
///
/// Der Handler kehrt danach ZURUECK, statt _exit zu rufen: nur so bleibt dem
/// Wachposten ueberhaupt Zeit, den geordneten Abbau zu fahren. Das Beenden des
/// eigenen Prozesses uebernimmt der Wachposten, wenn das Backend unten ist.
#[cfg(unix)]
extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    ABBRUCH_ANGEFORDERT.store(true, Ordering::SeqCst);
}

/// Wachposten fuer die Marke des Signalhandlers. Laeuft als eigener Thread und
/// darf darum alles, was dem Handler verboten ist (Mutex, Protokoll, Warten).
///
/// Er fuehrt denselben geordneten Abbau wie die drei Fensterwege
/// (CloseRequested/Destroyed/ExitRequested) -- ein einziger Weg fuer alle vier
/// Ausloeser -- und beendet erst DANACH den eigenen Prozess.
#[cfg(unix)]
fn starte_signal_wachposten(process: Arc<Mutex<Option<Child>>>) {
    thread::spawn(move || loop {
        if ABBRUCH_ANGEFORDERT.load(Ordering::SeqCst) {
            log("SIGTERM/SIGINT empfangen -> geordneter Abbau (Wachposten)");
            kill_backend_tree(&process);
            log("Abbau abgeschlossen -> eigener Prozess endet");
            std::process::exit(0);
        }
        // Derselbe Abfrageabstand wie beim Warten auf das Prozessende: fein
        // genug, dass das Beenden nicht spuerbar verzoegert wird, und ohne
        // nennenswerte Last im Leerlauf.
        thread::sleep(BACKEND_ABBAU_ABFRAGE);
    });
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

/// Raeumt verwaiste PyInstaller-Auspackverzeichnisse aus frueheren Laeufen ab
/// (Befund 45). Entfernt wird NUR, was sich als unseres BELEGEN laesst -- die
/// drei Bedingungen und ihre Begruendung stehen bei
/// `unix_prozesse::verwaiste_buendel`.
///
/// Jedes entfernte Verzeichnis wird BENANNT protokolliert; wird nichts
/// entfernt, wird auch DAS gesagt. Ein Fehlschlag beim Loeschen ist kein
/// stiller Rueckfall, sondern eine eigene Zeile.
#[cfg(unix)]
fn raeume_verwaiste_buendel() {
    let temp = std::env::temp_dir();
    let buendel = unix_prozesse::verwaiste_buendel(&temp);

    if buendel.is_empty() {
        log(&format!(
            "Verwaiste Buendel in {}: keines gefunden -- nichts entfernt",
            temp.display()
        ));
        return;
    }

    for verwaist in buendel {
        match std::fs::remove_dir_all(&verwaist.pfad) {
            Ok(()) => log(&format!(
                "Verwaistes Buendel entfernt: {}",
                verwaist.pfad.display()
            )),
            Err(e) => log(&format!(
                "WARN: verwaistes Buendel {} NICHT entfernt: {}",
                verwaist.pfad.display(),
                e
            )),
        }
    }
}

fn main() {
    // Clear previous log
    let _ = std::fs::write(log_path(), "");
    log("=== CERNIS PRO starting ===");

    configure_rendering();

    // Verwaiste Auspackverzeichnisse frueherer Laeufe abraeumen, BEVOR ein
    // neues entsteht (Befund 45).
    #[cfg(unix)]
    raeume_verwaiste_buendel();

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

    // Wachposten fuer die Marke des Signalhandlers. Erst HIER startbar, weil er
    // das geteilte Child-Arc braucht -- der Handler selbst darf es nicht
    // anfassen (Mutex im Signalkontext).
    #[cfg(unix)]
    starte_signal_wachposten(Arc::clone(&backend_process));

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
                    if let (Some(webview), Ok(parsed)) =
                        (window.app_handle().get_webview_window("main"), url.parse())
                    {
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
                                log(&format!(
                                    "WARN: navigate auf http-Splash fehlgeschlagen: {}",
                                    e
                                ));
                            }
                        }
                        Err(e) => log(&format!("WARN: http-Splash-URL nicht parsebar: {}", e)),
                    }
                } else {
                    // Fehler: Es gibt kein Backend -> der lokale App-Splash MUSS
                    // sichtbar bleiben. Fehlercode per Event an ihn schicken.
                    log(&format!(
                        "Backend-Fehler {} -> Event 'backend-error'",
                        status.code()
                    ));
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

/// Beendet einen Prozess, den wir NICHT als Kind halten (also kein `Child`,
/// kein `try_wait`), auf demselben geordneten Weg wie ein eigenes Kind:
/// SIGTERM an Prozess und Gruppe, gepolltes Warten auf das tatsaechliche Ende
/// bis `BACKEND_ABBAU_FRIST`, erst danach SIGKILL.
///
/// Gebraucht wird das fuer das Alt-Backend aus einem frueheren Lauf (Teil 1):
/// es ist unseres, aber es ist nicht unser Kind.
///
/// REIHENFOLGE VON SIGNAL UND EXISTENZPRUEFUNG (geprueft im Zuge von S84-A12,
/// als in `kill_backend_tree` ein Signal an eine bereits freigegebene Gruppe
/// gefunden wurde -- HIER liegt der Fehler NICHT vor, und zwar aus zwei
/// verschiedenen Gruenden je Zweig):
///
/// * ERFOLGSZWEIG: sobald `prozess_lebt` das Ende meldet, wird KEIN Signal mehr
///   abgesetzt -- die Funktion protokolliert und kehrt zurueck. Der Fall
///   "erst feststellen, dass es weg ist, dann trotzdem an die Gruppe schicken"
///   -- genau der Fehler aus `kill_backend_tree` -- existiert hier nicht.
///   Diese Zeilenfolge ist tragend: wer hinter der Erfolgsmeldung noch ein
///   Gruppensignal ergaenzt, baut den Fehler nach.
/// * FRISTZWEIG: hierhin fuehrt nur, dass der Prozess bei der letzten Abfrage
///   noch LEBTE. Die Kennung war also gerade eben belegt. Ein Restfenster von
///   einem Abfrageabstand bleibt und ist bei einem FREMDEN Prozess nicht
///   schliessbar: wir halten ihn nicht als Kind, koennen ihn also nicht
///   abholen und seine PID nicht festhalten (das ist der Unterschied zum
///   eigenen Kind, wo `waitid`+`WNOWAIT` genau das leistet). Das Fenster wird
///   so klein wie moeglich gehalten -- die Gruppenkennung wird DIREKT VOR dem
///   Signal frisch gelesen statt den 15 s alten Wert von oben zu verwenden --
///   und benannt, statt es zu verschweigen.
#[cfg(unix)]
fn beende_fremde_pid_geordnet(pid: i32) {
    // Prozessgruppe mitnehmen: das Backend startet den Sniff-Helfer OHNE
    // eigene Session, er haengt also in derselben Gruppe.
    let gruppe = unix_prozesse::prozessgruppe(pid);
    unsafe {
        libc::kill(pid, libc::SIGTERM);
        if let Some(pgid) = gruppe {
            libc::kill(-pgid, libc::SIGTERM);
        }
    }

    let beginn = Instant::now();
    while beginn.elapsed() < BACKEND_ABBAU_FRIST {
        if !unix_prozesse::prozess_lebt(pid) {
            log(&format!(
                "Alt-Backend PID {} nach {} ms geordnet beendet -- kein weiteres \
                 Signal (die Kennung ist ab jetzt nicht mehr belegbar unsere)",
                pid,
                beginn.elapsed().as_millis()
            ));
            return;
        }
        thread::sleep(BACKEND_ABBAU_ABFRAGE);
    }

    // Die Gruppenkennung FRISCH lesen: der oben gelesene Wert ist bis zu
    // BACKEND_ABBAU_FRIST alt. Ist der Prozess inzwischen doch weg, liefert
    // `prozessgruppe` None -- dann geht bewusst KEIN Gruppensignal raus,
    // statt eine womoeglich neu vergebene Kennung zu treffen.
    let gruppe_jetzt = unix_prozesse::prozessgruppe(pid);

    // Kein stiller Fallback: dass die Frist nicht reichte, wird BENANNT.
    log(&format!(
        "WARN: Alt-Backend PID {} nach {} s nicht beendet -> SIGKILL (Gruppe: {})",
        pid,
        BACKEND_ABBAU_FRIST.as_secs(),
        gruppe_jetzt
            .map(|g| g.to_string())
            .unwrap_or_else(|| "nicht mehr ermittelbar, kein Gruppensignal".to_string()),
    ));
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        if let Some(pgid) = gruppe_jetzt {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

fn kill_backend_tree(process: &Arc<Mutex<Option<Child>>>) {
    if let Ok(mut guard) = process.lock() {
        if let Some(ref mut child) = *guard {
            let pid = child.id();
            log(&format!("Killing backend process tree (PID {})", pid));

            // Kill entire process group (backend + uvicorn workers)
            #[cfg(unix)]
            {
                // VORPRUEFUNG, bevor das ERSTE Signal faellt: gibt es dieses
                // Kind ueberhaupt noch? `kind_beendet_ohne_abholen` liefert
                // `None` bei ECHILD -- dann wurde das Kind BEREITS ABGEHOLT
                // und die PID ist freigegeben.
                //
                // DAS IST KEIN THEORETISCHER FALL, es ist GEMESSEN: stirbt das
                // Backend beim Start vorzeitig, holt es der `try_wait` in
                // `child_exited` waehrend `wait_for_backend` ab (E-102 bzw.
                // E-105 bei verweigertem Start wegen des Datenbank-Schemas; der
                // Splash zeigt den Fehler und der Wrapper laeuft weiter).
                // Schliesst der Anwender das Fenster erst Sekunden spaeter,
                // gingen die beiden SIGTERM unten an eine laengst freigegebene
                // PID und Gruppenkennung. GEMESSEN in der Spur eines solchen
                // Laufs: `kill(-91010, SIGTERM)` 22 s nach dem `wait4`, das die
                // Kennung freigegeben hatte -- hier nur deshalb folgenlos
                // (ESRCH), weil die Nummer zufaellig noch frei war.
                let lage_vorab = unix_prozesse::kind_beendet_ohne_abholen(pid as i32);
                if lage_vorab.is_none() {
                    log(&format!(
                        "Backend-Kind (PID {}) ist bereits abgeholt (waitid: kein solches \
                         Kind) -- es geht KEIN Signal an PID oder Prozessgruppe: die Kennung \
                         ist freigegeben und kann einem fremden Prozessbaum gehoeren",
                        pid
                    ));
                    // Kein Signal, kein Warten -- direkt zum regulaeren
                    // Abschluss (child.wait() unten liefert den gemerkten
                    // Status, ohne einen Syscall abzusetzen).
                    let _ = child.wait();
                    log("Backend process tree killed");
                    *guard = None;
                    return;
                }

                unsafe {
                    // Erst direkte PID killen (funktioniert unabhaengig von PGID).
                    libc::kill(pid as i32, libc::SIGTERM);
                    // Zusaetzlich Prozessgruppe (uvicorn-Worker-Children).
                    libc::kill(-(pid as i32), libc::SIGTERM);
                }

                // GEPOLLT auf das TATSAECHLICHE Ende warten statt eine Dauer zu
                // SCHAETZEN (Befund 45/57). Frueher standen hier feste 500 ms:
                // der Abbauweg des Backends enthaelt selbst 3+2+2 s allein fuer
                // den Sniff-Helfer, SIGKILL traf also regelmaessig mitten in den
                // geordneten Abbau. Begruendung der Frist siehe
                // BACKEND_ABBAU_FRIST.
                //
                // Geprueft wird NICHT mit kill(pid, 0): der Prozess ist UNSER
                // Kind und bliebe nach seinem Ende als Zombie bestehen, bis wir
                // ihn abholen. kill(pid, 0) meldete ihn dann faelschlich als
                // lebend und liefe jedes Mal in die volle Frist.
                //
                // Geprueft wird auch NICHT mit try_wait -- DAS IST DIE FALLE,
                // und sie ist leicht wieder hineinzuschreiben: try_wait HOLT das
                // beendete Kind AB. Ab diesem Augenblick ist die PID frei und
                // kann neu vergeben werden; da die PGID bei unserem
                // setsid-Kind GLEICH der PID ist, traefe jedes danach
                // abgesetzte kill(-pid, ...) moeglicherweise einen FREMDEN
                // Prozessbaum. Genau diese Klasse hat der Wegfall von fuser -k
                // beseitigt.
                //
                // Darum waitid(WNOWAIT) ueber kind_beendet_ohne_abholen: es
                // meldet dasselbe Ende, laesst das Kind aber als Zombie stehen.
                // Die PID -- und damit die PGID -- bleibt belegt, bis wir unten
                // mit child.wait() ganz regulaer abholen.
                //
                // DREI Ausgaenge, nicht zwei -- der dritte ist der Grund, warum
                // hier kein blosses bool steht:
                //   Beendet          -- Kind ist tot, aber NICHT abgeholt.
                //                       Kennung noch unsere -> Gruppe abraeumen.
                //   FristAbgelaufen  -- Kind lebt noch. Kennung erst recht
                //                       unsere -> hart abraeumen.
                //   Unbekannt        -- waitid meldet ECHILD: das Kind wurde
                //                       zwischenzeitlich abgeholt, die PID ist
                //                       frei, die Gruppenkennung kann fremd
                //                       sein -> es geht KEIN Signal mehr raus.
                //                       Der HAEUFIGE Weg in diesen Fall (ein
                //                       beim Start abgeholtes E-102-Backend)
                //                       ist schon von der Vorpruefung oben
                //                       abgefangen; hier bleibt der Ausgang
                //                       stehen, damit die Schleife auch dann
                //                       schweigt, statt zu raten.
                enum Abbaulage {
                    Beendet,
                    FristAbgelaufen,
                    Unbekannt,
                }
                let beginn = Instant::now();
                let mut lage = Abbaulage::FristAbgelaufen;
                while beginn.elapsed() < BACKEND_ABBAU_FRIST {
                    match unix_prozesse::kind_beendet_ohne_abholen(pid as i32) {
                        Some(true) => {
                            lage = Abbaulage::Beendet;
                            break;
                        }
                        Some(false) => {}
                        None => {
                            lage = Abbaulage::Unbekannt;
                            break;
                        }
                    }
                    thread::sleep(BACKEND_ABBAU_ABFRAGE);
                }

                match lage {
                    Abbaulage::Unbekannt => {
                        log(&format!(
                            "Backend-Kind (PID {}) ist bereits abgeholt (waitid: kein solches \
                         Kind) -- es geht KEIN Signal mehr an PID oder Prozessgruppe: die \
                         Kennung ist freigegeben und kann einem fremden Prozessbaum gehoeren",
                            pid
                        ));
                    }
                    Abbaulage::Beendet => {
                        // REIHENFOLGE IST HIER TRAGEND -- erst das Gruppensignal,
                        // DANN das Abholen (child.wait() weiter unten):
                        //
                        // Der Sniff-Helfer haengt in derselben Gruppe und kann den
                        // Elternprozess ueberleben (er wird on demand gespawnt und
                        // vom lifespan-Shutdown nur dann mitgenommen, wenn dieser
                        // ueberhaupt laeuft und den betreffenden Zweig erreicht --
                        // siehe die Begruendung unten). Die Gruppe muss also
                        // abgeraeumt werden.
                        //
                        // Sie darf aber NUR abgeraeumt werden, solange die
                        // Gruppenkennung noch UNS gehoert. Genau das leistet die
                        // Reihenfolge: das Kind ist beendet, aber NICHT abgeholt
                        // (waitid mit WNOWAIT oben), die PID ist damit noch belegt
                        // und die PGID kann nicht neu vergeben worden sein. Wer
                        // diese zwei Zeilen tauscht, schickt ein SIGKILL an eine
                        // Kennung, die das System zwischenzeitlich einem fremden
                        // Prozessbaum gegeben haben kann.
                        //
                        // WARUM DAS SIGNAL TROTZ lifespan-Shutdown BLEIBT: der
                        // Shutdown des Backends nimmt den Helfer zwar mit
                        // (RunCapture.stop() / run_sni_uc.stop() /
                        // dns_bypass_recorder().stop() -> Adapter-stop ->
                        // _BaseSubprocessHelper._cleanup -> _stop_process), aber
                        // dieser Weg ist BEDINGT: der ganze Abbau-Block haengt an
                        // cfg.bootstrap_on_startup, der capture-Zweig zusaetzlich
                        // an einem noch laufenden capture_task, und _stop_process
                        // gibt nach seinen Fristen mit einer blossen Warnung auf.
                        // Das Gruppensignal ist das Netz darunter, nicht der
                        // Hauptweg.
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGKILL);
                        }
                        log(&format!(
                            "Backend nach {} ms geordnet beendet (kein SIGKILL an das Backend \
                         noetig); Prozessgruppe {} abgeraeumt VOR dem Abholen des Kindes, \
                         solange die Kennung noch uns gehoert",
                            beginn.elapsed().as_millis(),
                            pid
                        ));
                    }
                    Abbaulage::FristAbgelaufen => {
                        // Kein stiller Fallback: dass die Frist nicht reichte, wird
                        // BENANNT, bevor hart abgeraeumt wird.
                        log(&format!(
                            "WARN: Backend nach {} s nicht beendet -> SIGKILL an Backend \
                         und Prozessgruppe {} (Kennung noch belegt, Kind nicht abgeholt)",
                            BACKEND_ABBAU_FRIST.as_secs(),
                            pid
                        ));
                        // Hier ist die Kennung UNSTRITTIG noch unsere: in diesen
                        // Zweig fuehrt nur, dass das Kind eben NICHT als beendet
                        // gemeldet wurde -- abgeholt wurde es damit erst recht
                        // nicht (waitid mit WNOWAIT holt ohnehin nie ab). Die PID
                        // ist also belegt, die PGID nicht neu vergebbar. Das
                        // Abholen folgt auch hier erst unten mit child.wait().
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                            libc::kill(-(pid as i32), libc::SIGKILL);
                        }
                    }
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

            // ERST HIER wird abgeholt -- nach allen Signalen an die
            // Prozessgruppe. Das Abholen gibt die PID und damit die
            // Gruppenkennung frei; ab dieser Zeile darf kein kill(-pid, ...)
            // mehr folgen (siehe die Begruendung im Unix-Zweig oben).
            let _ = child.wait(); // reap zombie
            log("Backend process tree killed");
        }
        *guard = None;
    }
}
