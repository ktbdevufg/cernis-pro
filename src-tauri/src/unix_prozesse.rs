//! Prozess- und Bündelkunde für Unix (praktisch: Linux) -- die Tatsachen, die
//! `main.rs` braucht, BEVOR es etwas beendet oder löscht.
//!
//! WARUM /proc UND KEIN SYSTEMWERKZEUG (Befund 60): der bisherige Weg war
//! `fuser -k` -- ein Werkzeug, das den Portinhaber ermittelt UND ihn in
//! derselben unteilbaren Handlung abschiesst. Genau diese Kopplung ist der
//! Befund: es gibt keinen Zwischenpunkt, an dem man prüfen könnte, WEN man
//! da trifft. Auch `lsof`/`ss -p` lösen das nur halb: sie sind
//! Fremdprogramme, die auf einem Anwendersystem fehlen können, und ein
//! fehlendes Werkzeug führte wieder zu genau der Frage, die diese Änderung
//! beseitigen soll ("was tun, wenn wir es nicht wissen?"). `/proc` ist unter
//! Linux immer da, kostet keinen Prozessstart und liefert alle vier Merkmale
//! (Benutzer, Binärpfad, Prozessgruppe, Elternprozess) an einer Stelle.
//!
//! Alle Funktionen hier geben `Option`/leere Sammlungen zurück, wenn eine
//! Tatsache NICHT feststellbar ist. Kein Rückfall auf eine Annahme: der
//! Aufrufer entscheidet, und die Entscheidung bei "unbekannt" ist überall
//! dieselbe -- nichts anfassen.

use std::path::{Path, PathBuf};

/// Der ermittelte Inhaber eines lauschenden TCP-Ports.
pub struct Portinhaber {
    pub pid: i32,
    /// Aufgelöster Binärpfad (`/proc/<pid>/exe`). `None`, wenn nicht lesbar
    /// -- das ist bei fremden Prozessen anderer Benutzer der Normalfall.
    pub programm: Option<PathBuf>,
    /// Besitzer des Prozesses laut `/proc/<pid>/status` (Real-UID).
    pub uid: Option<u32>,
}

impl Portinhaber {
    /// Gehört dieser Prozess UNS -- selber Benutzer UND unser eigenes Backend?
    /// Beide Bedingungen müssen POSITIV feststehen. Ein nicht lesbarer
    /// Binärpfad oder eine nicht lesbare UID heisst "nein", nicht "vermutlich".
    pub fn ist_unser_backend(&self, eigenes_backend: &Path) -> bool {
        let Some(uid) = self.uid else {
            return false;
        };
        // SAFETY: getuid() ist immer erfolgreich und ohne Seiteneffekt.
        if uid != unsafe { libc::getuid() } {
            return false;
        }
        let Some(programm) = self.programm.as_ref() else {
            return false;
        };
        // Beide Seiten aufgelöst vergleichen: der Wrapper kennt seinen
        // Backend-Pfad über find_backend_exe() bereits kanonisiert, der
        // /proc/<pid>/exe-Link ist es von Haus aus. Ein Vergleich roher
        // Zeichenketten würde an einem Symlink scheitern.
        let eigenes = std::fs::canonicalize(eigenes_backend)
            .unwrap_or_else(|_| eigenes_backend.to_path_buf());
        *programm == eigenes
    }
}

/// Ermittelt den Prozess, der auf `127.0.0.1:<port>` LAUSCHT.
///
/// Weg: `/proc/net/tcp` liefert zum lauschenden Socket (Zustand 0A) dessen
/// Inode; die Inode wird dann in den Datei-Deskriptoren der Prozesse gesucht.
/// `None` heisst ausdrücklich "nicht ermittelbar" -- entweder lauscht
/// niemand, oder der Socket gehört einem fremden Benutzer, dessen
/// `/proc/<pid>/fd` wir nicht lesen dürfen. Beide Fälle sind für den Aufrufer
/// gleichbedeutend: Finger weg.
pub fn portinhaber(port: u16) -> Option<Portinhaber> {
    let inode = lauschende_socket_inode(port)?;
    let pid = pid_zu_socket_inode(inode)?;
    Some(Portinhaber {
        pid,
        programm: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
        uid: prozess_uid(pid),
    })
}

/// Sucht in `/proc/net/tcp` den LAUSCHENDEN Socket auf dem angegebenen Port
/// und gibt dessen Inode zurück. Nur IPv4/Loopback -- das Backend bindet
/// ausdrücklich auf 127.0.0.1 (siehe `serve.py`), ein IPv6-Lauscher wäre also
/// nicht unserer.
fn lauschende_socket_inode(port: u16) -> Option<u64> {
    let inhalt = std::fs::read_to_string("/proc/net/tcp").ok()?;
    for zeile in inhalt.lines().skip(1) {
        let felder: Vec<&str> = zeile.split_whitespace().collect();
        // 0=sl 1=local_address 2=rem_address 3=st ... 9=inode
        if felder.len() < 10 {
            continue;
        }
        // Zustand 0A == TCP_LISTEN. Verbundene Sockets auf demselben Port
        // (z. B. unsere eigene Prüfverbindung) tragen einen anderen Zustand
        // und dürfen nicht als "Inhaber" durchgehen.
        if felder[3] != "0A" {
            continue;
        }
        let (_adresse, port_hex) = felder[1].split_once(':')?;
        if u16::from_str_radix(port_hex, 16).ok()? != port {
            continue;
        }
        return felder[9].parse::<u64>().ok();
    }
    None
}

/// Sucht die PID zu einer Socket-Inode über `/proc/<pid>/fd`. Nicht lesbare
/// Verzeichnisse (fremde Benutzer) werden übersprungen -- das Ergebnis ist
/// dann `None`, also "nicht ermittelbar".
fn pid_zu_socket_inode(inode: u64) -> Option<i32> {
    let gesucht = format!("socket:[{inode}]");
    for eintrag in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = eintrag
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue; // fremder Benutzer oder Prozess inzwischen weg
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|z| z.to_string_lossy() == gesucht) {
                return Some(pid);
            }
        }
    }
    None
}

/// Real-UID eines Prozesses aus `/proc/<pid>/status` (Zeile `Uid:`, erstes Feld).
fn prozess_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for zeile in status.lines() {
        if let Some(rest) = zeile.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse::<u32>().ok();
        }
    }
    None
}

/// Prozessgruppe (PGID) eines Prozesses. Wird gebraucht, um den geordneten
/// Abbau auf denselben Weg zu schicken wie beim eigenen Kind: SIGTERM an die
/// GRUPPE erreicht auch den Sniff-Helfer, der als Kind ohne eigene Session
/// gestartet wird.
pub fn prozessgruppe(pid: i32) -> Option<i32> {
    // SAFETY: getpgid ist ein reiner Lesezugriff; -1 signalisiert den Fehler.
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid == -1 {
        None
    } else {
        Some(pgid)
    }
}

/// Lebt der Prozess noch? `kill(pid, 0)` stellt nur zu, wenn er existiert.
///
/// ACHTUNG -- Zombie: ein beendeter, aber noch nicht abgeholter Kindprozess
/// existiert weiterhin und meldet hier `true`. Für unsere eigenen Kinder wird
/// darum `try_wait` benutzt (siehe `child_exited` in `main.rs`); diese
/// Funktion gilt FREMDEN Prozessen, die wir nicht abholen können und die
/// darum auch nie zu Zombies unseres Prozesses werden.
pub fn prozess_lebt(pid: i32) -> bool {
    // SAFETY: Signal 0 wird nicht zugestellt, es wird nur die Existenz geprüft.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Ist unser Kindprozess beendet, OHNE ihn dabei abzuholen?
///
/// `Some(true)` = beendet und noch nicht abgeholt (Zombie), `Some(false)` =
/// laeuft noch, `None` = nicht feststellbar (kein solches Kind mehr, oder
/// `waitid` schlug fehl).
///
/// WARUM NICHT `try_wait` -- DIE FALLE, DIE DIESE FUNKTION VERMEIDET:
/// `Child::try_wait` fuehrt bei einem beendeten Kind das `waitpid` AUS und holt
/// es damit ab. In derselben Sekunde ist die PID freigegeben und kann vom
/// System neu vergeben werden. Wer DANACH `kill(-pid, ...)` an die
/// Prozessgruppe schickt -- die PGID ist bei einem mit `setsid` gestarteten
/// Kind GLEICH dieser PID --, trifft moeglicherweise einen fremden
/// Prozessbaum, der die Nummer inzwischen bekommen hat. Genau diese Klasse
/// (Signal an eine freigegebene Kennung) hat der Wegfall von `fuser -k`
/// beseitigt; sie darf hier nicht durch die Hintertuer zurueckkommen.
///
/// `waitid` mit `WNOWAIT` meldet denselben Zustandswechsel, laesst das Kind
/// aber ABHOLBAR stehen: die PID bleibt belegt, die PGID kann nicht neu
/// vergeben werden, und ein Gruppensignal trifft garantiert noch unsere eigene
/// Gruppe. Abgeholt wird das Kind erst danach, ganz regulaer ueber
/// `Child::wait` (siehe `kill_backend_tree` in `main.rs`).
///
/// GEMESSEN (dieses System, Probelauf mit setsid-Kind + Enkelkind): nach
/// `waitid(WNOWAIT)` steht das Kind in `/proc/<pid>/stat` als `Z`, ein
/// anschliessendes `kill(-pgid, SIGKILL)` liefert 0 und raeumt das Enkelkind
/// ab, und `Child::wait` holt das Kind danach fehlerfrei ab.
pub fn kind_beendet_ohne_abholen(pid: i32) -> Option<bool> {
    // SAFETY: `info` ist ein gueltiger, genullter siginfo-Puffer; `waitid`
    // beschreibt ausschliesslich diesen Puffer. P_PID + WNOWAIT lassen den
    // Prozess abholbar stehen (kein Reap).
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let ergebnis = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if ergebnis != 0 {
        return None; // z. B. ECHILD -- kein solches Kind (mehr)
    }
    // Bei WNOHANG ohne Zustandswechsel bleibt der Puffer genullt; `si_pid == 0`
    // heisst also "laeuft noch". Das setzt den genullten Puffer VOR dem Aufruf
    // voraus -- darum `zeroed()` oben.
    // SAFETY: `si_pid` liest ein Feld des von `waitid` beschriebenen Puffers.
    let gemeldete_pid = unsafe { info.si_pid() };
    Some(gemeldete_pid != 0)
}

/// Ein verwaistes PyInstaller-Auspackverzeichnis, das wir als UNSERES belegen
/// konnten.
pub struct VerwaistesBuendel {
    pub pfad: PathBuf,
}

/// Sucht verwaiste `_MEIxxxxxx`-Verzeichnisse, die alle drei Bedingungen aus
/// Befund 45 erfüllen.
///
/// (a) UNSER BENUTZER: Eigentümer-UID == eigene UID.
/// (b) VON NIEMANDEM GEHALTEN: kein laufender Prozess hat eine Datei darin
///     abgebildet (`/proc/<pid>/maps`). GEMESSEN: ein laufendes Bündel
///     erscheint dort immer, weil der Bootloader die entpackten `.so` aus
///     diesem Verzeichnis lädt.
/// (c) ZWEIFELSFREI UNSERES: das Verzeichnis trägt die Datenbeigaben, die NUR
///     unsere Backend-Spec einpackt -- `help/help_content.json` UND
///     `frontend-dist/index.html` UND ein `modules/`-Verzeichnis. Diese
///     Kombination entsteht aus `cernis_linux.spec` und aus keinem fremden
///     PyInstaller-Programm.
///
/// AUSDRÜCKLICH NICHT ERFASST ist das Bündel des Sniff-Helfers
/// (`cernis_sniffd_linux.spec`): es packt KEINE eigenen Datenbeigaben ein,
/// sein Inhalt (scapy, psutil, structlog und Systembibliotheken) ist von dem
/// eines beliebigen fremden scapy-Programms nicht zu unterscheiden. Nach der
/// Vorgabe aus Befund 45 -- lieber ein Rückstand als ein gelöschtes fremdes
/// Verzeichnis -- bleibt es liegen. Das ist ein benannter Rückstand, kein
/// Versehen.
pub fn verwaiste_buendel(temp: &Path) -> Vec<VerwaistesBuendel> {
    // SAFETY: getuid() ist immer erfolgreich und ohne Seiteneffekt.
    let eigene_uid = unsafe { libc::getuid() };
    let gehaltene = gehaltene_buendelpfade();

    let Ok(eintraege) = std::fs::read_dir(temp) else {
        return Vec::new();
    };

    let mut gefunden = Vec::new();
    for eintrag in eintraege.flatten() {
        let pfad = eintrag.path();
        if !pfad.is_dir() {
            continue;
        }
        let Some(name) = pfad.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("_MEI") {
            continue;
        }
        // (a) unser Benutzer
        if !gehoert_uns(&pfad, eigene_uid) {
            continue;
        }
        // (c) zweifelsfrei unseres -- VOR (b) geprüft, weil es die billigere
        // und die entscheidende Bedingung ist.
        if !ist_unser_backend_buendel(&pfad) {
            continue;
        }
        // (b) von keinem laufenden Prozess gehalten
        if gehaltene.iter().any(|g| g == &pfad) {
            continue;
        }
        gefunden.push(VerwaistesBuendel { pfad });
    }
    gefunden
}

fn gehoert_uns(pfad: &Path, eigene_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(pfad).is_ok_and(|m| m.uid() == eigene_uid)
}

/// Belegt (c): trägt das Verzeichnis die Datenbeigaben UNSERER Backend-Spec?
fn ist_unser_backend_buendel(pfad: &Path) -> bool {
    pfad.join("help").join("help_content.json").is_file()
        && pfad.join("frontend-dist").join("index.html").is_file()
        && pfad.join("modules").is_dir()
}

/// Sammelt alle `_MEI`-Verzeichnisse, die IRGENDEIN laufender Prozess über
/// eine abgebildete Datei hält. Prozesse fremder Benutzer sind hier nicht
/// lesbar; das ist unschädlich, weil deren Bündel schon an (a) scheitern.
fn gehaltene_buendelpfade() -> Vec<PathBuf> {
    let mut gehalten = Vec::new();
    let Ok(eintraege) = std::fs::read_dir("/proc") else {
        return gehalten;
    };
    for eintrag in eintraege.flatten() {
        let Some(pid) = eintrag
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for zeile in maps.lines() {
            let Some(start) = zeile.find("/_MEI").or_else(|| zeile.find("/tmp/_MEI")) else {
                continue;
            };
            // Ab dem Pfadanfang bis zum Ende der Zeile ist der Dateiname; das
            // Bündelverzeichnis ist der Teil bis zum nächsten Trenner NACH
            // dem _MEI-Namen.
            let Some(pfadbeginn) = zeile[..start + 1].rfind(' ').map(|i| i + 1) else {
                continue;
            };
            let voller = &zeile[pfadbeginn..];
            if let Some(dir) = buendelverzeichnis(Path::new(voller)) {
                if !gehalten.contains(&dir) {
                    gehalten.push(dir);
                }
            }
        }
    }
    gehalten
}

/// Schneidet aus einem Pfad INNERHALB eines Bündels das Bündelverzeichnis
/// selbst heraus (`/tmp/_MEIabc123/lib/x.so` -> `/tmp/_MEIabc123`).
fn buendelverzeichnis(datei: &Path) -> Option<PathBuf> {
    let mut aktuell = datei;
    loop {
        if aktuell
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("_MEI"))
        {
            return Some(aktuell.to_path_buf());
        }
        aktuell = aktuell.parent()?;
    }
}
