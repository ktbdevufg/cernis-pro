"""Naht-Test der acht Linux-Betreuerskripte unter ``src-tauri/``.

DER BEFUND (S85-A2, Befunde 39/40/41/43 und die Linux-Seite von 57): die
Paketskripte sind der einzige Teil der Auslieferung, den weder ruff noch mypy
noch pytest bisher angefasst haben -- es sind Shell-Dateien, die erst beim
Paketbau eingebettet werden. Genau dort standen die vier Fehler:

BEFUND 41 (preinst)
    ``killall -9 cernis-backend`` traf ueber den NAMEN und erschlug damit auch
    einen gleichnamigen fremden Prozess; SIGKILL sofort, ohne geordnetes Ende;
    danach ein geratenes ``sleep 1``.

BEFUND 40 (postinst)
    ``setcap ... 2>/dev/null || true`` verwarf Fehlerausgabe UND Rueckgabewert.
    Ein Fehlschlag ging als Erfolg durch.

BEFUND 57 (prerm)
    Es gab ueberhaupt kein prerm. Beim Entfernen und beim Upgrade wurden
    laufenden Programmen die Dateien entzogen.

BEFUND 43 + 39 (postrm)
    Es gab ueberhaupt kein postrm: ``/usr/share/licenses/cernis-pro`` blieb als
    leeres Verzeichnis zurueck (rpm fuehrt dafuer keinen Verzeichniseintrag),
    und der Benutzer erfuhr nicht, dass seine Daten erhalten bleiben.

WARUM AUS pytest, obwohl es Shell ist: dieselbe Ueberlegung wie in
``test_lizenzanzeige_texte_naht.py`` -- die CI faehrt pytest, und ein Test, den
niemand faehrt, ist keiner. Die Skripte werden dazu WIRKLICH ausgefuehrt, nicht
nach Textmustern durchsucht: eine Textsuche haette den ``$?``-Fehler nach dem
if-Konstrukt nicht gefunden, ein echter Lauf findet ihn.

WARUM NIE GEGEN DAS ECHTE ``/usr/bin``: die Beende-Funktion lernt ihr
Installationsverzeichnis aus der Variablen ``_CERNIS_BINDIR``. Fuer den Test
wird genau diese eine Zeile auf ``tmp_path`` umgebogen. Auf einer Maschine, auf
der CERNIS PRO installiert ist und laeuft, wuerde ein Test gegen ``/usr/bin``
sonst die laufende Anwendung beenden.
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

_WURZEL = Path(__file__).resolve().parents[2]
_TAURI = _WURZEL / "src-tauri"

# Die drei ausgelieferten Programme, in der Reihenfolge, in der sie beendet
# werden muessen: Oberflaeche -> Backend -> Sniff-Helfer.
_PROGRAMME = ("cernis-pro", "cernis-backend", "cernis-sniffd")

_PREINST = ("deb-preinst.sh", "rpm-preinst.sh")
_POSTINST = ("deb-postinst.sh", "rpm-postinst.sh")
_PRERM = ("deb-prerm.sh", "rpm-prerm.sh")
_POSTRM = ("deb-postrm.sh", "rpm-postrm.sh")
_ALLE = _PREINST + _POSTINST + _PRERM + _POSTRM

# Der Hinweis aus Befund 39, Zeile fuer Zeile im vorgegebenen Wortlaut. Mit
# echten Umlauten in "Oberfläche" und "gelöscht" -- der Text ist nutzersichtbar.
_HINWEIS = (
    "CERNIS PRO wurde entfernt. Ihre Daten bleiben erhalten:",
    "~/.local/share/cernis-pro (Scans, Einstellungen) und "
    "~/.local/share/de.cernis.pro (Oberfläche).",
    "Diese Verzeichnisse liegen je Benutzer und werden von der Paketverwaltung "
    "bewusst nicht gelöscht.",
)


def _skript(name: str) -> Path:
    pfad = _TAURI / name
    assert pfad.is_file(), f"Betreuerskript fehlt: {pfad}"
    return pfad


def _fuehre_aus(pfad: Path, *argumente: str) -> subprocess.CompletedProcess[str]:
    """Fuehrt ein Skript mit /bin/sh aus -- dem Interpreter, den auch rpm nimmt.

    Die Standardeingabe ist geschlossen: haengt ein Skript doch an einer
    Eingabe, laeuft der Test in den Timeout statt stillzustehen.
    """
    return subprocess.run(
        ["/bin/sh", str(pfad), *argumente],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("name", _ALLE)
def test_skripte_sind_posix_und_ausfuehrbar(name: str) -> None:
    """Jedes Skript ist syntaktisch gueltiges POSIX-sh und ausfuehrbar.

    WARUM POSIX UND NICHT BASH: das gebaute rpm traegt zu diesen Skripten kein
    ``*PROG``-Tag; rpm fuehrt sie deshalb mit seinem Vorgabe-Interpreter
    /bin/sh aus. Eine bash-Eigenheit fiele erst beim Entfernen auf dem Rechner
    des Benutzers auf.
    """
    pfad = _skript(name)
    assert os.access(pfad, os.X_OK), f"{name} ist nicht ausfuehrbar"
    geprueft = subprocess.run(
        ["/bin/sh", "-n", str(pfad)], capture_output=True, text=True, check=False
    )
    assert geprueft.returncode == 0, f"{name} ist kein gueltiges POSIX-sh: {geprueft.stderr}"


@pytest.mark.parametrize("name", _ALLE)
def test_kein_skript_wartet_auf_eingabe(name: str) -> None:
    """Kein Skript liest von der Standardeingabe.

    Paketentfernung laeuft nicht-interaktiv; ein wartendes Skript blockierte
    die gesamte Paketverwaltung.
    """
    text = _skript(name).read_text(encoding="utf-8")
    ohne_kommentare = "\n".join(
        zeile for zeile in text.splitlines() if not zeile.lstrip().startswith("#")
    )
    assert not re.search(r"\bread\b\s+[-\w]", ohne_kommentare), f"{name} liest von der Eingabe"
    assert "/dev/stdin" not in ohne_kommentare, f"{name} liest von /dev/stdin"


@pytest.mark.parametrize("name", _PREINST + _PRERM)
def test_kein_pauschales_killall_mehr(name: str) -> None:
    """Befund 41: kein killall, kein blindes Signal, kein geratenes sleep 1.

    Geprueft wird der ausfuehrbare Teil ohne Kommentare -- die Kommentare
    nennen ``killall`` absichtlich, um zu erklaeren, was hier frueher stand.
    """
    text = _skript(name).read_text(encoding="utf-8")
    code = "\n".join(z for z in text.splitlines() if not z.lstrip().startswith("#"))
    assert "killall" not in code, f"{name} benutzt weiterhin killall"
    assert not re.search(r"^\s*sleep\s+1\s*$", code, re.MULTILINE), (
        f"{name} enthaelt weiterhin ein pauschales 'sleep 1'"
    )
    # Der exe-Symlink ist das ZWINGENDE Auswahlkriterium, nicht der Name.
    assert "/exe" in code, f"{name} waehlt nicht ueber den exe-Symlink aus"


def _sandkasten_fassung(quelle: Path, bindir: Path, ziel: Path) -> Path:
    """Kopiert ein Skript und biegt NUR ``_CERNIS_BINDIR`` auf den Sandkasten um.

    Alles andere bleibt Zeichen fuer Zeichen wie ausgeliefert -- getestet wird
    das echte Skript, nicht eine Nachbildung.
    """
    text = quelle.read_text(encoding="utf-8")
    ersetzt, anzahl = re.subn(
        r"^_CERNIS_BINDIR='/usr/bin'$",
        f"_CERNIS_BINDIR='{bindir}'",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert anzahl == 1, f"{quelle.name}: _CERNIS_BINDIR nicht gefunden"
    ziel.write_text(ersetzt, encoding="utf-8")
    ziel.chmod(0o755)
    return ziel


@pytest.mark.parametrize("name", _PREINST + _PRERM)
def test_beendet_nur_programme_aus_dem_installationsverzeichnis(name: str, tmp_path: Path) -> None:
    """Der Kern von Befund 41: die Auswahl geht ueber den exe-Symlink.

    Zwei Prozesse mit DEMSELBEN Namen laufen gleichzeitig -- einer aus dem
    (nachgestellten) Installationsverzeichnis, einer aus einem fremden. Nur der
    erste darf beendet werden. Genau diesen Fall traf ``killall`` frueher falsch.
    """
    bindir = tmp_path / "usr" / "bin"
    bindir.mkdir(parents=True)
    fremd = tmp_path / "fremd"
    fremd.mkdir()

    # /usr/bin/sleep ist ein echtes Programm; sein exe-Symlink zeigt nach dem
    # Kopieren auf die Kopie, und genau darum geht es hier.
    shutil.copy2("/bin/sleep", bindir / "cernis-backend")
    shutil.copy2("/bin/sleep", fremd / "cernis-backend")

    installiert = subprocess.Popen([str(bindir / "cernis-backend"), "60"])
    fremder = subprocess.Popen([str(fremd / "cernis-backend"), "60"])
    try:
        fassung = _sandkasten_fassung(_skript(name), bindir, tmp_path / name)
        ergebnis = _fuehre_aus(fassung)
        assert ergebnis.returncode == 0, ergebnis.stderr

        assert installiert.wait(timeout=15) is not None, (
            "der Prozess aus dem Installationsverzeichnis laeuft noch"
        )
        assert fremder.poll() is None, (
            "der gleichnamige Prozess aus einem fremden Verzeichnis wurde "
            "faelschlich beendet -- genau der Fehler von killall"
        )
    finally:
        for prozess in (installiert, fremder):
            if prozess.poll() is None:
                prozess.kill()
            prozess.wait(timeout=10)


@pytest.mark.parametrize("name", _PRERM)
def test_beendet_in_der_vorgegebenen_reihenfolge(name: str, tmp_path: Path) -> None:
    """Reihenfolge cernis-pro -> cernis-backend -> cernis-sniffd.

    Von aussen nach innen entlang der Abhaengigkeitskette: die Oberflaeche ist
    Auftraggeber des Backends, das Backend steuert den Sniff-Helfer. Umgekehrt
    liefe bei jedem Schritt ein Programm auf einen Gespraechspartner, der schon
    weg ist, und meldete einen Fehler statt eines regulaeren Endes.

    Die Programme werden absichtlich in UMGEKEHRTER Reihenfolge gestartet --
    sonst koennte die Startreihenfolge das Ergebnis erklaeren statt des Skripts.
    """
    bindir = tmp_path / "usr" / "bin"
    bindir.mkdir(parents=True)
    protokoll = tmp_path / "reihenfolge.log"

    # Ein Programm, das seinen Namen protokolliert, sobald es SIGTERM bekommt.
    # Python selbst waere ungeeignet: alle drei Kopien haetten denselben
    # exe-Symlink auf den Interpreter. Es muss je eine eigene Programmdatei sein.
    quelle = tmp_path / "melder.c"
    quelle.write_text(
        "#include <signal.h>\n#include <stdio.h>\n#include <unistd.h>\n"
        "static const char *n, *l;\n"
        'static void bei_term(int s){(void)s;FILE*f=fopen(l,"a");'
        'if(f){fprintf(f,"%s\\n",n);fclose(f);}_exit(0);}\n'
        "int main(int c,char**v){if(c<3)return 2;n=v[1];l=v[2];"
        "signal(SIGTERM,bei_term);for(;;)pause();}\n",
        encoding="utf-8",
    )
    melder = tmp_path / "melder"
    uebersetzt = subprocess.run(
        ["cc", "-O0", "-o", str(melder), str(quelle)],
        capture_output=True,
        text=True,
        check=False,
    )
    if uebersetzt.returncode != 0:
        pytest.skip(f"kein C-Uebersetzer verfuegbar: {uebersetzt.stderr.strip()[:200]}")

    laeufer = []
    try:
        for programm in reversed(_PROGRAMME):
            ziel = bindir / programm
            shutil.copy2(melder, ziel)
            laeufer.append(subprocess.Popen([str(ziel), programm, str(protokoll)]))

        # Kurz warten, bis alle drei ihren Signalfaenger gesetzt haben.
        for prozess in laeufer:
            with pytest.raises(subprocess.TimeoutExpired):
                prozess.wait(timeout=0.3)

        fassung = _sandkasten_fassung(_skript(name), bindir, tmp_path / name)
        ergebnis = _fuehre_aus(fassung)
        assert ergebnis.returncode == 0, ergebnis.stderr

        for prozess in laeufer:
            prozess.wait(timeout=15)

        gemeldet = protokoll.read_text(encoding="utf-8").split()
        assert tuple(gemeldet) == _PROGRAMME, (
            f"{name} beendet in der Reihenfolge {gemeldet}, erwartet {list(_PROGRAMME)}"
        )
    finally:
        for prozess in laeufer:
            if prozess.poll() is None:
                prozess.kill()
            prozess.wait(timeout=10)


def _fassung_mit_untergeschobener_pid(
    quelle: Path, bindir: Path, ziel: Path, pid: int, programm: str
) -> Path:
    """Sandkasten-Fassung, deren Ermittlung eine VORGEGEBENE Kennung meldet.

    So wird der Wettlauf aus Befund S85-A5/1 deterministisch: die Ermittlung
    ist vorbei und meldet eine Kennung, die inzwischen einem fremden Programm
    gehoert. Genau das passiert im Betrieb, wenn unser Prozess frueh endet und
    der Kernel seine Nummer neu vergibt -- nur eben nicht auf Zuruf.

    Ersetzt wird allein der RUMPF von ``_cernis_pids_von``. Die Pruefung
    ``_cernis_ist_unseres`` und die gesamte Beendigungslogik bleiben Zeichen
    fuer Zeichen wie ausgeliefert -- sie sind das, was hier auf dem Pruefstand
    steht.
    """
    text = _sandkasten_fassung(quelle, bindir, ziel).read_text(encoding="utf-8")
    ersetzt, anzahl = re.subn(
        r"_cernis_pids_von\(\) \{.*?\n\}\n",
        (
            "_cernis_pids_von() {\n"
            '    if [ "$1" = ' + f"'{programm}'" + " ]; then\n"
            f"        printf '%s\\n' '{pid}'\n"
            "    fi\n"
            "}\n"
        ),
        text,
        count=1,
        flags=re.DOTALL,
    )
    assert anzahl == 1, f"{quelle.name}: _cernis_pids_von nicht gefunden"
    ziel.write_text(ersetzt, encoding="utf-8")
    ziel.chmod(0o755)
    return ziel


@pytest.mark.parametrize("name", _PREINST + _PRERM)
def test_kein_signal_an_eine_neu_vergebene_kennung(name: str, tmp_path: Path) -> None:
    """Befund S85-A5/1: eine inzwischen fremde Kennung bekommt KEIN Signal.

    DER MANGEL: die Kennungen wurden EINMAL ermittelt, danach wurde bis zu zehn
    Sekunden gewartet und erst dann SIGKILL geschickt. Im Warteschritt pruefte
    ``kill -0`` nur, ob die Nummer VERGEBEN ist -- nicht, ob sie noch unsere
    ist. Endet unser Prozess frueh und vergibt der Kernel die Nummer neu, traf
    SIGTERM oder SIGKILL einen fremden Prozessbaum. Das Skript laeuft als
    Verwalter, darf also jeden Prozess auf der Maschine erschlagen.

    DER AUFBAU: die Ermittlung wird so umgebogen, dass sie die Kennung eines
    Prozesses meldet, der NIE unserer war -- sein exe-Symlink zeigt in ein
    fremdes Verzeichnis. Fuer die Beendigungslogik ist das ununterscheidbar von
    einer neu vergebenen Nummer: in beiden Faellen gehoert die Kennung im
    Augenblick des Signals einem anderen Programm.

    ERWARTET: der Fremdprozess ueberlebt, das Skript endet mit null, und der
    Fall wird gemeldet statt stillschweigend uebergangen.
    """
    bindir = tmp_path / "usr" / "bin"
    bindir.mkdir(parents=True)
    fremd = tmp_path / "fremd"
    fremd.mkdir()

    # Der Fremdprozess traegt bewusst DENSELBEN Dateinamen: faellt die Auswahl
    # je auf den Namen zurueck, faellt dieser Test.
    shutil.copy2("/bin/sleep", fremd / "cernis-backend")
    fremder = subprocess.Popen([str(fremd / "cernis-backend"), "60"])
    try:
        fassung = _fassung_mit_untergeschobener_pid(
            _skript(name), bindir, tmp_path / name, fremder.pid, "cernis-backend"
        )
        ergebnis = _fuehre_aus(fassung)

        assert ergebnis.returncode == 0, ergebnis.stderr
        assert fremder.poll() is None, (
            "der fremde Prozess wurde beendet -- eine neu vergebene Kennung "
            "bekommt ein Signal, genau der Mangel aus Befund S85-A5/1"
        )
        assert "neu vergeben" in ergebnis.stderr, (
            "der Fall wird stillschweigend uebergangen statt gemeldet"
        )
        assert str(fremder.pid) in ergebnis.stderr, "die Meldung nennt die Kennung nicht"
    finally:
        if fremder.poll() is None:
            fremder.kill()
        fremder.wait(timeout=10)


@pytest.mark.parametrize("name", _PREINST + _PRERM)
def test_fremde_kennung_haelt_das_warten_nicht_auf(name: str, tmp_path: Path) -> None:
    """Teil 1b: eine fremde Kennung gilt als beendet, nicht als noch laufend.

    Prueft der Warteschritt bloss mit ``kill -0``, so gilt die neu vergebene
    Nummer als "laeuft noch" -- und das Skript wartet die volle Frist von zehn
    Sekunden auf einen Prozess, der nicht der seine ist. Bei drei Programmen
    haelt das eine Paketinstallation um bis zu dreissig Sekunden auf.

    Gemessen wird die Laufzeit: der Fremdprozess laeuft die ganze Zeit weiter,
    das Skript darf trotzdem nicht auf ihn warten.
    """
    bindir = tmp_path / "usr" / "bin"
    bindir.mkdir(parents=True)
    fremd = tmp_path / "fremd"
    fremd.mkdir()

    shutil.copy2("/bin/sleep", fremd / "cernis-backend")
    fremder = subprocess.Popen([str(fremd / "cernis-backend"), "60"])
    try:
        fassung = _fassung_mit_untergeschobener_pid(
            _skript(name), bindir, tmp_path / name, fremder.pid, "cernis-backend"
        )
        begonnen = time.monotonic()
        ergebnis = _fuehre_aus(fassung)
        gedauert = time.monotonic() - begonnen

        assert ergebnis.returncode == 0, ergebnis.stderr
        # Die Frist betraegt 10 s. Alles unter der halben Frist belegt, dass
        # nicht auf den fremden Prozess gewartet wurde; die grosszuegige Grenze
        # laesst Luft fuer eine langsame oder stark belastete Maschine.
        assert gedauert < 5.0, (
            f"das Skript wartete {gedauert:.1f} s auf eine fremde Kennung -- "
            "der Warteschritt prueft die Zugehoerigkeit nicht"
        )
        assert fremder.poll() is None, "der fremde Prozess wurde beendet"
    finally:
        if fremder.poll() is None:
            fremder.kill()
        fremder.wait(timeout=10)


@pytest.mark.parametrize("name", _PREINST + _PRERM)
def test_zugehoerigkeit_wird_vor_jedem_signal_geprueft(name: str, tmp_path: Path) -> None:
    """Teil 1a am Quelltext: kein Signal ohne unmittelbar vorangehende Pruefung.

    Die beiden Tests darueber messen das Verhalten. Dieser haelt die BAUART
    fest: jedes ``kill`` mit einem echten Signal steht innerhalb eines
    ``_cernis_ist_unseres``-Zweiges. Ein spaeterer Umbau, der ein Signal wieder
    ohne Pruefung absetzt, faellt hier auf, auch wenn er zufaellig kein Signal
    an einen fremden Prozess schickt.

    Ausgenommen ist allein ``kill -0``: das stellt nichts zu, es fragt nur, ob
    die Nummer ueberhaupt vergeben ist, und traegt damit die Unterscheidung
    zwischen "beendet" und "neu vergeben".
    """
    text = _skript(name).read_text(encoding="utf-8")
    zeilen = [z for z in text.splitlines() if not z.lstrip().startswith("#")]

    signale = [i for i, z in enumerate(zeilen) if re.search(r"\bkill\s+-(?!0\b)", z)]
    assert signale, f"{name} setzt ueberhaupt kein Signal ab"

    for stelle in signale:
        # Rueckwaerts bis zum naechsten oeffnenden if suchen: es MUSS die
        # Zugehoerigkeitspruefung sein.
        vorangehend = next(
            (z for z in reversed(zeilen[:stelle]) if z.lstrip().startswith("if ")),
            "",
        )
        assert "_cernis_ist_unseres" in vorangehend, (
            f"{name}, Zeile {zeilen[stelle].strip()!r}: das Signal steht nicht "
            f"in einem _cernis_ist_unseres-Zweig, sondern hinter {vorangehend.strip()!r}"
        )


@pytest.mark.parametrize("name", _POSTINST)
def test_setcap_fehlschlag_ist_ein_fehler(name: str, tmp_path: Path) -> None:
    """Befund 40: ein Fehlschlag von setcap darf nicht mehr still gelingen.

    setcap kommt aus einer HARTEN Abhaengigkeit (deb: ``libcap2-bin``, rpm:
    ``(libcap or libcap-progs)``), ist also zugesichert. Schlaegt es trotzdem
    fehl, ist das ein echter Fehler -- das Skript endet mit einem Wert ungleich
    null, und die Meldung nennt Faehigkeit, Datei und Folge.
    """
    ersatz = tmp_path / "bin"
    ersatz.mkdir()
    (ersatz / "setcap").write_text(
        '#!/bin/sh\necho "unable to set CAP_NET_RAW: Operation not supported" >&2\nexit 1\n',
        encoding="utf-8",
    )
    (ersatz / "setcap").chmod(0o755)

    umgebung = dict(os.environ, PATH=f"{ersatz}:{os.environ['PATH']}")
    ergebnis = subprocess.run(
        ["/bin/sh", str(_skript(name))],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=umgebung,
        timeout=60,
        check=False,
    )

    assert ergebnis.returncode != 0, (
        "setcap ist fehlgeschlagen, das Skript meldet trotzdem Erfolg -- "
        "genau der stille Fallback aus Befund 40"
    )
    assert "cap_net_raw" in ergebnis.stderr, "die Meldung nennt die Faehigkeit nicht"
    assert "/usr/bin/cernis-sniffd" in ergebnis.stderr, "die Meldung nennt die Datei nicht"
    assert "Operation not supported" in ergebnis.stderr, (
        "die Fehlerausgabe von setcap wird weiterhin verworfen"
    )
    assert "Folge:" in ergebnis.stderr, "die Meldung nennt die Folge nicht"


@pytest.mark.parametrize("name", _POSTINST)
def test_setcap_erfolg_endet_mit_null(name: str, tmp_path: Path) -> None:
    """Der Gegenpol: gelingt setcap, endet das Skript still mit null."""
    ersatz = tmp_path / "bin"
    ersatz.mkdir()
    (ersatz / "setcap").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (ersatz / "setcap").chmod(0o755)

    umgebung = dict(os.environ, PATH=f"{ersatz}:{os.environ['PATH']}")
    ergebnis = subprocess.run(
        ["/bin/sh", str(_skript(name))],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=umgebung,
        timeout=60,
        check=False,
    )
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert ergebnis.stderr == "", f"unerwartete Fehlerausgabe: {ergebnis.stderr}"


def _postinst_fassung(quelle: Path, ziel: Path, orte: str, sniffd: Path) -> Path:
    """Biegt Ortsliste UND Zieldatei des postinst auf den Sandkasten um.

    BEIDES ist zwingend: liefe der Test gegen das ausgelieferte
    ``/usr/bin/cernis-sniffd``, so setzte er auf einer Maschine mit
    installiertem CERNIS PRO Faehigkeiten auf der echten Programmdatei.
    """
    text = quelle.read_text(encoding="utf-8")
    for muster, ersatz in (
        (r"^_CERNIS_SETCAP_ORTE='[^']*'$", f"_CERNIS_SETCAP_ORTE='{orte}'"),
        (r"^_CERNIS_ZIEL='/usr/bin/cernis-sniffd'$", f"_CERNIS_ZIEL='{sniffd}'"),
    ):
        text, anzahl = re.subn(muster, ersatz, text, count=1, flags=re.MULTILINE)
        assert anzahl == 1, f"{quelle.name}: {muster} nicht gefunden"
    ziel.write_text(text, encoding="utf-8")
    ziel.chmod(0o755)
    return ziel


@pytest.mark.parametrize("name", _POSTINST)
def test_setcap_wird_auch_ohne_suchpfad_erreicht(name: str, tmp_path: Path) -> None:
    """Befund S85-A5/2: setcap muss auch bei knappem Suchpfad erreichbar sein.

    DIE MESSUNG DAHINTER (Wegwerfpaket gegen eine eigene dpkg-Datenbank mit
    ``--admindir``/``--instdir``, dpkg 1.22.6): dpkg setzt fuer Betreuerskripte
    KEINEN eigenen Suchpfad -- es reicht den PATH des Aufrufers durch. Es
    verlangt zwar, dass ``ldconfig`` und ``start-stop-daemon`` erreichbar sind,
    und beide liegen auf Debian/Ubuntu in ``/usr/sbin``; sind sie aber
    anderswoher erreichbar, laeuft dpkg mit einem PATH ohne ``/usr/sbin`` an --
    gemessen. Da das postinst seit Befund 40 hart fehlschlaegt, waere das eine
    fehlgeschlagene Installation beim Anwender.

    Geprueft wird mit einem PATH, der setcap NICHT enthaelt: der Nachschlag auf
    die am Paketinhalt belegten Orte muss greifen.
    """
    ort = tmp_path / "sbin"
    ort.mkdir()
    protokoll = tmp_path / "aufruf.log"
    (ort / "setcap").write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$*" > {protokoll}\nexit 0\n', encoding="utf-8"
    )
    (ort / "setcap").chmod(0o755)

    sniffd = tmp_path / "cernis-sniffd"
    sniffd.write_bytes(b"")
    fassung = _postinst_fassung(_skript(name), tmp_path / name, str(ort / "setcap"), sniffd)

    # Ein PATH, in dem es setcap definitiv NICHT gibt -- der gemessene Fall.
    leer = tmp_path / "leer"
    leer.mkdir()
    ergebnis = subprocess.run(
        ["/bin/sh", str(fassung)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={"PATH": str(leer)},
        timeout=60,
        check=False,
    )

    assert ergebnis.returncode == 0, (
        f"setcap lag ausserhalb des Suchpfads und wurde nicht erreicht: {ergebnis.stderr}"
    )
    assert protokoll.is_file(), "setcap wurde ueberhaupt nicht aufgerufen"
    assert protokoll.read_text(encoding="utf-8").split() == ["cap_net_raw+eip", str(sniffd)], (
        "setcap wurde mit anderen Argumenten aufgerufen als vorgesehen"
    )


@pytest.mark.parametrize("name", _POSTINST)
def test_gar_kein_setcap_bleibt_ein_harter_fehler(name: str, tmp_path: Path) -> None:
    """Der Nachschlag gibt den harten Rueckgabewert NICHT auf.

    Ist setcap weder im Suchpfad noch an einem der belegten Orte, so ist das
    weiterhin ein Fehler mit Wert ungleich null -- kein stiller Rueckfall.
    """
    sniffd = tmp_path / "cernis-sniffd"
    sniffd.write_bytes(b"")
    fassung = _postinst_fassung(
        _skript(name), tmp_path / name, str(tmp_path / "gibtsnicht" / "setcap"), sniffd
    )

    leer = tmp_path / "leer"
    leer.mkdir()
    ergebnis = subprocess.run(
        ["/bin/sh", str(fassung)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={"PATH": str(leer)},
        timeout=60,
        check=False,
    )

    assert ergebnis.returncode != 0, "kein setcap gefunden, das Skript meldet trotzdem Erfolg"
    assert "cap_net_raw" in ergebnis.stderr, "die Meldung nennt die Faehigkeit nicht"
    assert "Folge:" in ergebnis.stderr, "die Meldung nennt die Folge nicht"


def test_setcap_orte_stehen_im_paket_der_harten_abhaengigkeit() -> None:
    """Die Ortsliste ist belegt, nicht geraten.

    ``dpkg -L libcap2-bin`` liefert ``/usr/sbin/setcap``; ``/sbin`` ist auf
    Systemen mit usr-merge ein Symlink darauf und auf aelteren Systemen der
    tatsaechliche Ort. Waechst die Liste je um einen Pfad, den kein Paket
    hergibt, faellt dieser Test -- und genau das soll er.
    """
    for name in _POSTINST:
        text = _skript(name).read_text(encoding="utf-8")
        treffer = re.search(r"^_CERNIS_SETCAP_ORTE='([^']*)'$", text, re.MULTILINE)
        assert treffer is not None, f"{name}: _CERNIS_SETCAP_ORTE fehlt"
        assert treffer.group(1).split() == ["/usr/sbin/setcap", "/sbin/setcap"], (
            f"{name}: die Ortsliste weicht von den belegten Orten ab"
        )


def test_deb_postrm_meldet_bei_endgueltiger_entfernung() -> None:
    """deb: das erste Argument ist eine ZEICHENKETTE (deb-postrm(5)).

    Gemeldet wird allein beim "remove"-Aufruf -- die Begruendung steht in
    ``test_deb_postrm_meldet_bei_purge_genau_einmal``.
    """
    ergebnis = _fuehre_aus(_skript("deb-postrm.sh"), "remove")
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert ergebnis.stdout.splitlines() == list(_HINWEIS)


@pytest.mark.parametrize(
    "grund",
    ["purge", "upgrade", "failed-upgrade", "disappear", "abort-install", "abort-upgrade", ""],
)
def test_deb_postrm_schweigt_bei_allem_anderen(grund: str) -> None:
    """Beim Upgrade waere "CERNIS PRO wurde entfernt" schlicht falsch.

    "purge" steht bewusst in dieser Liste: es ist keine zweite Entfernung,
    sondern der zweite Aufruf DERSELBEN -- siehe den Test darunter.
    """
    argumente = [grund] if grund else []
    ergebnis = _fuehre_aus(_skript("deb-postrm.sh"), *argumente)
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert ergebnis.stdout == "", f"unerwartete Ausgabe bei '{grund}': {ergebnis.stdout}"


def test_deb_postrm_meldet_bei_purge_genau_einmal() -> None:
    """Der Hinweis erscheint bei einem purge genau einmal, nie zweimal.

    DIE MESSUNG DAHINTER (mit einem Wegwerfpaket gegen eine eigene
    dpkg-Datenbank, dpkg 1.22.6): dpkg teilt das Entfernen in zwei Schritte und
    ruft postrm fuer jeden davon auf.

    Fall 1 -- installiertes Paket wird mit purge entfernt::

        postrm remove
        postrm purge

    Fall 2 -- bereits entferntes Paket wird spaeter allein nachbehandelt::

        postrm remove   (beim seinerzeitigen Entfernen)
        postrm purge    (beim spaeteren purge)

    Meldete das Skript bei beiden Argumenten, saehe der Anwender den Hinweis in
    Fall 1 doppelt. Meldet allein "remove", so kommt der Hinweis in BEIDEN
    Faellen auf genau eine Ausgabe -- denn "remove" tritt in beiden genau einmal
    auf. Genau das haelt dieser Test fest, indem er die Aufrufreihenfolge
    nachspielt und die Ausgaben zusammenzaehlt.
    """
    skript = _skript("deb-postrm.sh")
    kopfzeile = _HINWEIS[0]

    for fall, aufrufe in (
        ("Fall 1: installiert -> purge", ("remove", "purge")),
        ("Fall 2: remove, spaeter purge", ("remove", "purge")),
    ):
        gesamt = ""
        for argument in aufrufe:
            ergebnis = _fuehre_aus(skript, argument)
            assert ergebnis.returncode == 0, f"{fall}/{argument}: {ergebnis.stderr}"
            gesamt += ergebnis.stdout

        assert gesamt.count(kopfzeile) == 1, (
            f"{fall}: der Hinweis erscheint {gesamt.count(kopfzeile)}-mal, "
            "erwartet ist genau einmal"
        )
        assert gesamt.splitlines() == list(_HINWEIS), (
            f"{fall}: der Hinweis kam nicht vollstaendig und genau einmal, "
            f"ausgegeben wurde: {gesamt!r}"
        )


def test_rpm_postrm_meldet_nur_bei_null() -> None:
    """rpm: das erste Argument ist eine ZAHL -- die verbleibenden Installationen.

    Belegt an rpm-scriptlets(7): 0 heisst endgueltig entfernt, jede andere Zahl
    heisst Upgrade, Downgrade oder Parallelinstallation.
    """
    ergebnis = _fuehre_aus(_skript("rpm-postrm.sh"), "0")
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert ergebnis.stdout.splitlines() == list(_HINWEIS)


@pytest.mark.parametrize("verbleibend", ["1", "2", "", "00", "abc"])
def test_rpm_postrm_schweigt_bei_allem_anderen(verbleibend: str) -> None:
    """Nur eine echte, rein numerische 0 zaehlt -- im Zweifel wird geschwiegen."""
    argumente = [verbleibend] if verbleibend else []
    ergebnis = _fuehre_aus(_skript("rpm-postrm.sh"), *argumente)
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert ergebnis.stdout == "", f"unerwartete Ausgabe bei '{verbleibend}': {ergebnis.stdout}"


def test_rpm_postrm_entfernt_nur_ein_leeres_lizenzverzeichnis(tmp_path: Path) -> None:
    """Befund 43: das leere Verzeichnis geht, ein befuelltes bleibt.

    Im gebauten rpm ist ``/usr/share/licenses/cernis-pro`` kein eigener
    Verzeichniseintrag -- rpm raeumt es deshalb nicht ab. Entfernt wird es hier
    mit ``rmdir`` ohne ``-p`` und ohne ``-f``: das schlaegt bei jedem Inhalt
    fehl, und dann bleibt das Verzeichnis unangetastet.
    """
    lizenzen = tmp_path / "licenses" / "cernis-pro"
    lizenzen.mkdir(parents=True)

    quelle = _skript("rpm-postrm.sh").read_text(encoding="utf-8")
    ersetzt, anzahl = re.subn(
        r"^_CERNIS_LIZENZVERZEICHNIS='/usr/share/licenses/cernis-pro'$",
        f"_CERNIS_LIZENZVERZEICHNIS='{lizenzen}'",
        quelle,
        count=1,
        flags=re.MULTILINE,
    )
    assert anzahl == 1, "_CERNIS_LIZENZVERZEICHNIS nicht gefunden"
    fassung = tmp_path / "rpm-postrm.sh"
    fassung.write_text(ersetzt, encoding="utf-8")
    fassung.chmod(0o755)

    # Fall A: leer -> wird entfernt.
    ergebnis = _fuehre_aus(fassung, "0")
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert not lizenzen.exists(), "das leere Lizenzverzeichnis blieb stehen"

    # Fall B: nicht leer -> bleibt, und das wird gemeldet.
    lizenzen.mkdir(parents=True)
    fremde_datei = lizenzen / "NOTIZ.txt"
    fremde_datei.write_text("von jemand anderem abgelegt\n", encoding="utf-8")

    ergebnis = _fuehre_aus(fassung, "0")
    assert ergebnis.returncode == 0, ergebnis.stderr
    assert fremde_datei.is_file(), "ein fremder Inhalt wurde geloescht"
    assert "ist nicht leer" in ergebnis.stderr, (
        "das Bestehenbleiben des Verzeichnisses wird nicht gemeldet"
    )


@pytest.mark.parametrize("name", _POSTRM)
def test_postrm_loescht_nichts_unter_einem_heimatverzeichnis(name: str) -> None:
    """Stoppbedingung: kein Betreuerskript loescht Daten unter HOME.

    Das Skript laeuft als Verwalter und kennt die betroffenen Benutzer nicht --
    es koennte die Daten mehrerer Benutzer gleichzeitig vernichten. Der Hinweis
    NENNT die Pfade, angefasst werden sie nicht.
    """
    text = _skript(name).read_text(encoding="utf-8")
    code = "\n".join(z for z in text.splitlines() if not z.lstrip().startswith("#"))
    for gefaehrlich in ("rm -rf", "rm -r", "rm -f"):
        assert gefaehrlich not in code, f"{name} enthaelt '{gefaehrlich}'"
    for zeile in code.splitlines():
        if zeile.lstrip().startswith("echo"):
            continue
        assert "$HOME" not in zeile and "/home/" not in zeile, (
            f"{name} fasst ein Heimatverzeichnis an: {zeile.strip()}"
        )


def test_tauri_konfiguration_fuehrt_alle_vier_skripte() -> None:
    """Alle vier Felder sind fuer deb UND rpm eingetragen, und die Dateien gibt es.

    Die Feldnamen stammen aus ``config.schema.json`` der CLI. Die Konfiguration
    fuehrt ``deny_unknown_fields`` -- ein Tippfehler im Feldnamen ist ein harter
    Baufehler, kein stilles Ignorieren.
    """
    konfiguration = json.loads((_TAURI / "tauri.conf.json").read_text(encoding="utf-8"))
    linux = konfiguration["bundle"]["linux"]

    erwartet = {
        "deb": {
            "preInstallScript": "deb-preinst.sh",
            "postInstallScript": "deb-postinst.sh",
            "preRemoveScript": "deb-prerm.sh",
            "postRemoveScript": "deb-postrm.sh",
        },
        "rpm": {
            "preInstallScript": "rpm-preinst.sh",
            "postInstallScript": "rpm-postinst.sh",
            "preRemoveScript": "rpm-prerm.sh",
            "postRemoveScript": "rpm-postrm.sh",
        },
    }
    for format_name, felder in erwartet.items():
        for feld, dateiname in felder.items():
            assert linux[format_name].get(feld) == dateiname, (
                f"{format_name}.{feld} fehlt oder weicht ab"
            )
            assert (_TAURI / dateiname).is_file(), f"{dateiname} fehlt im Baum"


def test_kein_plattform_overlay_ersetzt_die_skriptfelder() -> None:
    """Ein Overlay, das ``bundle.linux`` fuehrt, wuerde die Felder verdraengen.

    Tauri mischt ``tauri.<plattform>.conf.json`` ueber die Grundkonfiguration.
    Fuehrte eines der Overlays ``bundle.linux.deb`` oder ``bundle.linux.rpm``,
    ersetzte es den ganzen Teilbaum -- und die Skripte fielen still weg.
    """
    for overlay in _TAURI.glob("tauri.*.conf.json"):
        inhalt = json.loads(overlay.read_text(encoding="utf-8"))
        linux = inhalt.get("bundle", {}).get("linux")
        assert linux is None, (
            f"{overlay.name} fuehrt bundle.linux und wuerde die Skriptfelder ersetzen"
        )


def test_setcap_bleibt_eine_harte_abhaengigkeit() -> None:
    """Der Rueckgabewert des postinst haengt an dieser Messung.

    Solange setcap zugesichert ist, ist ein Fehlschlag ein echter Fehler und
    das postinst endet ungleich null. Faellt die Abhaengigkeit je auf
    ``recommends`` zurueck, muss diese Entscheidung neu getroffen werden --
    dieser Test faellt dann und erzwingt genau das.
    """
    konfiguration = json.loads((_TAURI / "tauri.conf.json").read_text(encoding="utf-8"))
    linux = konfiguration["bundle"]["linux"]

    assert "libcap2-bin" in linux["deb"]["depends"], (
        "libcap2-bin steht nicht mehr in den harten deb-Abhaengigkeiten"
    )
    assert "(libcap or libcap-progs)" in linux["rpm"]["depends"], (
        "(libcap or libcap-progs) steht nicht mehr in den harten rpm-Abhaengigkeiten"
    )
