"""Tests fuer das GESTUFTE Beenden des Helferprozesses (``_stop_process``).

Anders als die uebrigen Client-Tests fahren diese hier ECHTE Subprozesse -- aber
KEINEN echten Helfer: es genuegen zwei winzige Python-Prozesse mit genau dem
Verhalten, um das es geht (endet von selbst / endet nie). Weder scapy noch
CAP_NET_RAW noch ein Raw-Socket sind dafuer noetig, der Constraint der uebrigen
Testdateien bleibt also gewahrt.

Geprueft wird die Stufung, die auf Windows vorher faktisch fehlte:

* endet der Helfer von SELBST (freundlicher Weg), wird er NICHT hart beendet --
  sein eigener Rueckgabewert bleibt erhalten;
* endet er NICHT von selbst, greift das harte Beenden NACH der Frist und haengt
  nicht;
* die Frist wird wirklich abgewartet, bevor hart zugegriffen wird.

Plattformunabhaengig: keine Erwartung an Signal-Nummern oder Rueckgabewerte des
harten Weges (die unterscheiden sich zwischen Windows und POSIX) -- geprueft wird
das VERHALTEN.
"""

import subprocess
import sys
import threading
import time

import pytest

from infrastructure.sniffd_client import base
from infrastructure.sniffd_client.base import _BaseSubprocessHelper


def _prozess_der_von_selbst_endet() -> "subprocess.Popen[bytes]":
    """Endet nach kurzer Zeit mit Rueckgabewert 0 -- wie ein Helfer am Verbindungsende."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def _prozess_der_nie_endet() -> "subprocess.Popen[bytes]":
    """Endet NIE von selbst -- erzwingt das harte Beenden nach Frist."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time\nwhile True: time.sleep(0.5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def test_freundliches_ende_wird_abgewartet_und_nicht_hart_beendet() -> None:
    """Endet der Helfer von selbst, bleibt sein eigener Rueckgabewert (0) erhalten.

    Das ist der Kern des Befunds: frueher rief ``_cleanup`` sofort ``terminate()``
    und ueberschrieb damit auf Windows das saubere Selbst-Ende (Rueckgabewert 1
    statt 0). Bleibt hier die 0 stehen, hat der freundliche Weg gewonnen.
    """
    proc = _prozess_der_von_selbst_endet()
    helper = _BaseSubprocessHelper()

    helper._stop_process(proc)

    assert proc.returncode == 0, "der freundliche Weg wurde ueberholt -- hart beendet"


def test_hartes_ende_greift_nach_frist_und_haengt_nicht(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Endet der Helfer NICHT von selbst, raeumt das harte Beenden ihn nach der Frist ab.

    Die Frist wird fuer den Test kurz gesetzt (sonst dauert er unnoetig lange);
    geprueft wird, dass ``_stop_process`` zurueckkehrt UND der Prozess wirklich
    tot ist -- also weder haengt noch den sturen Prozess stehen laesst.
    """
    monkeypatch.setattr(base, "_GRACEFUL_EXIT_TIMEOUT_SECS", 0.3)
    proc = _prozess_der_nie_endet()
    helper = _BaseSubprocessHelper()

    t0 = time.monotonic()
    helper._stop_process(proc)
    dauer = time.monotonic() - t0

    assert proc.poll() is not None, "sturer Helfer laeuft noch -- hartes Beenden griff nicht"
    assert dauer < 8.0, f"Abbau haengt ({dauer:.1f}s)"


def test_frist_wird_vor_dem_harten_zugriff_wirklich_abgewartet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Der harte Zugriff erfolgt NICHT sofort, sondern erst NACH dem Warten auf das Selbst-Ende.

    Genau hier lag der Fehler: ``terminate()`` kam ohne jede Wartezeit und gewann
    das Rennen gegen das Selbst-Ende.

    Geprueft wird die REIHENFOLGE, nicht die Wanduhr: aufgezeichnet wird, ob vor
    dem ersten ``terminate()`` ueberhaupt ein ``wait`` mit der Frist stattfand.
    Eine Wanduhr-Messung waere hier untauglich -- unter Last (voller Testlauf)
    schwankt allein schon der Interpreterstart des Hilfsprozesses, was den Test
    unzuverlaessig macht, ohne etwas ueber den Produktivcode auszusagen.
    """
    frist = 0.3
    monkeypatch.setattr(base, "_GRACEFUL_EXIT_TIMEOUT_SECS", frist)
    proc = _prozess_der_nie_endet()
    ablauf: list[str] = []

    echtes_wait = proc.wait
    echtes_terminate = proc.terminate

    def beobachtetes_wait(timeout: float | None = None) -> int:
        # Nur das Warten auf das Selbst-Ende zaehlt (Frist), nicht die kurzen
        # Nachlauf-Waits des harten Weges.
        if timeout == frist:
            ablauf.append("freundlich-gewartet")
        return echtes_wait(timeout=timeout)

    def beobachtetes_terminate() -> None:
        ablauf.append("hart-zugegriffen")
        echtes_terminate()

    monkeypatch.setattr(proc, "wait", beobachtetes_wait)
    monkeypatch.setattr(proc, "terminate", beobachtetes_terminate)

    _BaseSubprocessHelper()._stop_process(proc)

    assert "hart-zugegriffen" in ablauf, "sturer Helfer wurde nie hart beendet"
    assert ablauf.index("freundlich-gewartet") < ablauf.index("hart-zugegriffen"), (
        f"hart zugegriffen, ohne vorher auf das Selbst-Ende zu warten: {ablauf}"
    )
    assert proc.poll() is not None


def test_stop_quittung_wird_vor_dem_kanalschluss_abgewartet() -> None:
    """Nach ``STOP`` faellt der Kanal erst, wenn der Helfer quittiert hat.

    Der Befund aus dem echten Lauf: ``stop()`` sendet ``STOP`` und raeumte
    UNMITTELBAR ab. Der Helfer wollte seine ``STOPPED``-Quittung senden, traf auf
    den bereits geschlossenen Kanal, sein ``sendall`` scheiterte -- und er endete
    mit Rueckgabewert 1 statt 0.

    Geprueft wird ohne echten Helfer: ein Kanal-Doppel schreibt mit, WANN es
    geschlossen wird, und der Reader bekommt die Quittung erst nach einer kurzen
    Verzoegerung. Wird trotzdem vorher geschlossen, faellt der Test.
    """
    ablauf: list[str] = []
    quittung_durch = threading.Event()

    class KanalDoppel:
        def sendall(self, data: bytes, /) -> None:
            pass

        def recv(self, bufsize: int, /) -> bytes:
            raise AssertionError("hier nicht erwartet")

        def settimeout(self, value: float | None, /) -> None:
            pass

        def close(self) -> None:
            ablauf.append("kanal-geschlossen")

    helper = _BaseSubprocessHelper()
    helper._sock = KanalDoppel()  # type: ignore[assignment]
    helper._proc = _prozess_der_nie_endet()
    helper._stop_sent = True

    def reader_der_spaet_quittiert() -> None:
        time.sleep(0.4)  # der Helfer braucht kurz, bis die Quittung raus ist
        ablauf.append("quittung-gesehen")
        helper._stopped_seen.set()
        quittung_durch.set()

    helper._reader = threading.Thread(target=reader_der_spaet_quittiert, daemon=True)
    helper._reader.start()

    try:
        helper._await_stop_ack()
        helper._sock.close()  # type: ignore[union-attr]
    finally:
        quittung_durch.wait(timeout=5)
        proc = helper._proc
        if proc is not None:
            proc.kill()
            proc.wait(timeout=5)

    assert ablauf == ["quittung-gesehen", "kanal-geschlossen"], (
        f"Kanal fiel vor der Quittung -- der Helfer koennte sie nicht mehr senden: {ablauf}"
    )


def test_ohne_gesendetes_stop_wird_nicht_auf_eine_quittung_gewartet() -> None:
    """Wurde nie ``STOP`` gesendet, wartet der Abbau nicht -- es gibt nichts zu quittieren.

    Wichtig fuer die Fehlerpfade (Spawn/Connect gescheitert): dort darf der Abbau
    nicht kuenstlich um die Quittungsfrist verzoegert werden.
    """
    helper = _BaseSubprocessHelper()
    assert helper._stop_sent is False

    t0 = time.monotonic()
    helper._await_stop_ack()
    dauer = time.monotonic() - t0

    assert dauer < 0.5, f"ohne gesendetes STOP wurde {dauer:.2f}s gewartet"


def test_stop_process_auf_bereits_beendetem_prozess_ist_ein_no_op() -> None:
    """Ein schon beendeter Helfer wird nicht noch einmal angefasst (idempotent)."""
    proc = _prozess_der_von_selbst_endet()
    proc.wait(timeout=10)
    vorher = proc.returncode

    _BaseSubprocessHelper()._stop_process(proc)

    assert proc.returncode == vorher
