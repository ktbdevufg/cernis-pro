"""Smoke-Test des Helfer-Servers: nur Protokoll-/Lifecycle-Pfad, KEIN echter Sniff.

``serve()`` laeuft in einem Thread auf einer temp-Adresse (``helper_address``). Der Test
verbindet sich ueber die Funktionen aus ``transport.py`` -- er kennt die BAUART des
Kanals also NICHT mehr selbst (AF_UNIX-Socket auf Linux/macOS, benannte Pipe auf
Windows), sondern nur noch die Naht. Geprueft werden PING -> PONG und dass das
Verbindungsende den Server-Thread sauber beendet. KEIN scapy-Import, keine echten
Raw-Sockets -- ein START-Versuch darf an fehlenden Rechten NICHT scheitern (STARTED
ODER ERROR ist beides gueltig).
"""

import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from infrastructure.sniffd.protocol import MessageType, recv_message, send_message
from infrastructure.sniffd.server import serve
from infrastructure.sniffd.transport import (
    address_for_dir,
    address_ready,
    connect,
    create_address_dir,
    remove_address_dir,
)


@pytest.fixture
def helper_address() -> Iterator[str]:
    """Temp-Adresse fuer den Helfer-Kanal -- ueber die Naht statt selbstgebaut.

    Frueher baute der Test den Pfad selbst (``tempfile.mkdtemp()`` + angehaengter
    Dateiname). Das kannte die Bauart des Kanals und war damit auf AF_UNIX
    festgelegt. Jetzt liefert ``create_address_dir``/``address_for_dir`` die
    Adresse -- auf Linux/macOS unveraendert eine Socket-Datei im 0700-Verzeichnis
    (inklusive der kurzen ``$TMPDIR``-Basis wegen des macOS-``sun_path``-Limits von
    104 Zeichen), auf Windows eine benannte Pipe. Teardown raeumt best-effort ab.
    """
    address_dir = create_address_dir()
    try:
        yield address_for_dir(address_dir)
    finally:
        remove_address_dir(address_dir)


def _wait_for_address(address: str, timeout: float = 5.0) -> None:
    """Pollt ueber die Naht, bis die Adresse bereit ist (statt eines festen sleep)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if address_ready(address):
            return
        time.sleep(0.01)
    raise AssertionError(f"Adresse {address} ist nicht innerhalb {timeout}s bereit geworden")


def _connect(address: str, timeout: float = 5.0) -> socket.socket:
    """Verbindet sich ueber die Naht auf den Helfer-Kanal (mit kurzer Retry-Schleife)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return connect(address)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.01)


def test_ping_pong_and_clean_shutdown(helper_address: str) -> None:
    """PING -> PONG; danach Verbindungsende -> Server-Thread endet sauber."""
    server_thread = threading.Thread(target=serve, args=(helper_address,), daemon=True)
    server_thread.start()

    _wait_for_address(helper_address)
    conn = _connect(helper_address)
    try:
        send_message(conn, {"type": MessageType.PING})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] == str(MessageType.PONG)
    finally:
        conn.close()  # Verbindungsende -> Server soll sauber zurueckkehren

    server_thread.join(timeout=5)
    assert not server_thread.is_alive(), "Server-Thread nach Verbindungsende nicht beendet"
    # Adresse ist nach sauberem Shutdown nicht mehr bereit (Socket-Datei entfernt
    # bzw. Pipe-Handle geschlossen).
    assert not address_ready(helper_address)


def test_start_returns_started_or_error(helper_address: str) -> None:
    """START liefert STARTED (falls Rechte) ODER ERROR (ohne Rechte) -- beides gueltig.

    Der Test darf an fehlenden Raw-Socket-Rechten NICHT scheitern. Anschliessend
    schliesst er die Verbindung und erwartet einen sauberen Server-Shutdown.
    """
    server_thread = threading.Thread(target=serve, args=(helper_address,), daemon=True)
    server_thread.start()

    _wait_for_address(helper_address)
    conn = _connect(helper_address)
    try:
        send_message(conn, {"type": MessageType.START})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] in (str(MessageType.STARTED), str(MessageType.ERROR))
    finally:
        conn.close()

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()


def test_start_pcap_returns_started_or_error(helper_address: str) -> None:
    """START_PCAP liefert STARTED (mit Rechten) ODER ERROR (ohne) -- beides gueltig.

    Wie der START-Smoke: ohne Raw-Socket-Rechte/scapy darf der Server NICHT
    crashen, sondern sauber ERROR (oder STARTED, falls Rechte da sind) liefern.
    KEIN echter Sniff wird hier erwartet.
    """
    server_thread = threading.Thread(target=serve, args=(helper_address,), daemon=True)
    server_thread.start()

    _wait_for_address(helper_address)
    conn = _connect(helper_address)
    try:
        send_message(conn, {"type": MessageType.START_PCAP, "max_packets": 10})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] in (str(MessageType.STARTED), str(MessageType.ERROR))
    finally:
        conn.close()

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()


def test_start_lldp_returns_started_or_error_or_neighbors(helper_address: str) -> None:
    """START_LLDP: ohne Rechte ERROR; mit Rechten laeuft der Sniff im Thread.

    Ohne Raw-Socket-Rechte antwortet der Server synchron mit ERROR. Sind die Rechte
    (unerwartet) da, laeuft ``run_lldp_sniff`` im Thread und liefert nach kurzer
    ``duration`` ein NEIGHBORS -- beide Antworten sind hier gueltig; der Test darf
    NICHT an der Umgebung scheitern. Kurze ``duration``, damit der Thread bei
    vorhandenen Rechten zeitnah endet.
    """
    server_thread = threading.Thread(target=serve, args=(helper_address,), daemon=True)
    server_thread.start()

    _wait_for_address(helper_address)
    conn = _connect(helper_address)
    try:
        send_message(conn, {"type": MessageType.START_LLDP, "duration": 0.1})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] in (str(MessageType.ERROR), str(MessageType.NEIGHBORS))
    finally:
        conn.close()

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()


def test_export_pcap_without_packets_returns_not_ok(helper_address: str, tmp_path: Path) -> None:
    """EXPORT_PCAP ohne gesammelte Pakete -> EXPORTED {"ok": false} (deterministisch).

    Ohne vorausgegangenen pcap-Lauf ist die Rohpaket-Sammlung leer; ``export_pcap``
    ist best-effort und liefert dann ``False`` -- unabhaengig von scapy/Rechten,
    daher hart pruefbar. Das Export-Ziel liegt in ``tmp_path``: die Adresse ist auf
    Windows eine Pipe und damit KEIN Verzeichnis, in das sich schreiben liesse.
    """
    server_thread = threading.Thread(target=serve, args=(helper_address,), daemon=True)
    server_thread.start()

    _wait_for_address(helper_address)
    conn = _connect(helper_address)
    try:
        export_path = str(tmp_path / "out.pcap")
        send_message(conn, {"type": MessageType.EXPORT_PCAP, "path": export_path})
        reply = recv_message(conn)
        assert reply is not None
        assert reply["type"] == str(MessageType.EXPORTED)
        assert reply["ok"] is False
    finally:
        conn.close()

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()


def test_created_address_is_restricted_to_current_user() -> None:
    """Die erzeugte Adresse ist AUSSCHLIESSLICH fuer den aktuellen Benutzer zugaenglich.

    Absicherung gegen ein spaeteres stilles Aufweichen der Zugriffsrechte -- dieser
    Test darf NICHT uebersprungen werden und prueft auf JEDER Plattform das jeweils
    Richtige:

    * Windows: die TATSAECHLICHE Zugriffsliste der erzeugten Pipe wird ausgelesen
      (nicht die Absicht geprueft). Erwartet wird eine geschuetzte DACL (``D:P``,
      keine Vererbung) mit GENAU EINEM Eintrag, und zwar fuer den eigenen SID. Ohne
      ausdrueckliche Sicherheitsangabe vergaebe Windows hier zusaetzlich Lesezugriff
      an Jeder (``WD``) und ANONYMOUS LOGON (``AN``) -- genau das darf NICHT
      auftauchen.
    * Linux/macOS: das erzeugte Verzeichnis traegt Rechte 0700 (nur der Eigentuemer).
    """
    address_dir = create_address_dir()
    try:
        if sys.platform == "win32":
            from infrastructure.sniffd.transport import (
                address_acl_of_listener,
                close_listener,
                create_listener,
            )

            address = address_for_dir(address_dir)
            listener = create_listener(address)
            try:
                acl = address_acl_of_listener(listener)
            finally:
                close_listener(listener, address)

            # Vererbung ausgeschlossen: geschuetzte DACL.
            assert "D:P" in acl, f"DACL nicht geschuetzt (keine Vererbungssperre): {acl}"
            # Weder Jeder noch ANONYMOUS LOGON duerfen einen Eintrag haben.
            assert ";;;WD)" not in acl, f"Jeder (WD) hat Zugriff auf die Pipe: {acl}"
            assert ";;;AN)" not in acl, f"ANONYMOUS LOGON (AN) hat Zugriff auf die Pipe: {acl}"
            # Genau EIN Eintrag in der DACL -- und der gehoert dem eigenen SID.
            dacl = acl[acl.index("D:P") :]
            assert dacl.count("(A;") == 1, f"DACL hat mehr als einen Eintrag: {acl}"
            assert dacl.count("(D;") == 0, f"DACL enthaelt Deny-Eintraege: {acl}"
            own_sid = _current_process_sid()
            assert f";;;{own_sid})" in dacl, (
                f"einziger DACL-Eintrag gehoert nicht dem aktuellen Benutzer ({own_sid}): {acl}"
            )
        else:
            mode = Path(address_dir).stat().st_mode & 0o777
            assert mode == 0o700, f"Adress-Verzeichnis hat Rechte {mode:o} statt 700"
    finally:
        remove_address_dir(address_dir)


def _current_process_sid() -> str:
    """SID des aktuellen Benutzers -- nur fuer den Windows-Zweig des ACL-Tests.

    Import UND Aufruf stehen im positiven ``sys.platform``-Guard, genau wie im
    Produktivcode: ``_current_user_sid`` ist in ``transport.py`` selbst innerhalb
    des ``if sys.platform == "win32":``-Blocks definiert. mypy wertet
    ``sys.platform`` statisch aus und behandelt diesen Block auf Nicht-Windows als
    unerreichbar -- der Name existiert dort also gar nicht. Der aufrufende Test
    betritt diesen Zweig zur Laufzeit ohnehin nur auf Windows; der Guard traegt
    dieselbe Aussage zusaetzlich in die statische Pruefung.
    """
    if sys.platform == "win32":
        from infrastructure.sniffd.transport import _current_user_sid

        return _current_user_sid()
    raise AssertionError("nur im Windows-Zweig des ACL-Tests aufrufbar")
