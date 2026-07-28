"""Transportnaht des Sniff-Helfers -- reine stdlib (``socket``/``os``/``tempfile``).

Dieses Modul buendelt AUSSCHLIESSLICH die transportabhaengigen Handgriffe der
Helfer-IPC: Erzeugen/Binden der lauschenden Stelle, Annehmen genau einer
Verbindung, Abraeumen; auf Backendseite das Anlegen des Adress-Ortes, die
Adressbildung, die Bereitschaftsfrage und das Verbinden. Fachlogik, Domaenen-
modelle und Webrahmenwerk-Importe gehoeren NICHT hierher -- die Rahmung selbst
liegt unveraendert in ``protocol.py``.

Der Kanal (``Channel``) ist ein STRUKTURELLER Typ mit genau vier Handgriffen:
``sendall``, ``recv``, ``settimeout``, ``close``. Die Namen sind bewusst die des
``socket.socket``, damit ein gewoehnlicher Socket den Typ OHNE Huelle erfuellt.
Auf Linux/macOS fliesst dadurch weiterhin GENAU dasselbe Objekt wie bisher --
die Gleichheit des Verhaltens ist Bauart, nicht Behauptung.
"""

import os
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Protocol

import structlog

_logger = structlog.get_logger(__name__)

# Praefix des Socket-Verzeichnisses (0700) und Name der Socket-Datei darin.
_SOCKET_DIR_PREFIX = "cernis-sniffd-"
_SOCKET_FILE_NAME = "sniffd.sock"


class Channel(Protocol):
    """Verbundener Kanal mit genau vier Handgriffen.

    Struktureller Typ: ``socket.socket`` erfuellt ihn ohne Adapter, weil die
    Namen bewusst die des Sockets sind.
    """

    def sendall(self, data: bytes, /) -> None:
        """Sendet ALLE Bytes (kein Teil-Send)."""
        ...

    def recv(self, bufsize: int, /) -> bytes:
        """Empfaengt hoechstens ``bufsize`` Bytes (``b""`` am Verbindungsende)."""
        ...

    def settimeout(self, value: float | None, /) -> None:
        """Setzt die Zeitgrenze (``None`` = blockierend)."""
        ...

    def close(self) -> None:
        """Schliesst den Kanal."""
        ...


# -- Helferseite (Server) -----------------------------------------------------


def unlink_quietly(socket_path: str) -> None:
    """Entfernt die Socket-Datei, falls vorhanden -- ohne Krach bei Abwesenheit."""
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _logger.warning("sniffd_unlink_failed", path=socket_path, error=str(exc))


def create_listener(socket_path: str) -> socket.socket:
    """Erzeugt die lauschende Stelle: Vorab-``unlink`` + ungebundener Socket.

    Der Vorab-``unlink`` raeumt eine evtl. verwaiste Socket-Datei weg, sonst
    scheitert ``bind``. GEBUNDEN wird erst in ``bind_listener``: der Aufrufer
    legt den Listener zwischen beiden Schritten in sein ``try``, damit ein
    fehlgeschlagenes ``bind`` weiterhin vom ``finally`` abgeraeumt wird.
    """
    unlink_quietly(socket_path)
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def bind_listener(listener: socket.socket, socket_path: str) -> None:
    """Bindet die lauschende Stelle an die Adresse und horcht (``listen(1)``)."""
    listener.bind(socket_path)
    listener.listen(1)


def accept_one(listener: socket.socket) -> socket.socket:
    """Nimmt GENAU eine Verbindung an und gibt sie zurueck.

    Rueckgabetyp ist bewusst der konkrete Socket (nicht ``Channel``): auf dieser
    Plattform IST der angenommene Kanal ein Socket, und der Aufrufer reicht ihn
    unveraendert weiter. ``socket.socket`` erfuellt ``Channel`` strukturell.
    """
    conn, _addr = listener.accept()
    return conn


def close_listener(listener: socket.socket, socket_path: str) -> None:
    """Raeumt die lauschende Stelle ab: schliessen + Socket-Datei entfernen."""
    listener.close()
    unlink_quietly(socket_path)


# -- Backendseite (Client) ----------------------------------------------------


def create_address_dir() -> str:
    """Legt den Adress-Ort (Socket-Verzeichnis, 0700) an und gibt ihn zurueck.

    ``mkdtemp`` erzeugt mit 0700 -- NICHT world-writable wie ein blankes
    ``/tmp/cernis-sniffd.sock``. Ein ``OSError`` wird an den Aufrufer
    durchgereicht (dort entsteht der Fehlertext).
    """
    return tempfile.mkdtemp(prefix=_SOCKET_DIR_PREFIX)


def address_for_dir(address_dir: str) -> str:
    """Bildet die Adresse aus dem Adress-Ort (Socket-Datei im Verzeichnis)."""
    return str(Path(address_dir) / _SOCKET_FILE_NAME)


def address_ready(socket_path: str) -> bool:
    """``True``, sobald die Adresse bereit ist (Socket-Datei existiert).

    NUR die Bereitschaftsfrage -- die Warteschleife bleibt beim Aufrufer, weil
    sie zusaetzlich den vorzeitigen Tod des Helferprozesses prueft.
    """
    return Path(socket_path).exists()


def connect(socket_path: str) -> socket.socket:
    """Verbindet zur Adresse und gibt den verbundenen Kanal zurueck.

    Rueckgabetyp ist bewusst der konkrete Socket (nicht ``Channel``), analog zu
    ``accept_one``: der Aufrufer haelt ihn unveraendert weiter.
    ``socket.socket`` erfuellt ``Channel`` strukturell.

    Ein ``OSError`` wird an den Aufrufer durchgereicht (dort entsteht der
    Fehlertext).
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    return sock


def remove_address_dir(address_dir: str) -> None:
    """Raeumt den Adress-Ort samt Socket-Datei ab (best-effort, wie bisher)."""
    shutil.rmtree(address_dir, ignore_errors=True)
