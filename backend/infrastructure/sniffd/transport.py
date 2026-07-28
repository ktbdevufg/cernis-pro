"""Transportnaht des Sniff-Helfers -- reine stdlib (``socket``/``os``/``tempfile``/``ctypes``).

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

PLATTFORM-WEICHE (``sys.platform``, NICHT ``hasattr``): Windows besitzt kein
AF_UNIX; dort traegt eine BENANNTE PIPE (``\\\\.\\pipe\\...``) dieselbe Naht. Die
Weiche laeuft ueber ``sys.platform == "win32"``, weil mypy genau DAS statisch
auswertet -- so verschwinden die ``AF_UNIX``-``attr-defined``-Meldungen auf
Windows, und der Windows-Zweig gilt auf Linux/macOS als unerreichbar (Muster wie
in ``sniffd_client/base.py``). Import UND Aufruf der plattformeigenen Teile
liegen INNERHALB des Guards.

Die Rahmung aus ``protocol.py`` traegt ueber die Pipe UNVERAENDERT, weil dort nur
``sendall`` und ``recv`` benutzt werden -- ``protocol.py`` wird NICHT angefasst.
"""

import os
import shutil
import socket
import sys
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
    Namen bewusst die des Sockets sind. Auf Windows erfuellt ihn der
    ``_PipeChannel`` (benannte Pipe) mit derselben Signatur.
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


if sys.platform == "win32":
    # ── Windows: benannte Pipe statt AF_UNIX ────────────────────────────────
    #
    # Import UND Aufruf der plattformeigenen Teile stehen INNERHALB des Guards,
    # damit Linux/macOS ``ctypes.wintypes`` nie laden (dort nicht importierbar).
    import ctypes
    import secrets
    from ctypes import wintypes
    from typing import cast

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    _PIPE_ACCESS_DUPLEX = 0x00000003
    _FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    # UEBERLAPPENDER Betrieb -- NICHT wegoptimieren, siehe ``_PipeChannel``:
    # ohne dieses Flag serialisiert Windows ALLE Zugriffe auf ein Pipe-Handle.
    # Ein Schreibvorgang aus dem Sniff-Thread bliebe dann stehen, solange die
    # Kommando-Schleife im blockierenden Lesen haengt -- genau das Muster von
    # ``server.py`` (LLDP/HIT/PACKET senden, waehrend ``recv_message`` wartet).
    _FILE_FLAG_OVERLAPPED = 0x40000000
    _PIPE_TYPE_BYTE = 0x00000000
    _PIPE_READMODE_BYTE = 0x00000000
    _PIPE_WAIT = 0x00000000
    # Netzzugriff wird schon an der Pipe selbst abgelehnt (zweite Verteidigungs-
    # linie neben der DACL unten).
    _PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _PIPE_BUFFER_SIZE = 65536

    _ERROR_PIPE_CONNECTED = 535
    _ERROR_BROKEN_PIPE = 109
    _ERROR_PIPE_NOT_CONNECTED = 233
    _ERROR_NO_DATA = 232
    _ERROR_OPERATION_ABORTED = 995
    _ERROR_IO_PENDING = 997

    # Ein Verbindungsende meldet Windows je nach Lage unter einem dieser Codes.
    # Sie werden zu ``b""`` -- genau wie ein Socket am EOF, worauf ``protocol.py``
    # baut (dort unterscheidet ``_recv_exactly`` sauberes Ende vom halben Frame).
    _END_OF_PIPE_CODES = (
        _ERROR_BROKEN_PIPE,
        _ERROR_PIPE_NOT_CONNECTED,
        _ERROR_NO_DATA,
        _ERROR_OPERATION_ABORTED,
    )

    _WAIT_OBJECT_0 = 0x00000000
    _WAIT_TIMEOUT = 0x00000102
    _INFINITE = 0xFFFFFFFF

    _SDDL_REVISION_1 = 1
    _SE_KERNEL_OBJECT = 6
    _DACL_SECURITY_INFORMATION = 0x00000004
    _OWNER_SECURITY_INFORMATION = 0x00000001

    _TOKEN_QUERY = 0x0008
    _TOKEN_USER_CLASS = 1

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    class _OVERLAPPED(ctypes.Structure):
        """``OVERLAPPED`` fuer den ueberlappenden Betrieb.

        Jeder Vorgang bekommt eine EIGENE Struktur samt eigenem Ereignis -- so
        stoeren sich gleichzeitiges Lesen und Schreiben nicht gegenseitig.
        """

        _fields_ = (
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        )

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = (("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD))

    class _TOKEN_USER(ctypes.Structure):
        _fields_ = (("User", _SID_AND_ATTRIBUTES),)

    # Alle Prototypen EXPLIZIT: ohne ``argtypes``/``restype`` nimmt ctypes
    # ``c_int`` an und schneidet 64-Bit-Handles/Zeiger ab -- das aeussert sich
    # als "Das Handle ist ungueltig" (WinError 6) statt als Typfehler.
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    _kernel32.LocalFree.restype = wintypes.HLOCAL
    _kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
    ]
    _kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    _kernel32.ConnectNamedPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    _kernel32.CreateEventW.argtypes = [
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    _kernel32.CreateEventW.restype = wintypes.HANDLE
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    ]
    _kernel32.GetOverlappedResult.restype = wintypes.BOOL
    _kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED)]
    _kernel32.CancelIoEx.restype = wintypes.BOOL
    _kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    _kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetSecurityInfo.restype = wintypes.DWORD

    def _current_user_sid() -> str:
        """Liefert den SID des aktuellen Benutzers als Text (z. B. ``S-1-5-21-...``).

        Grundlage der Sicherheitsangabe: nur DIESER SID bekommt Zugriff auf die
        Pipe. Ein Fehlschlag wird als ``OSError`` gemeldet und verhindert weiter
        oben das Erzeugen der Pipe -- niemals ein Rueckfall auf "kein SID, also
        offen".
        """
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(
            _kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD(0)
            # Erster Aufruf ermittelt nur die benoetigte Puffergroesse.
            _advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not _advapi32.GetTokenInformation(
                token, _TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            token_user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER)).contents
            sid_text = ctypes.c_wchar_p()
            if not _advapi32.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(sid_text)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return str(sid_text.value)
            finally:
                _kernel32.LocalFree(sid_text)
        finally:
            _kernel32.CloseHandle(token)

    def _own_user_only_sddl() -> str:
        """SDDL, das AUSSCHLIESSLICH dem aktuellen Benutzer Vollzugriff gibt.

        ``D:P`` -- ``D`` = DACL, ``P`` = PROTECTED: die Vererbung wird
        ausgeschlossen, es kommt also KEIN geerbter Eintrag hinzu.
        ``(A;;GA;;;<SID>)`` -- genau EIN Allow-ACE mit GENERIC_ALL fuer den
        eigenen SID. Weil sonst nichts in der Liste steht, hat niemand sonst
        Zugriff (kein Everyone, kein ANONYMOUS LOGON).
        """
        return f"D:P(A;;GA;;;{_current_user_sid()})"

    def _security_attributes() -> tuple[_SECURITY_ATTRIBUTES, ctypes.c_void_p]:
        """Baut die ``SECURITY_ATTRIBUTES`` mit der Nur-eigener-Benutzer-DACL.

        SICHERHEIT -- DIESE STELLE NICHT VEREINFACHEN ODER ENTFERNEN:
        Wird eine benannte Pipe OHNE ausdrueckliche Sicherheitsangabe erzeugt
        (``lpSecurityAttributes = NULL``), vergibt Windows die Default-DACL des
        Prozess-Tokens. GEMESSEN sieht die so aus:

            D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<eigener SID>)
              (A;;FR;;;WD)(A;;FR;;;AN)

        ``WD`` = Jeder (Everyone) und ``AN`` = ANONYMOUS LOGON bekommen dabei
        LESEZUGRIFF auf die Pipe -- jeder lokale Benutzer koennte die IPC des
        Helfers mitlesen. Die heutige Linux-/macOS-Naht schuetzt ueber ein
        Verzeichnis mit Rechten 0700; der Windows-Weg darf dahinter NICHT
        zurueckfallen. Mit der Angabe unten bleibt GEMESSEN genau EIN Eintrag:

            D:P(A;;FA;;;<eigener SID>)

        Darum: Die Sicherheitsangabe ist PFLICHT. Scheitert sie, wird KEINE Pipe
        erzeugt, sondern ein ehrlicher Fehler gemeldet (S3: keine stillen
        Fallbacks) -- eine offene Pipe ist auch voruebergehend unzulaessig.
        ``bInheritHandle = False`` haelt das Handle zusaetzlich aus Kindprozessen
        heraus.
        """
        descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _own_user_only_sddl(), _SDDL_REVISION_1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = _SECURITY_ATTRIBUTES()
        attributes.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
        attributes.lpSecurityDescriptor = descriptor
        attributes.bInheritHandle = False
        return attributes, descriptor

    def describe_address_acl(handle: int) -> str:
        """Liest die TATSAECHLICHE Zugriffsliste eines Pipe-Handles als SDDL-Text.

        Nicht fuer den Betrieb, sondern fuer den Nachweis: der Test liest damit
        aus, was das Betriebssystem wirklich gesetzt hat, statt der Absicht zu
        vertrauen.
        """
        descriptor = ctypes.c_void_p()
        status = _advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            _SE_KERNEL_OBJECT,
            _DACL_SECURITY_INFORMATION | _OWNER_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if status != 0:
            raise ctypes.WinError(status)
        try:
            text = ctypes.c_wchar_p()
            if not _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                _SDDL_REVISION_1,
                _DACL_SECURITY_INFORMATION | _OWNER_SECURITY_INFORMATION,
                ctypes.byref(text),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return str(text.value)
            finally:
                _kernel32.LocalFree(text)
        finally:
            _kernel32.LocalFree(descriptor)

    class _PipeChannel:
        """Verbundener Pipe-Kanal -- erfuellt ``Channel`` mit denselben vier Namen.

        Bildet die Socket-Semantik nach, auf die ``protocol.py`` baut:
        ``sendall`` schreibt ALLE Bytes, ``recv`` liefert ``b""`` am
        Verbindungsende (statt einer Ausnahme), ``settimeout`` setzt die
        Lese-Zeitgrenze.

        UEBERLAPPENDER BETRIEB -- TRAGEND, NICHT VEREINFACHEN:
        Alle Zugriffe laufen ueber ``OVERLAPPED``-Vorgaenge, jeder mit EIGENEM
        Ereignis. Grund: ``server.py`` schreibt aus dem Sniff-Thread
        (HIT/PACKET/NEIGHBORS), WAEHREND die Kommando-Schleife im Lesen wartet --
        beides auf DEMSELBEN Handle. Bei synchronem Betrieb serialisiert Windows
        diese Zugriffe: das Schreiben bliebe stehen, bis das Lesen zurueckkehrt,
        und der Helfer antwortete nie (GEMESSEN: ``WinError 233`` bzw. ein
        haengender LLDP-Lauf). Der ueberlappende Betrieb ist die dokumentierte
        Loesung dafuer und der Grund, warum die Naht ohne Aenderung an
        ``server.py``/``protocol.py`` traegt.

        Die Zeitgrenze kommt dadurch ohne Poll aus: ``WaitForSingleObject`` auf
        das Ereignis des Lesevorgangs wartet genau so lange wie erlaubt.
        """

        def __init__(self, handle: int, *, is_server: bool) -> None:
            self._handle: int | None = handle
            self._is_server = is_server
            self._timeout: float | None = None

        @property
        def handle(self) -> int:
            """Rohes Handle -- nur fuer die ACL-Pruefung im Test."""
            return self._require_handle()

        def sendall(self, data: bytes, /) -> None:
            """Schreibt ALLE Bytes; ein Teil-Write wird nachgezogen."""
            handle = self._require_handle()
            buffer = bytearray(data)
            total = 0
            while total < len(buffer):
                chunk = (ctypes.c_char * (len(buffer) - total)).from_buffer(buffer, total)
                written = self._run_overlapped(
                    handle, _kernel32.WriteFile, chunk, len(buffer) - total, None
                )
                if written == 0:
                    raise OSError("Pipe-Schreibvorgang hat 0 Bytes geschrieben")
                total += written

        def recv(self, bufsize: int, /) -> bytes:
            """Liest hoechstens ``bufsize`` Bytes; ``b""`` am Verbindungsende.

            Ist eine Zeitgrenze gesetzt und laeuft sie ab, wird -- wie beim
            Socket -- ein ``TimeoutError`` geworfen.
            """
            handle = self._require_handle()
            buffer = ctypes.create_string_buffer(bufsize)
            read = self._run_overlapped(handle, _kernel32.ReadFile, buffer, bufsize, self._timeout)
            return buffer.raw[:read]

        def _run_overlapped(
            self,
            handle: int,
            operation: object,
            buffer: object,
            size: int,
            timeout: float | None,
        ) -> int:
            """Fuehrt EINEN ueberlappenden Vorgang aus und liefert die Byte-Zahl.

            Jeder Aufruf bekommt ein eigenes Ereignis und eine eigene
            ``OVERLAPPED``-Struktur -- nur so koennen Lesen und Schreiben auf
            demselben Handle gleichzeitig laufen. Ein Verbindungsende meldet sich
            als ``0`` Bytes (der Aufrufer macht daraus ``b""``), eine
            ueberschrittene Zeitgrenze als ``TimeoutError``.
            """
            event = _kernel32.CreateEventW(None, True, False, None)
            if not event:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                overlapped = _OVERLAPPED()
                overlapped.hEvent = event
                transferred = wintypes.DWORD(0)
                ok = operation(  # type: ignore[operator]
                    wintypes.HANDLE(handle),
                    buffer,
                    size,
                    ctypes.byref(transferred),
                    ctypes.byref(overlapped),
                )
                if not ok:
                    code = ctypes.get_last_error()
                    if code in _END_OF_PIPE_CODES:
                        return 0  # sauberes Verbindungsende -- wie ein Socket
                    if code != _ERROR_IO_PENDING:
                        raise ctypes.WinError(code)
                    self._await_overlapped(handle, overlapped, event, timeout)
                if not _kernel32.GetOverlappedResult(
                    wintypes.HANDLE(handle),
                    ctypes.byref(overlapped),
                    ctypes.byref(transferred),
                    False,
                ):
                    code = ctypes.get_last_error()
                    if code in _END_OF_PIPE_CODES:
                        return 0
                    raise ctypes.WinError(code)
                return int(transferred.value)
            finally:
                _kernel32.CloseHandle(event)

        def _await_overlapped(
            self,
            handle: int,
            overlapped: "_OVERLAPPED",
            event: int,
            timeout: float | None,
        ) -> None:
            """Wartet auf das Ende des Vorgangs; bricht ihn bei Zeitueberschreitung ab.

            Der Abbruch (``CancelIoEx``) ist Pflicht: bliebe der Vorgang stehen,
            schriebe der Kern spaeter in einen Puffer, den es nicht mehr gibt.
            """
            wait = _INFINITE if timeout is None else int(timeout * 1000)
            status = _kernel32.WaitForSingleObject(wintypes.HANDLE(event), wait)
            if status == _WAIT_OBJECT_0:
                return
            if status == _WAIT_TIMEOUT:
                _kernel32.CancelIoEx(wintypes.HANDLE(handle), ctypes.byref(overlapped))
                # Auf den abgebrochenen Vorgang warten, damit der Puffer
                # nachweislich frei ist, bevor er verworfen wird.
                done = wintypes.DWORD(0)
                _kernel32.GetOverlappedResult(
                    wintypes.HANDLE(handle),
                    ctypes.byref(overlapped),
                    ctypes.byref(done),
                    True,
                )
                raise TimeoutError("Zeitgrenze beim Lesen der Pipe erreicht")
            raise ctypes.WinError(ctypes.get_last_error())

        def settimeout(self, value: float | None, /) -> None:
            """Setzt die Lese-Zeitgrenze (``None`` = blockierend)."""
            self._timeout = value

        def close(self) -> None:
            """Schliesst den Kanal (idempotent), serverseitig mit sauberem Trennen."""
            handle = self._handle
            self._handle = None
            if handle is None:
                return
            if self._is_server:
                # Erst die gepufferten Bytes rausschieben, dann trennen -- sonst
                # verliert die Gegenseite die letzte Nachricht.
                _kernel32.FlushFileBuffers(wintypes.HANDLE(handle))
                _kernel32.DisconnectNamedPipe(wintypes.HANDLE(handle))
            _kernel32.CloseHandle(wintypes.HANDLE(handle))

        def _require_handle(self) -> int:
            if self._handle is None:
                raise OSError("Pipe-Kanal ist bereits geschlossen")
            return self._handle

    class _PipeListener:
        """Lauschende Pipe-Instanz -- Gegenstueck zum lauschenden Socket.

        Haelt das Server-Handle zwischen ``create_listener`` und ``accept_one``.
        Die Pipe entsteht bereits in ``create_listener`` (mit Sicherheitsangabe),
        weil erst ihre Existenz die Bereitschaft anzeigt -- ``bind_listener``
        hat auf Windows daher nichts mehr zu tun.
        """

        def __init__(self, handle: int, name: str) -> None:
            self.handle: int | None = handle
            self.name = name

        def close(self) -> None:
            handle = self.handle
            self.handle = None
            if handle is not None:
                _kernel32.CloseHandle(wintypes.HANDLE(handle))

    def _pipe_name(address: str) -> str:
        """Bildet den vollen Pipe-Namen aus der uebergebenen Kennung.

        Der Aufrufer reicht dieselbe Zeichenkette durch, die
        ``address_for_dir`` geliefert hat -- ist sie bereits ein Pipe-Name,
        bleibt sie unveraendert.
        """
        if address.startswith("\\\\.\\pipe\\") or address.startswith("//./pipe/"):
            return address
        return f"\\\\.\\pipe\\{address}"

    def unlink_quietly(socket_path: str) -> None:
        """Auf Windows ohne Wirkung: eine Pipe hat keine Datei im Dateisystem.

        Sie verschwindet, sobald das letzte Handle geschlossen ist. Muss aber
        ohne Fehler durchlaufen, weil die Aufrufer sie unveraendert rufen.
        """

    def create_listener(socket_path: str) -> "_PipeListener":
        """Erzeugt die lauschende Pipe MIT ausdruecklicher Sicherheitsangabe.

        Anders als beim Socket entsteht die Pipe schon hier: ihre blosse Existenz
        ist die Bereitschaft, die ``address_ready`` abfragt. ``bind_listener``
        bleibt darum auf Windows ein Nichts-Tuer.

        Scheitert die Sicherheitsangabe, wird KEINE Pipe erzeugt (siehe die
        Begruendung in ``_security_attributes``).
        """
        name = _pipe_name(socket_path)
        attributes, descriptor = _security_attributes()
        try:
            handle = _kernel32.CreateNamedPipeW(
                name,
                _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE | _FILE_FLAG_OVERLAPPED,
                _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT | _PIPE_REJECT_REMOTE_CLIENTS,
                1,  # genau EINE Instanz -- ein Backend, eine Sniff-Session
                _PIPE_BUFFER_SIZE,
                _PIPE_BUFFER_SIZE,
                0,
                ctypes.byref(attributes),
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            # Der Deskriptor ist nach ``CreateNamedPipeW`` in das Objekt kopiert.
            _kernel32.LocalFree(descriptor)
        return _PipeListener(handle, name)

    def bind_listener(listener: "_PipeListener", socket_path: str) -> None:
        """Auf Windows ohne Wirkung -- die Pipe wurde in ``create_listener`` erzeugt.

        Die Aufrufform bleibt erhalten, damit ``server.py`` seine Ablauffolge
        NICHT aendern muss.
        """

    def accept_one(listener: "_PipeListener") -> socket.socket:
        """Nimmt GENAU eine Verbindung an und gibt den verbundenen Kanal zurueck.

        Der Rueckgabetyp bleibt ABSICHTLICH ``socket.socket``: ``protocol.py``
        annotiert seine Parameter so und wird NICHT geaendert; die Aufrufer
        (``server.py``) bleiben dadurch unveraendert. Das gelieferte Objekt ist
        real ein ``_PipeChannel`` und erfuellt ``Channel`` strukturell -- der
        ``cast`` sagt genau das und bleibt auf dieses Modul beschraenkt.
        """
        if listener.handle is None:
            raise OSError("Pipe-Listener ist bereits geschlossen")
        # Auch das Annehmen laeuft ueberlappend (die Pipe wurde so erzeugt) und
        # wartet dann auf sein Ereignis -- ohne Zeitgrenze, wie ``accept`` beim
        # Socket.
        event = _kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            overlapped = _OVERLAPPED()
            overlapped.hEvent = event
            if not _kernel32.ConnectNamedPipe(
                wintypes.HANDLE(listener.handle), ctypes.byref(overlapped)
            ):
                code = ctypes.get_last_error()
                # Verbindet sich der Client, BEVOR ``ConnectNamedPipe`` laeuft,
                # meldet Windows das als ERROR_PIPE_CONNECTED -- Erfolg, kein Fehler.
                if code == _ERROR_IO_PENDING:
                    if (
                        _kernel32.WaitForSingleObject(wintypes.HANDLE(event), _INFINITE)
                        != _WAIT_OBJECT_0
                    ):
                        raise ctypes.WinError(ctypes.get_last_error())
                elif code != _ERROR_PIPE_CONNECTED:
                    raise ctypes.WinError(code)
        finally:
            _kernel32.CloseHandle(event)
        # Das Listener-Handle IST der verbundene Kanal (eine Instanz); der Kanal
        # uebernimmt es, der Listener gibt es ab, damit es nur EINMAL geschlossen
        # wird.
        handle = listener.handle
        listener.handle = None
        return cast(socket.socket, _PipeChannel(handle, is_server=True))

    def close_listener(listener: "_PipeListener", socket_path: str) -> None:
        """Raeumt die lauschende Stelle ab (idempotent, auch nach ``accept_one``)."""
        listener.close()

    def create_address_dir() -> str:
        """Liefert eine eindeutige, nicht erratbare Kennung -- KEIN Verzeichnis.

        Auf Windows lebt die Pipe im Namensraum des Systems, nicht im
        Dateisystem; es gibt also nichts anzulegen. Der Zufallsanteil
        (``secrets.token_hex``) macht den Namen unerratbar -- den Zugriff regelt
        aber die DACL, nicht die Unkenntnis des Namens.
        """
        return f"{_SOCKET_DIR_PREFIX}{os.getpid()}-{secrets.token_hex(16)}"

    def address_for_dir(address_dir: str) -> str:
        """Bildet den vollen Pipe-Namen aus der Kennung."""
        return _pipe_name(address_dir)

    def address_ready(socket_path: str) -> bool:
        """``True``, sobald sich die Pipe verbinden liesse.

        Statt der Existenz einer Datei wird ``WaitNamedPipeW`` mit sehr kurzer
        Wartezeit gefragt. Die Warteschleife bleibt UNVERAENDERT beim Aufrufer,
        samt seiner Pruefung auf den vorzeitigen Tod des Helferprozesses.
        """
        return bool(_kernel32.WaitNamedPipeW(_pipe_name(socket_path), 1))

    def connect(socket_path: str) -> socket.socket:
        """Verbindet zur Pipe und gibt den verbundenen Kanal zurueck.

        Rueckgabetyp ``socket.socket`` aus demselben Grund wie bei
        ``accept_one``. Ein Fehlschlag kommt als ``OSError`` beim Aufrufer an
        (dort entsteht der Fehlertext) -- ``ctypes.WinError`` liefert genau das.
        """
        name = _pipe_name(socket_path)
        handle = _kernel32.CreateFileW(
            name,
            _GENERIC_READ | _GENERIC_WRITE,
            0,  # kein Teilen -- niemand sonst haengt sich an dieses Handle
            None,
            _OPEN_EXISTING,
            # Ueberlappend wie die Serverseite: der Backend-Client liest im
            # Reader-Thread, waehrend der Adapter Befehle schreibt.
            _FILE_FLAG_OVERLAPPED,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return cast(socket.socket, _PipeChannel(handle, is_server=False))

    def remove_address_dir(address_dir: str) -> None:
        """Auf Windows ohne Wirkung -- es wurde kein Verzeichnis angelegt.

        Die Pipe verschwindet mit dem letzten geschlossenen Handle. Muss
        fehlerfrei durchlaufen, weil der Aufrufer sie unveraendert ruft.
        """

    def address_acl_of_listener(listener: "_PipeListener") -> str:
        """SDDL-Text der tatsaechlichen Zugriffsliste der lauschenden Pipe (Nachweis)."""
        if listener.handle is None:
            raise OSError("Pipe-Listener ist bereits geschlossen")
        return describe_address_acl(listener.handle)

else:
    # ── Linux/macOS: AF_UNIX-Socket -- ZEICHENGLEICH wie bisher ─────────────
    #
    # Hier fliesst weiterhin GENAU dasselbe ``socket.socket``-Objekt wie vor der
    # Windows-Naht; an diesem Zweig hat sich inhaltlich NICHTS geaendert.

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
