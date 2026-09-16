"""Desktop-Benachrichtigung via ``osascript`` (macOS) -- AppleScript-Injection geheilt.

Neubau des Altcode ``modules.alerting.notify_macos`` im v2-Kern. Die Desktop-
Notification ist ein EIGENER Belang (osascript/AppleScript) und liegt darum in einer
eigenen Datei, getrennt vom SMTP-Versand (``email_sender.py``).

FEHLER 2 -- APPLESCRIPT-INJECTION (geheilt): Der Altcode baute das AppleScript per
f-String und interpolierte ``title``/``message``/``subtitle`` UNESCAPED in die
String-Literale. Ein ``"`` in einem dieser Werte brach aus dem Literal aus -- und die
Werte stammen aus Geraetenamen, also AUS DEM NETZWERK: eine echte Injection. Hier
werden die Werte -- wie das Schwestermodul ``modules/monitor.py`` -- ueber
``escape_applescript_literal`` fuer das Double-Quoted-Literal escaped, bevor sie in den
Programmtext fliessen. Der Aufruf bleibt ``osascript -e <script>`` als Arg-Liste OHNE
``shell=True`` (keine zusaetzliche Shell-Injection), Timeout 3 s wie Altcode.

PLATTFORM (port-treu): ``osascript`` ist macOS-only. Auf Linux wirft
``subprocess.run(["osascript", ...])`` ``FileNotFoundError`` -- der Aufrufer
(``AlertNotifierAdapter.macos``) faengt das, loggt es und macht best-effort weiter
(Linux-no-op). Diese Funktion selbst schluckt nichts.
"""

import subprocess

from infrastructure.osascript_escape import escape_applescript_literal

# osascript-Timeout wie Altcode modules.alerting.notify_macos (3 s).
_OSASCRIPT_TIMEOUT = 3


def notify_macos(title: str, message: str, subtitle: str = "") -> None:
    """Sendet eine macOS-Desktop-Notification via ``osascript`` (blockierend).

    Die eingebetteten Werte werden fuer das AppleScript-Double-Quoted-Literal escaped
    (kein Ausbruch per ``"``). Die Programmstruktur (``display notification ... with
    title ... sound name "Basso"``) bleibt Altcode-treu. Wirft ``FileNotFoundError``
    auf Systemen ohne ``osascript`` (z. B. Linux) -- der Aufrufer faengt das.
    """
    title_e = escape_applescript_literal(title)
    message_e = escape_applescript_literal(message)
    subtitle_e = escape_applescript_literal(subtitle)
    sub = f'subtitle "{subtitle_e}" ' if subtitle else ""
    script = f'display notification "{message_e}" with title "{title_e}" {sub}sound name "Basso"'
    subprocess.run(
        ["osascript", "-e", script],
        timeout=_OSASCRIPT_TIMEOUT,
        capture_output=True,
    )
