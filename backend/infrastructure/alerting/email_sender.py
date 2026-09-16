"""SMTP-Versand fuer Alert-E-Mails -- TLS ist PFLICHT, kein Klartext-Rueckfall.

Neubau des Altcode ``modules.alerting.notify_email_with_log`` im v2-Kern. Der
Versand ist ein EIGENER Belang (SMTP) und liegt darum in einer eigenen Datei,
getrennt von der Desktop-Notification (``desktop_notifier.py``, osascript).

WAS BLEIBT (der brauchbare Teil des Altcode):
* Das schrittweise Protokoll (``step``/``log``) als Diagnostik -- Aufbau und
  Aussagekraft erhalten, die differenzierte Ausnahmebehandlung am Ende ebenso
  (``SMTPConnectError`` / ``SMTPAuthenticationError`` / ``SMTPException`` /
  ``ConnectionRefusedError`` / ``TimeoutError``).
* Der Rueckgabevertrag ``{"success": bool, "log": list[str]}`` -- die Aufrufer
  (``AlertNotifierAdapter.email`` -> ``EmailResult``) bleiben unveraendert.

WAS SICH AENDERT (zwei belegte Sicherheitsfehler geheilt, ADR-Regel "keine stillen
Fallbacks", CLAUDE.md Finding S3):
* FEHLER 1 -- KLARTEXT-VERSAND: Der Altcode fing einen STARTTLS-Fehlschlag,
  protokollierte "continuing without encryption" und loggte sich dann ueber eine
  UNVERSCHLUESSELTE Verbindung ein -- das SMTP-Passwort ging im Klartext ueber die
  Leitung. Zusaetzlich uebersprang ``port != 25`` STARTTLS auf Port 25 grundsaetzlich.
  BEIDES ist weg. NEUE REGEL: Port 465 ist implizites TLS (``SMTP_SSL``); fuer JEDEN
  anderen Port (587, 25, beliebig) wird STARTTLS ZWINGEND durchgefuehrt. Schlaegt es
  fehl -- aus welchem Grund auch immer, auch wenn der Server es nicht unterstuetzt --
  wird die Verbindung geschlossen und NICHT gesendet: KEIN Login, KEIN Versand ueber
  eine unverschluesselte Verbindung. Es gibt KEINEN Schalter, das abzuwaehlen. Der
  Fehlerfall wird ehrlich gemeldet (``success=False`` + klare Log-Zeile).
* SOCKET-LEAK: ``server.quit()`` steht jetzt in einem ``finally`` -- bricht der
  Versand mit einer Ausnahme ab, bleibt kein SMTP-Socket offen liegen.

Der HTML-Mailtext traegt jetzt ``v2.0.0`` (Altcode: ``v1.0.0``).
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

# Timeout wie Altcode (15 s Connect/IO).
_SMTP_TIMEOUT = 15

# Port 465 ist implizites TLS (SMTPS) -- von Anfang an verschluesselt.
_IMPLICIT_TLS_PORT = 465


def notify_email_with_log(subject: str, body: str, smtp_config: dict[str, Any]) -> dict[str, Any]:
    """Sendet eine E-Mail via SMTP mit schrittweisem Protokoll. Wirft nie.

    Gibt IMMER ``{"success": bool, "log": list[str]}`` zurueck -- jeder Fehler landet
    im Log, ``success`` ist ``True`` nur bei tatsaechlich abgeschicktem Versand ueber
    eine verschluesselte Verbindung.
    """
    log: list[str] = []
    success = False

    def step(msg: str) -> None:
        log.append(msg)

    def _snip(resp: bytes | None) -> str:
        """Kurze, sichere Darstellung einer SMTP-Serverantwort (erste 80 Bytes)."""
        return repr(resp[:80]) if resp else repr(b"")

    host = str(smtp_config.get("host", ""))
    port = int(smtp_config.get("port", 587))
    user = str(smtp_config.get("user", ""))
    password = str(smtp_config.get("password", ""))
    to_addr = str(smtp_config.get("to", ""))
    from_addr = str(smtp_config.get("from") or user)
    use_ssl = port == _IMPLICIT_TLS_PORT

    step(f"Config: host={host}, port={port}, user={user}, from={from_addr}, to={to_addr}")
    # v2: Port 465 -> implizites TLS (SMTPS); JEDER andere Port -> STARTTLS (Pflicht).
    step(f"Mode: {'SMTPS/SSL' if use_ssl else 'STARTTLS (mandatory)'}")

    if not host:
        step("ERROR: SMTP host is empty")
        return {"success": False, "log": log}
    if not to_addr:
        step("ERROR: Recipient address is empty")
        return {"success": False, "log": log}

    # Nachricht bauen.
    step("Building email message...")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CERNIS PRO] {subject}"
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.attach(MIMEText(body, "plain"))
    _div_style = (
        "font-family:monospace;background:#0a0c0f;color:#e8ecf4;padding:20px;border-radius:8px;"
    )
    html_body = f"""
        <div style="{_div_style}">
          <h2 style="color:#00d4ff;margin:0 0 12px">CERNIS PRO Alert</h2>
          <pre style="background:#141820;padding:12px;border-radius:4px;color:#e8ecf4">{body}</pre>
          <p style="color:#4a5a78;font-size:12px;margin-top:12px">CERNIS PRO v2.0.0</p>
        </div>
        """
    msg.attach(MIMEText(html_body, "html"))
    step("Message built OK")

    server: smtplib.SMTP | None = None
    try:
        # Verbinden.
        if use_ssl:
            step(f"Connecting via SMTPS (SSL) to {host}:{port}...")
            server = smtplib.SMTP_SSL(host, port, timeout=_SMTP_TIMEOUT)
        else:
            step(f"Connecting via SMTP to {host}:{port}...")
            server = smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT)

        step(f"Connected. Server banner: {_snip(server.ehlo_resp)}")

        # EHLO.
        step("Sending EHLO...")
        code, resp = server.ehlo()
        step(f"EHLO response: {code} {_snip(resp)}")

        # STARTTLS ist PFLICHT fuer jeden Nicht-SSL-Port (587, 25, beliebig).
        # Schlaegt es fehl -- auch "not supported" --, wird NICHT gesendet.
        if not use_ssl:
            step("Starting TLS (STARTTLS, mandatory)...")
            try:
                code, resp = server.starttls()
                step(f"STARTTLS response: {code} {_snip(resp)}")
            except smtplib.SMTPNotSupportedError:
                step(
                    "ABORT: server does not support STARTTLS -- refusing to send "
                    "over an unencrypted connection (no cleartext login, no send)."
                )
                return {"success": False, "log": log}
            except smtplib.SMTPException as e:
                step(
                    f"ABORT: STARTTLS failed ({e}) -- refusing to send over an "
                    "unencrypted connection (no cleartext login, no send)."
                )
                return {"success": False, "log": log}
            # EHLO nach erfolgreichem STARTTLS wiederholen (die Faehigkeiten aendern sich).
            code, resp = server.ehlo()
            step(f"EHLO after TLS: {code}")

        # Ab hier ist die Verbindung garantiert verschluesselt (SMTPS oder STARTTLS-OK).

        # Login.
        if user and password:
            step(f"Logging in as '{user}'...")
            try:
                code, resp = server.login(user, password)
                step(f"Login OK: {code} {_snip(resp)}")
            except smtplib.SMTPAuthenticationError as e:
                step(f"LOGIN FAILED: {e.smtp_code} {e.smtp_error!r}")
                return {"success": False, "log": log}
        else:
            step("No credentials -- skipping login (anonymous relay)")

        # Senden.
        step(f"Sending email from '{from_addr}' to '{to_addr}'...")
        result = server.sendmail(from_addr, to_addr, msg.as_string())
        if result:
            step(f"Partial failure: {result}")
        else:
            step("Email sent successfully!")
            success = True

    except smtplib.SMTPConnectError as e:
        step(f"CONNECTION FAILED: {e}")
    except smtplib.SMTPAuthenticationError as e:
        step(f"AUTH FAILED: {e.smtp_code} {e.smtp_error!r}")
    except smtplib.SMTPException as e:
        step(f"SMTP ERROR: {e}")
    except ConnectionRefusedError:
        step(f"CONNECTION REFUSED: {host}:{port} -- check host and port")
    except TimeoutError:
        step(f"TIMEOUT: Could not connect to {host}:{port} within {_SMTP_TIMEOUT}s")
    except Exception as e:
        # Best-effort: kein Fehler darf den Aufrufer erreichen (der Vertrag: wirft nie).
        step(f"ERROR: {type(e).__name__}: {e}")
    finally:
        # Verbindungsabbau IMMER -- auch im Fehlerfall (kein Socket-Leak).
        if server is not None:
            try:
                server.quit()
                step("Connection closed.")
            except Exception:
                # quit darf den Rueckgabewert nicht kippen (best-effort).
                step("Connection close failed (ignored).")

    return {"success": success, "log": log}
