"""Ports der alerting-Domaene: Vertraege fuer Persistenz, Notification, SMTP-Config.

Drei Vertraege, gruppiert nach Belang:

* **Persistenz** -- ``AlertRuleRepository`` (CRUD der Regeln + History save/recent).
  EIN Port fuer BEIDE Tabellen (``alert_rules`` + ``alert_history``): sie liegen in
  derselben DB, gehoeren einer Domaene und werden von einem Adapter mit einem
  ``_ensure_schema`` bedient -- "ein Port = kohaerente Einheit" (Muster
  ``ScanHistoryRepository`` save+list+get). ``save``/``recent`` der History kommen
  mit, auch wenn ``save`` erst von A.5/A.7 genutzt wird (stabil am Altcode
  ``_save_alert_event``/``get_alert_history`` ablesbar).
* **Notification** -- ``AlertNotifierPort`` (macos-Desktop + E-Mail). EIGENER
  alerting-Notifier, KEINE monitoring-Wiederverwendung (independence: jede Domaene
  haelt ihre eigene Notification-Naht; der monitoring-Notifier hat eine andere
  Signatur -- ``notify(MonitorEvent)`` -- und gehoert monitoring).
* **Konfiguration** -- ``SmtpConfigPort`` (laedt die aufgeloeste ``SmtpConfig``).
  Trennt "Config beschaffen" (settings + crypto.decrypt, lebt im A.4-Adapter) von
  "Mail senden" (Notifier). Der A.5-Use-Case kennt settings/crypto NIE -- er ruft
  ``load()`` und reicht das Ergebnis an ``email(...)`` (spiegelt die Altcode-Naht:
  ``smtp_config`` wird von aussen in ``notify_email_with_log`` reingereicht).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster settings/monitoring/
scanning). Vertragspruefung statisch ueber mypy + Verdrahtung im Composition Root.

I/O-/Seiteneffekt-Methoden des Notifiers sind ``async`` (osascript-Subprocess + SMTP
-- blockierend, der Adapter kapselt ueber ``run_in_executor``). Persistenz-Repo und
``SmtpConfigPort.load`` sind ``sync`` (Muster scanning/monitoring: sqlite/settings
schnell genug, kein executor).

``ports/`` kennt NUR ``domain/alerting``-Typen + stdlib. Import von ``domain`` ist
erlaubt; ``modules/``/``infrastructure/`` sind verboten (import-linter "ports kennen
hoechstens domain").
"""

from typing import Any, Protocol

from domain.alerting import AlertEvent, AlertRule, EmailResult, SmtpConfig

# ── Persistenz ────────────────────────────────────────────────────────────


class AlertRuleRepository(Protocol):
    """Persistenz der Alert-Regeln (``alert_rules``) und -Historie (``alert_history``).

    EIN Vertrag fuer beide Tabellen (s. Modul-Docstring). Die int<->bool-Konvertierung
    der Flags (``enabled``/``notify_email``/``notify_macos``) ist Adapter-Sache: der
    Adapter liest SQLite-int 0/1 und baut ``AlertRule`` mit ``bool``, schreibt
    ``bool``->``int`` zurueck. Die Domaene (bool) und der A.1-Altcode-Pfad (int)
    bleiben dadurch beide unberuehrt.
    """

    def get_rules(self) -> list[AlertRule]:
        """Alle Regeln, nach ``id`` aufsteigend sortiert (Altcode ``get_rules``).

        Leere Tabelle -> leere Liste, niemals ``None``. Gegen eine leere-aber-
        initialisierte DB ist das ``[]`` (der Adapter fuehrt ``_ensure_schema``).
        """
        ...

    def add(
        self,
        name: str,
        rule_type: str,
        target: str,
        threshold: int,
        notify_email: bool,
        notify_macos: bool,
    ) -> int:
        """Legt eine Regel an und gibt ihre neue ``id`` (rowid) zurueck.

        ``enabled`` ist beim Anlegen immer ``True`` (Altcode-Default ``enabled=1``);
        ``last_triggered`` startet bei ``0.0``.
        """
        ...

    def update(
        self,
        rule_id: int,
        *,
        name: str | None = None,
        target: str | None = None,
        threshold: int | None = None,
        notify_email: bool | None = None,
        notify_macos: bool | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Aktualisiert die gesetzten Felder einer Regel (Whitelist wie Altcode).

        Nur die uebergebenen (nicht-``None``) Felder werden geschrieben -- exakt die
        Altcode-Whitelist ``{name, enabled, threshold, notify_email, notify_macos,
        target}``. ``rule_type``/``id``/``last_triggered`` sind NICHT aenderbar.
        """
        ...

    def delete(self, rule_id: int) -> None:
        """Loescht eine Regel. Idempotent -- kein Fehler bei fehlender ``id``."""
        ...

    def save_event(self, event: AlertEvent) -> None:
        """Schreibt ein gefeuertes Ereignis in ``alert_history`` und setzt
        ``last_triggered`` der Regel auf ``event.timestamp`` (Altcode
        ``_save_alert_event``). Genutzt von A.5/A.7 (der Schreibpfad ist im Altcode
        tot, wird aber AS-IS migriert)."""
        ...

    def recent(self, limit: int) -> list[AlertEvent]:
        """Die juengsten History-Ereignisse, neueste zuerst (Altcode
        ``get_alert_history``, ``ORDER BY ts DESC LIMIT ?``). Leere/initialisierte
        DB -> ``[]`` (der geheilte Pfad, den A.1 einfriert)."""
        ...

    def clear_all(self) -> None:
        """Leert Alert-Regeln UND -Historie (nur die eigenen Tabellen)."""
        ...


# ── Notification ──────────────────────────────────────────────────────────


class AlertNotifierPort(Protocol):
    """Loest Alert-Notifications aus: Desktop (osascript) und E-Mail (SMTP).

    Eigener alerting-Notifier (s. Modul-Docstring). Beide Methoden ``async``: der
    Adapter kapselt das blockierende ``osascript``-Subprocess bzw. den SMTP-Versand
    ueber ``run_in_executor``.
    """

    async def macos(self, title: str, message: str, subtitle: str = "") -> None:
        """Desktop-Notification (Altcode ``notify_macos`` via osascript).

        Best-effort: ein Fehlschlag ist KEIN Fehler des Aufrufers. Auf Linux ist
        ``osascript`` nicht vorhanden -> no-op. Der Adapter loggt einen unerwarteten
        Fehler (``structlog.warning``) statt ihn zu schlucken (bewusste Abweichung
        vom Altcode-``except: pass``, E.4) oder zu werfen.
        """
        ...

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        """Sendet eine E-Mail ueber die gegebene ``SmtpConfig`` (Altcode
        ``notify_email_with_log``).

        Gibt IMMER ein ``EmailResult`` zurueck (wirft nicht -- der Altcode faengt
        jeden SMTP-Fehler und protokolliert ihn in ``log``). ``EmailResult.success``
        ist exakt der Altcode-``success``-Wert.
        """
        ...


# ── Konfiguration ─────────────────────────────────────────────────────────


class SmtpConfigPort(Protocol):
    """Laedt/speichert die SMTP-Konfiguration (settings + crypto).

    Drei Methoden, eine kohaerente Einheit fuer die ``smtp_config``-Verantwortung
    (Muster ``AlertRuleRepository``: ein Port deckt seine Tabelle/sein Setting ganz ab):
    ``load`` (entschluesselt, fuer den Versand), ``load_raw`` (roh, Cipher -- fuer
    Anzeige/Redaktion/host-to-Pruefung) und ``save`` (Sentinel-Logik + crypto.encrypt).
    """

    def load(self) -> SmtpConfig | None:
        """Liefert die ``SmtpConfig`` mit entschluesseltem Passwort, oder ``None``.

        ``None`` = nicht konfiguriert (kein ``smtp_config``-Setting / leeres dict) --
        legitimer Zustand, kein Fehler. Der Adapter liest den ``smtp_config``-Wert
        ueber den settings-Port, casted ``port`` zu int und entschluesselt das
        ``password``-Feld via ``crypto.decrypt``; der Use-Case sieht weder settings
        noch crypto.
        """
        ...

    def load_raw(self) -> dict[str, Any] | None:
        """Liefert das ROHE ``smtp_config``-dict (Passwort als CIPHER), oder ``None``.

        Fuer Anzeige (GET ``/smtp`` redigiert das Passwort selbst zu ``••••••••``),
        Redaktion und die ``host``/``to``-Leer-Pruefung (400 am api-Rand). Das Passwort
        wird hier NICHT entschluesselt -- der Cipher darf den api-Rand erreichen (er wird
        dort redigiert), der KLARTEXT niemals (dafuer ist ``load`` fuer den Versand da).
        ``None`` = nicht konfiguriert.
        """
        ...

    def save(self, config: dict[str, Any]) -> None:
        """Speichert die SMTP-Config (Sentinel-Logik + ``crypto.encrypt`` aufs Passwort).

        Nimmt das ROHE Client-dict (Wire-naeher als ein typisiertes Objekt -- die
        Sentinel-Erkennung ``password == "••••••••"`` und die Verschluesselung sind
        Adapter-Sache, der Use-Case reicht nur durch). Sentinel-Vertrag (v2-Heilung des
        Altcode-Bugs S7, s. ``infrastructure/alerting/smtp_config.py``): Sentinel ->
        alten Cipher UNVERAENDERT uebernehmen (KEIN re-encrypt); neues Klartext-PW ->
        genau 1x ``encrypt``; leeres PW -> ``""``.
        """
        ...
