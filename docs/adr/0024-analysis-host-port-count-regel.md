# ADR 0024 — analysis-Domäne: Regel `host_port_count` („viele hohe Ports = auffällig")

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine, additive Erweiterung der analysis-Domäne (`domain/analysis`): ein neuer `kind`, eine neue Eval-Funktion, ein neuer `help_kind`, ein neues `Rule`-Feld, eine neue Built-in-Regel. Keine neue Domäne, kein neuer Use-Case, keine Verdrahtung im Composition Root, kein UI, kein Endpunkt, keine Settings-Anbindung.
- **Bezug:** ADR 0012 (analysis-Domäne — `Rule` als Daten, `Observation` wertneutral, Engine als reine Funktion, Dispatch pro `kind`); ADR 0002 (domain bleibt framework-/URL-frei, stdlib + dataclasses + typing); ADR 0021 (`kind`-Feld der Observation); ADR 0022 (Severity-Stufen); CLAUDE.md (keine stillen Fallbacks).

## Kontext

Das Konzept der Auffälligkeits-Engine (§3.3) nennt „viele hohe Ports" als auffälliges Signal: ein Host, der eine große Zahl hoher Ports (oberhalb 1024) offen hält, fällt auf. NAS- und IoT-Geräte halten legitim zwei bis vier hohe Ports offen; jenseits von etwa zehn wird das ungewöhnlich.

Eine naheliegende Formulierung — „alle Ports >1024 sind auffällig" — wurde **verworfen**: sie wäre zu laut, weil praktisch jedes normale Gerät ein paar hohe Ports anbietet. Der gewählte **Anzahl-Ansatz** fängt das eigentliche Signal (auffällig *viele* hohe Ports) ohne diesen Lärm.

Den bestehenden host-Regeln fehlte dafür das Werkzeug: `host_remote_port` matcht eine **feste Portmenge** (`host.open_ports & rule.ports`), `host_new` wertet ein bool aus. Keine Regel-Art ZÄHLT Ports gegen eine Schwelle. Es brauchte daher einen wirklich neuen `kind` — und damit (ADR 0012) genau einen neuen Dispatch-Zweig in der Engine.

## Entscheidung

1. **Neuer `kind="host_port_count"`** (`domain/analysis/rules.py`, `RuleKind`-Union erweitert) mit genau einem neuen Dispatch-Zweig (`case "host_port_count"`) und einer neuen Eval-Funktion `_eval_host_port_count` (`domain/analysis/engine.py`). Struktur exakt nach `_eval_host_remote_port` als Vorlage: subject = `host.ip`, Hosts ohne ip werden übersprungen, pro Host genau EINE Observation.

2. **Neuer `help_kind="many_high_ports"`** (`HelpKind`-Union erweitert): viele hohe Ports sind ein eigenes Hilfe-Thema, kein Fernzugriff — daher ein eigener Schlüssel statt einer Mitnutzung von `remote_access_port`.

3. **Neues `Rule`-Feld `port_floor: int = 0`** (additiv, Default 0 = keine Untergrenze, bestehende Regeln unberührt): nur Ports STRIKT GRÖSSER als dieser Wert zählen. Zusammen mit dem vorhandenen Feld `threshold` (das jetzt auch von `host_port_count` genutzt wird) bildet es die Bedingung: Treffer, wenn die Anzahl der Ports > `port_floor` die Schwelle `threshold` STRIKT überschreitet.

4. **Default-Regel `host_many_high_ports`** in `DEFAULT_RULES`, thematisch direkt hinter `host_remote_access_port` gruppiert (beide werten ein GERÄT anhand seiner offenen Ports aus): `severity="notable"`, `help_kind="many_high_ports"`, `kind="host_port_count"`, `threshold=10`, `port_floor=1024`.

5. **STRIKT größer bei beiden Vergleichen:** ein Port zählt nur bei `port > port_floor`, ein Host trifft nur bei `len(high_ports) > threshold` (analog `pid_connection_count`). Damit ist die Schwelle 10 ein leiser Default **mit Sicherheitsabstand** zu den zwei bis vier hohen Ports realer Geräte; genau 10 Ports treffen noch NICHT.

Die Schwelle 10 ist bewusst konservativ gewählt; sie soll später per UI-Dropdown änderbar sein. Das ist ein **eigener, späterer Schnitt** (Settings + UI) — hier steht nur der fixe, leise Default.

## Konsequenzen

**Positiv**
- **Additiv:** ein neues Feld mit Default, ein neuer `kind`, ein neuer `help_kind`, eine neue Regel, eine neue Eval-Funktion. Bestehende Regeln, Evals und Tests bleiben unberührt; kein Vertrag wird gebrochen, nur erweitert.
- **mypy-strict erzwingt Vollständigkeit:** der `match rule.kind`-Dispatch muss den neuen `case` enthalten, sonst läuft die Engine bei einer `host_port_count`-Regel ohne Rückgabewert auf — kein stiller Fallback.
- **domain bleibt rein:** reine Domänenlogik (stdlib + dataclasses + typing), kein I/O, deterministisch (die Engine sortiert am Ende global nach `(severity, rule_id, subject)`).
- **Severity bleibt `notable`:** „fällt auf", kein Urteil — die Achse-B-orange-Markierung, kein „gefährlich"/„sicher". Die rote Linie aus ADR 0012 bleibt unangetastet.

**Offen / später**
- **Konfigurierbare Schwelle:** Settings-Anbindung + UI-Dropdown für `threshold` (und ggf. `port_floor`) ist ein eigener Schnitt. Bis dahin gilt der fixe Default `threshold=10`, `port_floor=1024`.
