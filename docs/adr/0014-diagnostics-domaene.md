# ADR 0014 — diagnostics-Domäne: Frage-Antwort-Werkzeuge (Block 1a: DNS + traceroute)

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Phase:** Grüne Wiese (erste Diagnose-Domäne, nach interfaces (0009) + traffic (0010) + process (0011) + analysis (0012/0013)), Block 1a
- **Bezug:** ADR 0011 (process als Fünf-Ringe-Muster, Rechte-Port-Vorbild, rootless-Naht); ADR 0010 (traffic: System-Tool `ss` statt Python-Lib — dieselbe Konsistenz-Entscheidung); ADR 0001 (keine stillen Fallbacks, Finding S3); ADR 0002 (domain bleibt framework-frei); CLAUDE.md (Nur Linux x64, keine Selbst-Eskalation von Rechten)

## Kontext

Die diagnostics-Domäne ist die erste **Diagnose-Schicht** des Rewrites: aktive **Frage-Antwort-Werkzeuge**, mit denen der Nutzer ein Netz gezielt befragt — „welche Adressen hat dieser Name?" (DNS), „welchen Pfad nimmt der Verkehr zu diesem Ziel?" (traceroute). Anders als die passiv beobachtenden Schwester-Domänen (traffic/process beobachten, analysis interpretiert) **fragt** diagnostics aktiv und liefert die rohe Antwort.

Faktencheck der Quellen (gegen das reale System geprüft):

- `dig +noall +answer <name> <TYPE>` liefert die Antwort-Datensätze eine Zeile pro Record (`name. ttl IN TYPE value`) — robust parsebar, der Wert ist alles ab dem 5. Feld.
- `traceroute` liefert Hops zeilenweise (`<nr>  host (ip)  <rtt> ms ...`); ein nicht-antwortender Hop erscheint als `* * *`.
- `traceroute` läuft **rootless** (UDP-Default), liefert aber mit Root die genauere ICMP-Methode (`-I`). DNS braucht **keine** besonderen Rechte.

Zwei wiederkehrende Spannungen, die dieses ADR auflöst:

1. **System-Binary oder Python-Lib?** — wie schon bei `ss` (traffic) gegen eine reine Python-Implementierung.
2. **Wie geht der Tool-fehlt-Fehler durch die Ringe?** — der import-linter verbietet `infrastructure` den Import von `application` (Contract „infrastructure kennt nicht application/api"), also kann der Adapter die application-Exception nicht werfen.

## Entscheidung

1. **Vollwertige diagnostics-Domäne über alle fünf Ringe** nach dem process-Muster. `domain/diagnostics.py`: frozen `DnsRecord`/`DnsResult`/`TracerouteHop`/`TracerouteResult`, Alias `DnsRecordType` (`Literal[...]`), reine Funktion `dedup_records` (Dedup+Sortierung der DNS-Records, deterministisch) — kein I/O, keine Uhr (`rtt_ms` als Feld).

2. **System-Binaries statt Python-Libs** (`dig` für DNS, `traceroute` für den Pfad) — **Konsistenz mit `ss` in traffic** (ADR 0010). Begründung: kein Python-Resolver-/Raw-Socket-Stack pflegen, der das verlässliche System-Tool nur nachbaut; die Sprach-Wechsel-Option (Vision 5.2) bleibt offen, weil der systemnahe Aufruf in **einem** Adapter gekapselt ist.

3. **traceroute mit bewusster Nutzerwahl `privileged`/`unprivileged`** (keine Sackgasse): `privileged=True` → ICMP via `-I` (genauer, braucht Root), `False` → UDP-Default (unprivilegiert, ungenauer). **Pflicht-Bool am api-Rand** (`GET …/traceroute?privileged=…`) — wie `view` bei processes, kein Default-Raten. **Keine Selbst-Eskalation** (CLAUDE.md): `privileged` läuft nur, wenn der Prozess die Rechte ohnehin hat; sonst meldet der Rechte-Port ehrlich die unprivilegierte Methode.

4. **DNS mit nutzer-wählbaren Record-Typen**, Default `A`/`AAAA`/`PTR` (`?types=A&types=AAAA&…`, wiederholbarer Query-Parameter). **Kein Rechte-Port für DNS** — Namensauflösung braucht keine besonderen Rechte.

5. **Eigener Rechte-Port `TraceroutePermissionPort`** (synchron, Muster `ProcessPermissionPort`): `is_available` (Binary im PATH) + `check_permission` (`None` = privilegierte Methode möglich/Root, sonst Begründung). `CheckTraceroutePermission` liefert die `{ok, error}`-Naht exakt wie `CheckProcessPermission` — `ok=True` heißt hier: die genauere Methode ist verfügbar.

6. **Tool-fehlt-Naht über das `SecretStoreUnavailableError`-Vorbild** (vom Auftrag vorgesehene Abweichung, Repo-Stand gewinnt): Der import-linter-Contract „infrastructure kennt nicht application/api" verbietet dem Adapter, die application-Exception `DiagnosticsToolMissingError` zu werfen. Darum wirft der Adapter eine **infrastruktur-eigene** Exception `infrastructure.diagnostics_linux.DiagnosticsToolMissing`, die der Composition Root (`app.py`) über einen globalen `exception_handler` auf **503** abbildet — genau wie `SecretStoreUnavailableError`. `application/diagnostics/errors.py` führt weiterhin die `DiagnosticsApplicationError`-Basis (+ `DiagnosticsToolMissingError`) als domänen-konformen Aufhänger; der api-Ring bleibt clean (kein infrastructure-Import). NUR neutrale Meldung, **kein** Install-Befehl (das reichert Block 1b an).

7. **Ehrliche None-/leer-Semantik** (wie traffic/process): ein nicht-antwortender traceroute-Hop ist `address=None`/`rtt_ms=None` (nicht weggelassen, nicht erfunden); eine leere DNS-Antwort (NXDOMAIN/kein Eintrag) ist `records` LEER und **kein** Fehler.

8. **Tool-/Paketmanager-Erkennung bewusst auf Block 1b verschoben** — 1a liefert die reine Funktion (DNS/traceroute), 1b reichert das Fehlt-Erlebnis um Erkennung + distro-spezifischen Install-Hinweis an.

9. **`independence`-Contract um `domain.diagnostics` erweitert** — die Domänen-Isolation bleibt lückenlos maschinell abgesichert (kein Querimport zu/aus einer anderen `domain`-Subdomäne).

## Konsequenzen

**Positiv**
- Die erste Diagnose-Domäne steht über fünf saubere Ringe; die Domänenlogik (`dedup_records`) ist an **einer** Stelle testbar, die Tool-Naht ist repo-konform (Vorbild `SecretStoreUnavailableError`).
- **Konsistenz mit traffic** (`ss`): dieselbe „System-Tool statt nachgebaute Lib"-Linie, der Sprach-Wechsel bleibt ein lokaler Eingriff im Adapter.
- **Bewusste Nutzerwahl** statt verstecktem Default (traceroute `privileged`, DNS-Typen) — Kontrolle, wo sie etwas ändert.
- **Ehrliche Lücken**: nicht-antwortende Hops und leere DNS-Antworten bleiben sichtbar, ohne erfundenen Wert.

**Kosten / Grenzen**
- **Abhängigkeit von installierten System-Tools** (`dig`/`traceroute`): fehlt eines, ist die Funktion ein ehrlicher 503 — Block 1b liefert Erkennung + Install-Hinweis, damit das Fehlt-Erlebnis handlungsorientiert wird.
- **rootless traceroute funktioniert** (UDP, ungenauer); die genauere ICMP-Methode braucht Root — die Differenz ist benannt, nicht verschwiegen (kein stiller Fallback, S3).
- **Parser an die `dig`/`traceroute`-Ausgabe gebunden**: robust gegen Timeout-Hops/leere Antworten getestet, aber an die reale Tool-Ausgabe gekoppelt (gekapselt in den reinen Parser-Helfern, ohne echten Netz-/Subprocess-Aufruf testbar).
