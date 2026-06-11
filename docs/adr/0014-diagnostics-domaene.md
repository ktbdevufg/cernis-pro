# ADR 0014 — diagnostics-Domäne: Frage-Antwort-Werkzeuge (Block 1a: DNS + traceroute; Block 1b: Tool-/Paketmanager-Erkennung; Block 2a: Banner-Grabbing; Block 2b: externer IP/Port-Check via cpnetcheck)

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

## Block 1b: Tool-/Paketmanager-Erkennung

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Bezug:** baut auf 1a (Entscheidung 8: Erkennung + Install-Hinweis bewusst auf 1b verschoben); CLAUDE.md (keine stillen Fallbacks S3; keine Selbst-Eskalation von Rechten); ADR 0011 (Rechte-/Detector-Port-Vorbild `ProcessPermissionPort` → `ToolDetector`/`PackageManagerDetector`)

### Kontext

1a liefert DNS/traceroute, aber das Fehlt-Erlebnis ist nur ein nackter 503 (»Programm 'dig' wurde nicht gefunden«). Block 1b macht es handlungsorientiert: erkennen, welche Tools fehlen, welcher Paketmanager vorliegt, und den passenden Install-Befehls-**Text** liefern — über alle fünf Ringe, ohne neue Abhängigkeit und ohne neue Domäne.

### Entscheidung

1. **Registry als einzige Quelle der Wahrheit im domain-Ring.** `TOOL_PACKAGES: dict[str, dict[PackageManager, str]]` ist reine Daten (Block 1b) — die EINZIGE Stelle, die weiß, welche Tools CERNIS PRO verwendet (`dig`/`traceroute`) und wie das Paket je Manager heißt. `ALL_TOOLS` wird daraus abgeleitet (keine zweite, divergierende Liste). Die Adapter erkennen nur; sie wissen nicht, _was_ es zu erkennen gibt.

2. **`dig`-Paketnamen-Unterschied ist der eigentliche Grund für die Registry:** Debian/Ubuntu `dnsutils`, RHEL/Fedora/SUSE `bind-utils`, Arch `bind`. `traceroute` heißt überall `traceroute` (nur das Befehls-Schema unterscheidet sich).

3. **`yum` mappt bewusst auf dieselben Paketnamen wie `dnf`** (RHEL-Altsysteme nutzen dieselben `bind-utils`/`traceroute`-Pakete).

4. **Paketmanager-Erkennung über `which`, nicht über `/etc/os-release`.** `LinuxPackageManagerDetector` prüft in fester, deterministischer Reihenfolge (`apt → dnf → yum → zypper → pacman`) und gibt den ERSTEN gefundenen zurück. Robust gegen Derivate: ein Derivat erbt den Paketmanager seiner Basis, nicht zwingend den Distro-Namen. `dnf` vor `yum`, damit auf Systemen mit beiden der modernere gewinnt.

5. **Ehrliche None-Semantik durchgehend (kein Raten):** kein Manager erkannt → `install_command` `None`; nichts fehlt → `None`; unbekanntes Tool (nicht in `TOOL_PACKAGES`) → übersprungen, nicht erfunden. `build_install_command`/`assemble_report` sind rein, deterministisch (dedup + Sortierung), voll testbar — die heikelste Stelle (die unterschiedlichen Paketnamen) liegt im domain-Ring.

6. **KEINE Selbst-Installation (Sicherheits-Prinzip).** Das Backend führt NIE einen Paketmanager-Befehl aus — es liefert nur den Befehls-**Text**. Der Nutzer entscheidet und führt aus.

7. **Backend bleibt zustandslos — kein Erststart-Gedächtnis.** Kein „alle Tools schon mal geprüft?"-Flag im Backend. `GET /api/diagnostics/tools` ohne `tools`-Param = alle prüfen (Erstinstallation), mit `tools=…` = gezielt (Laufzeit). WANN die GUI „alle" abfragt, entscheidet die GUI, nicht das Backend.

8. **Detektoren als eigene synchrone Ports** (`ToolDetector`/`PackageManagerDetector`, Muster `TraceroutePermissionPort`): schnelle lokale `which`-Checks, kein Loop-I/O → synchron. Der Use-Case `CheckDiagnosticsTools` orchestriert nur (Detector + Manager → reine `assemble_report`).

### Konsequenzen

- **Kein neuer import-linter-Contract nötig** — gleiche Domäne `diagnostics`, der `independence`-Contract für `domain.diagnostics` aus 1a deckt 1b mit ab.
- Das Fehlt-Erlebnis ist jetzt handlungsorientiert (konkreter Install-Befehl) statt nur ein 503 — ohne dass das Backend je selbst installiert oder Zustand führt.
- **Grenze:** die Registry wächst mit jedem neuen System-Tool, das CERNIS PRO nutzt — aber das ist genau die _eine_ Stelle, an der ein neues Tool registriert wird (Binary → Paketnamen je Manager).

## Block 2a: Banner-Grabbing

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Bezug:** baut auf 1a (Frage-Antwort-Werkzeug über fünf Ringe, async-Runner-Muster `SystemTracerouteRunner`); ADR 0001 (keine stillen Fallbacks, ehrliche None-/state-Semantik); CLAUDE.md (Nur Linux x64; Banner-Grabbing bleibt Diagnose, kein Angriffswerkzeug)

### Kontext

Banner-Grabbing ergänzt die aktiven Frage-Antwort-Werkzeuge um „**was begrüßt mich auf diesem Port?**" — rein lokales TCP-Klopfen + Lesen der Begrüßungszeile. Block 2a ist bewusst **eng geschnitten**: KEIN externer Dienst, KEIN Token, KEINE Settings (das ist 2b). Nur ein Connect, höchstens eine minimale Standard-Anfrage, eine gelesene Begrüßung.

### Entscheidung

1. **Eine einzige Heuristik im domain-Ring (`probe_for_port`).** Klartext-Web-Ports `{80, 8080, 8000, 8008}` → `http_head` (eine minimale HTTP-HEAD-Anfrage senden), alle anderen → `passive` (kurz lauschen, der Dienst grüßt selbst). Rein, deterministisch, mutationsproben-tauglich — die heikelste Stelle (passive vs. aktiv) liegt im testbaren Domänen-Ring.

2. **TLS-Ports `{443, 8443}` bewusst NICHT als `http_head`.** Ein roher TCP-Connect dorthin spricht TLS, kein Klartext-HTTP — eine HEAD-Anfrage gäbe Müll. **Kein TLS-Handshake in 2a** (das wäre Scope-Ausweitung). Saubere Wahl: TLS-Ports aus der http_head-Menge herausgenommen, sie fallen in `passive` und grüßen bei rohem Connect nicht → ehrlich `no_banner`.

3. **NUR eine minimale, standardkonforme HTTP-HEAD-Anfrage** (`HEAD / HTTP/1.0\r\nHost: <target>\r\n\r\n`), nie mehr. Bei `passive` wird **nichts** gesendet, nur gelesen. **Sicherheits-Grenze:** keine konfigurierbaren Payloads, kein generischer Byte-Sender — Banner-Grabbing bleibt Diagnose, kein Angriffswerkzeug.

4. **Async-Adapter über `asyncio.open_connection` mit `wait_for`-Timeouts** (3 s Connect, 3 s Read) — Muster `SystemTracerouteRunner` (async-Runner), nur nativ async (asyncio-Sockets statt Subprocess). **KEIN Rechte-Port** (anders als traceroute): ein gewöhnlicher TCP-Connect braucht keine besonderen Rechte.

5. **Ehrliche state-/None-Semantik (kein erfundener Banner):** Connect ok + Banner gelesen → `state="ok"`; Connect ok + nichts Lesbares → `no_banner`; `ConnectionRefused` → `closed`; Timeout/unerreichbar → `filtered`. `banner` ist NUR bei `ok` nicht-`null` — bei `no_banner`/`closed`/`filtered` ehrlich `null`.

6. **Reine Bereinigung im domain-Ring (`sanitize_banner`):** erste Zeile, Steuerzeichen raus, auf 512 Zeichen gekürzt — rein, deterministisch, testbar (uferlose/binäre Antwort eines bösartigen Diensts wird begrenzt).

### Konsequenzen

- **Kein neuer import-linter-Contract nötig** — gleiche Domäne `diagnostics`, der `independence`-Contract für `domain.diagnostics` aus 1a deckt 2a mit ab.
- Die zwei heiklen Stellen (Methoden-Wahl, Bereinigung) liegen rein im domain-Ring, ohne Netz testbar; das Socket-I/O ist in **einem** Adapter gekapselt (Sprach-Wechsel bleibt lokal).
- **Grenze:** TLS-Dienste liefern in 2a kein Banner (ehrlich `no_banner`) — ein echter TLS-Handshake (Zertifikat/ALPN als „Banner") wäre ein späterer, bewusster Schnitt, kein stiller Fallback.

## Block 2b: externer IP/Port-Check via cpnetcheck (Modell D)

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Bezug:** baut auf 2a (Banner-Grabbing fragt lokal — 2b fragt einen externen Dienst); ADR 0001 (keine stillen Fallbacks, `configured=False` ist explizit + benannt); ADR 0002 (domain bleibt rein — kein HTTP); Settings-/Secret-Naht aus settings (`SECRET_KEYS`/`redact`) + agent (`secret_store.get(...) or ""`)

### Kontext

2a beantwortet „was begrüßt mich auf diesem **lokalen** Port?". 2b ergänzt die Außensicht: „**welche öffentliche IP hat CERNIS, und sind meine Ports von außen erreichbar?**". Das lässt sich nicht lokal beantworten — es braucht einen Dienst **außerhalb** des eigenen Netzes, der zurückschaut. CERNIS ruft dafür einen **cpnetcheck-konformen Dienst als CLIENT** (eigener/Karls Dienst, künftig austauschbar gegen einen Drittanbieter über das `cpnetcheck_url`-Setting).

Der Vertrag des externen Diensts: `GET /v1/myip` (→ `{ip, family}`) und `POST /v1/portcheck` (`{ports, protocol}` → `{checked_ip, family, results:[{port, reachable, state}]}`), beide mit `Authorization: Bearer <token>`. Dienst-Fehler: 401 (Token), 422 (ungültige Ports/Whitelist), 403 (private IP), 429 (Rate-Limit), 503.

### Entscheidung

1. **Modell D — Feature nur aktiv, wenn URL UND Token konfiguriert sind.** Fehlt eines, liefert der Use-Case ehrlich `ExternalCheckResult(configured=False, …)` mit neutralem Hinweis und ruft **nichts** nach außen (ADR 0001, kein stiller Fallback). **KEIN C1-Auto-Fallback** auf öffentliche what-is-my-ip-Dienste — das ist eine bewusste spätere Option, kein stiller Ersatz. **KEINE Speicherung** des Ergebnisses.

2. **Token als Secret `cpnetcheck_token` (`SECRET_KEYS`).** Allein durch den Eintrag in `domain.settings.SECRET_KEYS` wird er automatisch redigiert (`GetSettings`/`redact` → `[REDACTED]`) und ausschließlich über `UpdateSecret` setzbar; `UpdateSetting` lehnt ihn via `is_secret()` ab — **keine** Änderung an `UpdateSecret`/`UpdateSetting` nötig (verifiziert über einen Test). Die **URL `cpnetcheck_url`** ist ein **NICHT-geheimes** normales Setting; settings hat keinen Default-Mechanismus, also liest der diagnostics-Use-Case sie über das `SettingsRepository` und fällt bei Abwesenheit auf die Konstante `DEFAULT_CPNETCHECK_URL = "https://cpnetcheck.bach.world"` zurück. Die **Default-Konstante lebt in der diagnostics-Schicht** (application), NICHT in settings.

3. **Client-seitige Port-Validierung im domain-Ring (`validate_requested_ports`).** Dedup, Bereich 1..65535, max 10 — spiegelt die Dienst-Grenzen, damit offensichtlich Ungültiges gar nicht erst rausgeht. **KEINE Whitelist-Doppelung** (die setzt der Dienst durch; der Client darf großzügiger sein). Rein, deterministisch, mutationsproben-tauglich.

4. **`ExternalReachabilityProvider`-Port (async, HTTP-I/O); der configured-Zustand wird im Use-Case entschieden, nicht im Port.** Der Port ist reine Mechanik (`base_url`/`token` als Parameter). Eine Use-Case-Methode mit **optionaler Portliste** (`ports=None` → reiner IP-Check; Liste → IP + Port-Check) bedient die zwei api-Routen `GET /external/ip` und `GET /external/ports`.

5. **HTTPS-Cert-PFLICHT — kein `verify=False`.** Ein gehärteter Dienst hat ein echtes Zertifikat (Sicherheitsnaht). Der Adapter (`HttpxReachabilityProvider`, `httpx.AsyncClient`) setzt getrennte Connect-/Read-Timeouts (5 s / 35 s — der Port-Check kann beim Dienst dauern).

6. **Dienst-Fehler → 502 über das `DiagnosticsToolMissing`-Vorbild.** Jeder Fehler (HTTP ≥400, Netzfehler, Timeout, JSON-Parsefehler) wird im Adapter zu einer **infra-eigenen** `ExternalCheckFailed` mit **NEUTRALER** Meldung — der **Token wird NIE geloggt/zurückgegeben**, interne Details (Body/URL/Stacktrace) leaken NIE. 401 → eigene „Authentifizierung am externen Dienst fehlgeschlagen"-Meldung, alles andere generisch. Der Composition Root mappt `ExternalCheckFailed` über einen globalen `exception_handler` auf **502** (Bad Gateway — externer Dienst), genau wie `DiagnosticsToolMissing` → 503. `application/diagnostics/errors.py` führt `ExternalCheckError` als domänen-konformen Aufhänger (api-Ring bleibt clean). Der Use-Case **verschluckt** Dienstfehler nicht — Durchwurf zum api-Rand.

### Konsequenzen

- **Kein neuer import-linter-Contract nötig** — gleiche Domäne `diagnostics`; der `independence`-Contract für `domain.diagnostics` aus 1a deckt 2b mit ab. Der Use-Case importiert `ports.settings` (`SettingsRepository`/`SecretStore`) — das ist `application → ports` (erlaubt) und **genau das Muster, das `application.agent` für den `SecretStore` schon nutzt**; kein domain↔domain- und kein Ring-Verstoß.
- Die heiklen Stellen (Modell-D-Gate, Port-Validierung, Token-Redaction) liegen testbar im domain-/application-Ring; das HTTP-I/O ist in **einem** Adapter gekapselt (gegen `httpx.MockTransport` ohne Netz testbar, Sprach-Wechsel bleibt lokal).
- **Grenze:** der externe Dienst ist eine Abhängigkeit — fällt er aus, ist das ein ehrlicher 502 (kein stiller Fallback auf einen anderen Dienst). Die Austauschbarkeit über `cpnetcheck_url` hält den Anbieter offen.
