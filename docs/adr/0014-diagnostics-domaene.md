# ADR 0014 — diagnostics-Domäne: Frage-Antwort-Werkzeuge (Block 1a: DNS + traceroute; Block 1b: Tool-/Paketmanager-Erkennung; Block 2a: Banner-Grabbing; Block 2b: externer IP/Port-Check via cpnetcheck; Block 3: Rogue-DHCP-Erkennung)

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

## Block 3: Rogue-DHCP-Erkennung

- **Status:** Akzeptiert
- **Datum:** 2026-06-11
- **Bezug:** baut auf 1a (Frage-Antwort-Werkzeug über fünf Ringe, async-Runner-Muster `SystemTracerouteRunner`, Rechte-Port-Muster `TraceroutePermissionPort`); 1b (Tool-Registry `TOOL_PACKAGES`); 2b (Setting-Lesen über `SettingsRepository`); ADR 0009 (interfaces: `select_primary`/`InterfaceDiscoveryPort` als Gateway-Quelle); ADR 0001 (keine stillen Fallbacks, S3); CLAUDE.md (Nur Linux x64; keine Selbst-Eskalation von Rechten)

### Kontext

Block 3 ergänzt die aktiven Frage-Antwort-Werkzeuge um „**antwortet hier ein DHCP-Server, den ich nicht erwarte?**" — ein klassischer Hinweis auf einen falsch konfigurierten oder bösartigen DHCP-Server (Rogue DHCP) im lokalen Netz. Methode: `nmap --script broadcast-dhcp-discover` sendet **ein** DHCP DISCOVER ins lokale Netz und sammelt **alle** antwortenden Offers; CERNIS vergleicht die antwortenden Server gegen eine **erwartete Menge**.

**Speedtest gestrichen, lokale Bandbreite via traffic:** Der ursprünglich für diesen Block angedachte Speedtest ist **gestrichen** (kein verlässlicher, lizenzfreier, anbieterneutraler Mess-Endpunkt ohne Drittabhängigkeit; ein eigener Mess-Server wäre eigene Infrastruktur). Die **lokale Bandbreite/Durchsatz-Sicht** ist bereits durch die **traffic-Domäne** (ADR 0010, Per-App-Netzwerk-Monitoring) abgedeckt — eine zweite Messung hier wäre Doppelung. Block 3 ist damit **nur** Rogue-DHCP-Erkennung.

### Entscheidung

1. **Reine Klassifikation im domain-Ring (`classify_dhcp_servers`).** Frozen `DhcpServer` (`ip`, `mac` ehrlich `None`, `is_expected`) + `RogueDhcpResult` (`servers`, `expected` für Wire-Transparenz, `has_unexpected`). Die Funktion normalisiert/dedupliziert die Funde **nach IP** (erstes Vorkommen gewinnt samt MAC), markiert `is_expected = (ip in expected-Menge)`, sortiert deterministisch nach IP. **Rein, deterministisch, mutationsproben-tauglich** — das Herz des Blocks liegt im testbaren Ring (kein nmap-Wissen, kein I/O).

2. **Erwartete Menge: Nutzerliste ODER Gateway-Fallback.** Das **NICHT-geheime** Setting `expected_dhcp_servers` (Liste — `SettingValue` erlaubt `list`, **kein** neuer Mechanismus) gilt, wenn gesetzt+nicht-leer; gesetzt/gelöscht über die bestehenden settings-Use-Cases (`UpdateSetting`), gelesen im Use-Case über `SettingsRepository`. **Sonst Fallback** auf das Gateway des primären Interface — über den **bestehenden** `InterfaceDiscoveryPort` + die reine domain-Funktion `select_primary` (NICHT direkt ein Adapter; injiziert als Protocol, **genau das 2b-Muster** für `settings_repo`/`secret_store`). Kein Gateway ermittelbar → erwartete Menge **leer**.

3. **Leere Erwartung → alle gefundenen gelten als unexpected (ehrlich).** Ohne Erwartung ist jeder antwortende Server „unerwartet" — das ist korrekt. Der api-Rand/das Frontend kann den Fall „keine Erwartung konfiguriert" am leeren `expected` erkennen und kenntlich machen.

4. **Zeigen+einordnen, NICHT verurteilen.** `is_expected`/`has_unexpected` sind **Fakten**, kein Urteil (kein „GEFAHR"). Die Wertung überlässt die Domäne dem Frontend.

5. **Root-pflichtig, KEINE rootless Alternative — ehrliche Sperre.** Rohe DHCP-Pakete brauchen Root. Anders als traceroute (das eine ungenauere rootless-Methode hat, ADR 0014 Entscheidung 3) gibt es hier **keine** Alternative. Eigener `DhcpPermissionPort` (synchron, Muster `TraceroutePermissionPort`): `is_available` (nmap im PATH) + `check_permission` (`None` = Root vorhanden, sonst „als Root starten"). Der Use-Case `DetectRogueDhcp` prüft die Rechte **VOR** `probe.discover()` und wirft bei fehlendem Root eine **application-eigene** `RogueDhcpPermissionError` → **403** (globaler `exception_handler` im Composition Root, Muster der Tool-fehlt-/Dienst-Naht). Der Probe läuft **NIE blind** gegen fehlendes Root; **keine Selbst-Eskalation** (CLAUDE.md), **kein stiller Fallback** (S3). `CheckDhcpPermission` liefert separat die `{ok, error}`-Auskunft.

6. **`nmap` in der 1b-Tool-Registry (`TOOL_PACKAGES`).** Bei allen fünf Managern heißt das Paket schlicht `nmap` (kein Distro-Unterschied wie bei `dig`). Dadurch greift die 1b-Tool-Erkennung (`/api/diagnostics/tools`) auch für nmap; `ALL_TOOLS` leitet sich automatisch mit ab. Der Install-Hinweis ist damit über Block 1b abgedeckt — der Rechte-Port nennt **keinen** Install-Befehl (saubere Trennung).

7. **System-Binary statt Python-Lib** (nmap broadcast-dhcp-discover) — **Konsistenz mit `ss`/`dig`/`traceroute`** (ADR 0010/0014): kein eigener DHCP-Client-Stack, der das verlässliche Tool nachbaut; der systemnahe Aufruf bleibt in **einem** Adapter (`NmapDhcpProbe`) gekapselt. nmap fehlt → infra-eigene `DiagnosticsToolMissing` → 503 (Muster dig/traceroute). Der Parser ist gegen realistische nmap-Beispielausgaben (ein/zwei/kein Server) ohne echten Netz-/nmap-Aufruf getestet.

### Konsequenzen

**Positiv**
- Die heikelste Stelle (erwartet vs. unerwartet, Dedup, Sortierung) liegt **rein im domain-Ring**, mutationsproben-getestet; das nmap-/Netz-I/O ist in **einem** Adapter gekapselt (Sprach-Wechsel bleibt lokal).
- **Ehrliche Sperre** statt stillem Fallback: ohne Root ein klarer 403 mit Begründung, kein blindes Laufen.
- **Wiederverwendung** statt Doppelung: die Gateway-Quelle ist der bestehende interfaces-Port (`select_primary`), das Setting-Lesen das bestehende 2b-Muster — kein neuer Mechanismus.
- **Ehrliche None-/leer-Semantik:** MAC `None`, wenn nmap sie nicht ausweist; leere Erwartung → alle unexpected.

**Kosten / Grenzen**
- **Root-Pflicht:** ohne Root ist die Funktion ein ehrlicher 403 — bewusst, keine rootless Annäherung (rohe DHCP-Pakete gehen nicht anders).
- **Abhängigkeit von nmap:** fehlt es, ist die Funktion ein ehrlicher 503; Block 1b liefert den Install-Hinweis (`nmap` ist registriert).
- **Parser an die nmap-Ausgabe gebunden:** robust gegen ein/zwei/kein Server getestet, aber an die reale `broadcast-dhcp-discover`-Ausgabe gekoppelt (gekapselt im reinen Parser, ohne echten Aufruf testbar).
- **Kein neuer import-linter-Contract nötig** — gleiche Domäne `diagnostics`; der `independence`-Contract für `domain.diagnostics` deckt Block 3 mit ab. Der Use-Case importiert `ports.diagnostics` + `ports.interfaces` + `ports.settings` und `domain.interfaces.select_primary` — das ist `application → ports`/`application → domain` (beides erlaubt; `application.monitoring` nutzt bereits zwei domain-Subpakete) und **kein** application↔application-Import (`ListInterfaces` wurde bewusst **nicht** injiziert, sondern der rohe Port + die reine domain-Funktion — so bleibt das real existierende Muster „application kennt nur domain+ports" unberührt).
