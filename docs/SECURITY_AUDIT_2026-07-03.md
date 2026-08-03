# Sicherheits-Audit CERNIS PRO 2.0

## 1. Kopf

- **Datum:** 2026-07-03
- **Commit-Hash:** `0d4c2e7439a4b434fb6adb976be9e84748a74d36` (Branch `rewrite/v2`)
- **Auftrag:** Auftragsdatei `audit_v2.md` (außerhalb des Repos) — reiner Lese-/Befund-Auftrag, KEIN Fix.
- **Bindung an die App:** Der Server bindet laut `backend/serve.py:30-31` an
  `host = "127.0.0.1"`, `port = int(os.environ.get("CERNIS_PORT", "8765"))` — also
  **localhost:8765**, NICHT `0.0.0.0`.

### Threat-Model-Annahme (verbindlich)

Übliches Desktop-Threat-Model: Karl öffnet auf demselben Rechner evtl. auch fremde
Webseiten. **Die localhost-API (Port 8765) ist NICHT als privat anzunehmen.** Konkret:

- Eine beliebige Webseite im lokalen Browser kann Requests an `http://127.0.0.1:8765`
  **absenden**. Die CORS-Middleware verhindert nur, dass die fremde Seite die **Antwort
  liest** — der Request (und damit die serverseitige **Aktion**) läuft trotzdem
  (CSRF-artige Wirkung bei zustandsändernden Endpunkten ohne Preflight-auslösenden
  Content-Type).
- **WebSocket-Handshakes** unterliegen KEINER CORS-Preflight-Prüfung. Eine fremde Seite
  kann `ws://127.0.0.1:8765/ws/...` öffnen, sofern der Server den Handshake nicht selbst
  gegen den `Origin`-Header prüft.
- Ein anderer lokaler Prozess desselben Nutzers kann die API direkt ansprechen.

Kein Remote-Netzwerk-Angreifer (127.0.0.1-Bindung), aber „localhost = vertrauenswürdig"
gilt ausdrücklich NICHT.

### Methodik

Statische Code-Analyse (manuelles Lesen der Nahtstellen entlang der festen Prüfmatrix)
+ deterministische Scanner (bandit, pip-audit, npm audit). **Keine Exploits ausgeführt**,
keine Login-Versuche gefahren, keine Requests gegen eine laufende Instanz gesendet.
Alle Fund-Orte sind mit `Datei:Zeile` gegen den obigen Commit belegt.

### Hinweis zur Matrix-Reichweite

Der Auftrag (B1) spricht von „24 Routen-Dateien in `backend/api/`". Faktisch liegen dort
**29 Router-Dateien** (`ls backend/api/*.py` ohne `__init__.py`). Ich prüfe die real
vorhandenen 29; die Zahl im Auftragstext ist damit als untere Schranke behandelt, kein
Router wurde übersprungen. Das ist keine Design-Mehrdeutigkeit (kein Stopp erforderlich),
sondern eine transparente Korrektur der Bestandszahl.

---

## 2. Zusammenfassung (Zählung je Schweregrad)

| Schweregrad | Anzahl | Befunde |
|-------------|--------|---------|
| **Critical** | 1 | F-01 (fehlende Auth/Origin-Prüfung auf der gesamten localhost-API inkl. WebSockets) |
| **High**     | 2 | F-02 (SSRF über Blocklist-Fetcher), F-03 (aktiv-intrusive default-creds-Logins ohne Auth/Rate-Limit) |
| **Medium**   | 3 | F-04 (unbegrenzte Frame-Länge im sniffd-IPC → Speicher-DoS), F-05 (AppleScript-Injection in beiden Notifiern), F-06 (bekannte CVEs in Python-Dependencies) |
| **Low**      | 3 | F-07 (Argument-Injection ohne `--`-Terminator in dig/traceroute/ping), F-08 (esbuild/vite-Dev-Server-CVE, nur dev), F-09 (TLS-Verify im default-creds-Check deaktiviert) |

**Gesamt: 9 Befunde** (1 Critical, 2 High, 3 Medium, 3 Low).

Die deterministischen Scanner meldeten zusätzlich zahlreiche Low/Medium-Treffer, die nach
manueller Prüfung **False-Positives** sind (siehe Abschnitt 3 „Geprüfte Nicht-Befunde"
und die B4-Matrix). Diese werden bewusst nicht als Befunde geführt.

---

## 3. Remediierungs-Status (Stand 2026-07-03)

Dieser Abschnitt hält den Behebungs-Stand der neun Befunde fest. Behobene Findings sind
mit dem jeweiligen Commit belegt; bewusst zurückgestellte Findings sind mit Begründung
und Reaktivierungs-Bedingung dokumentiert.

| Finding | Schweregrad | Status | Beleg / Begründung |
|---------|-------------|--------|--------------------|
| F-01 | Critical | **Teilweise behoben** | Etappe 1 (Origin-Guard HTTP+WS) behoben in Commit `fb9c113`; Etappe 2 (Token) bewusst zurückgestellt — siehe unten. |
| F-02 | High | **Behoben** | SSRF-Schema-/Ziel-Guard in Commit `ed652a3`. |
| F-03 | High | **Als Feature-Entscheidung übernommen** | Wird nicht entfernt, sondern zur scharfen Opt-in-Sonderfunktion umgebaut — siehe unten (ADR 0044). |
| F-04 | Medium | **Behoben** | sniffd-Frame-Längendeckel in Commit `c49440d`. |
| F-05 | Medium | **Behoben** | osascript-Escaping in Commit `c49440d`. |
| F-06 | Medium | **Behoben** | Dependency-Bumps (starlette/cryptography/pydantic-settings) in Commit `b66704f`. |
| F-07 | Low | **Behoben** | `--`-Terminatoren vor nutzergesteuerten CLI-Argumenten in Commit `c49440d`. |
| F-08 | Low | **Zurückgestellt** | Nur Dev-Abhängigkeit, kein Produkt-Impact — siehe unten. |
| F-09 | Low | **In Feature-Block verlagert** | Wird im Zuge des F-03-Umbaus (ADR 0044) adressiert — siehe unten. |

### Bewusst zurückgestellte und verlagerte Findings

**F-01 Etappe 2 (lokaler Shared-Token):** Zurückgestellt. Etappe 1 (Origin-Guard) schließt
den realistischen Angriff (fremde Webseite im lokalen Browser triggert die localhost-API,
inkl. der WebSocket-Lücke). Etappe 2 würde zusätzlich einen lokalen Fremdprozess unter
demselben Nutzer abwehren — ein Angreifer, der bereits Code als dieser Nutzer ausführt und
damit das Token-File (0600) ohnehin lesen sowie DB und Keyring-Secrets abgreifen könnte.
Der Grenznutzen ist klein, der Grenzaufwand hoch (Tauri-nativer Token-Kanal, Selbst-
Aussperr-Risiko, Dev-Modus-Bypass). Reaktivierung, wenn sich das Threat-Model ändert:
Bindung an mehr als Loopback, Multi-User-Host oder Server-Deployment.

**F-03 / F-09 (Standardpasswort-Prüfung):** Als Produktentscheidung übernommen statt entfernt.
Die aktiven Default-Credential-Logins bleiben erhalten, werden aber zu einer bewusst
scharfen Sonderfunktion umgebaut: bei jedem Programmstart deaktiviert (Session-scoped),
manuelles Aktivieren nur nach bestätigter Warnung, technisch auf das eigene/lokale Netz
begrenzt (keine Internet-Ziele). Damit entfällt die Missbrauchs-Fläche als
Credential-Stuffing-Proxy. F-09 (deaktivierte TLS-Verifikation im creds-Check) wird im
Zuge dieses Umbaus adressiert, nicht separat. Verortet als eigener Feature-Block, ADR 0044.

**F-08 (esbuild/vite Dev-Server-CVE):** Zurückgestellt. Die Lücke steckt ausschließlich in
Dev-Abhängigkeiten (Vite-Dev-Server); npm audit --omit=dev meldet null Verwundbarkeiten,
das ausgelieferte Frontend ist nicht betroffen. Der Fix erzwingt ein Major-Upgrade auf
vite 8 mit Breaking-Change-Risiko. Wird mit dem geplanten bewussten vite-8-Upgrade
gebündelt, nicht als isolierter Sicherheits-Fix vorgezogen.

---

## 4. Befunde (Critical → Low)

### F-01 — Gesamte localhost-API und alle WebSockets ohne Authentifizierung/Origin-Prüfung  **[Critical]**

**Ort:** Querschnitt. Belege:
- CORS-Middleware: `backend/app.py:2238-2244` (einzige Middleware der App).
- Kein einziger Router hat eine Auth-Dependency: keine `Security(...)`, `APIKeyHeader`,
  `HTTPBearer`, `OAuth2`, kein `dependencies=` an `include_router`/`APIRouter` (geprüft
  über alle `backend/api/*.py` + `app.py`). Alle `Depends(...)` sind reine Use-Case-DI.
- **74 zustandsändernde Endpunkte** (POST/PUT/DELETE/PATCH) über 20 Router, alle offen.
- WebSockets ohne Origin-/Auth-Prüfung:
  - `backend/ws_scan.py:365` `await websocket.accept()` — nimmt danach per
    `receive_json()` (`:370`) Scan-Kommandos entgegen (**Scan-Start-Pfad**).
  - `backend/ws_monitor.py:65` `await websocket.accept()`.
  - `backend/ws_pcap.py:54` `await websocket.accept()`.
  - Keine Origin-Prüfung in den WS-Handlern oder in `app.py` (`add_api_websocket_route`
    bei `app.py:2468`, `:2746`, `:3511`).

**Namentlich sensible, unauthentisierte Endpunkte (Auswahl mit Datei:Zeile):**
- Scan starten: `backend/ws_scan.py:364` (WS `/ws/scan`, kommandogesteuert).
- Capture/pcap: `backend/api/capture.py:233` (`POST /api/pcap/start`), `:251` (stop),
  `:277` (save), `:313` (`/lldp/capture`); WS `/ws/pcap` (`app.py:3511`).
- Settings schreiben: `backend/api/settings.py:66` (`PUT /api/settings/{key}`),
  `:88` (`PUT /api/settings/secrets/{key}`).
- Agent-Verwaltung: `backend/api/agent.py:139` (`POST /agents`), `:164` (DELETE),
  `:192` (`POST /agents/{id}/scan`).
- Security-Aktionen: `backend/api/security.py:209` (`POST /api/security/arp-scan`),
  `:286` (`POST /api/security/default-creds` — intrusiv, siehe F-03).
- Wartung/Reset: `backend/api/maintenance.py:119` (`reset-scan-data`), `:128`
  (`reset-selected`), `:146` (`factory-reset`).
- Blocklist-/Tool-Aktionen: `backend/api/blocklist.py:320` (`POST /sources`, URL-getrieben
  → siehe F-02), `:370` (`refresh`), `:395` (`reset-defaults`).

**CORS-Detail:** `cors_allow_origins` defaultet in `backend/infrastructure/config.py:28-33`
auf eine **feste restriktive Allowlist** (`tauri://localhost`, `http://tauri.localhost`,
`http://localhost:1420`, `http://localhost:5173`) — **kein Fallback auf `"*"`**, überschreibbar
per `CERNIS_CORS_ALLOW_ORIGINS`. Das ist korrekt umgesetzt (Finding S1 adressiert). ABER:
`allow_credentials=True` zusammen mit den `localhost:*`-Origins bedeutet, dass **jede andere
lokal auf `localhost:1420`/`5173` laufende App** dieselbe Origin teilt. Und entscheidend:
CORS schützt weder gegen das reine Absenden zustandsändernder Requests noch gegen WebSockets.

**Threat-Model-Einordnung:** Eine fremde Webseite im lokalen Browser kann
`ws://127.0.0.1:8765/ws/scan` öffnen und einen Scan auslösen (kein CORS-Schutz für WS);
sie kann zustandsändernde POSTs absenden (Aktion läuft, nur die Antwort ist unlesbar). Ein
lokaler Fremdprozess kann die gesamte API frei bedienen — inkl. Factory-Reset, Settings-
Schreiben, intrusiver Security-Scans. Unter der Annahme „localhost nicht privat" ist die
**vollständige Abwesenheit jeder Authentifizierung/Origin-Prüfung** der schwerwiegendste
Befund. **Critical.**

---

### F-02 — SSRF über den Blocklist-Fetcher (nutzergesteuerte URL, kein Schema-/Ziel-Guard)  **[High]**

**Ort:** `backend/infrastructure/blocklist_fetcher.py:64-67`
(`urllib.request.urlopen(request, ...)` mit ungeprüfter `url`).
Herkunft der URL bis zur api-Naht:
- `backend/api/blocklist.py:320` `POST /api/blocklist/sources` mit Body-Feld `url: str`
  (`AddSourceBody`, `blocklist.py:50`) — bzw. `PATCH /sources/{id}` (`:344`).
- → `AddSourceRunner`/`RefreshSource` → `backend/application/blocklist/use_cases.py:562`
  `fetcher.fetch(url)`.

**Belege:** `fetch()` setzt **keine Schema-Whitelist** (jedes von `urllib` erlaubte Schema,
inkl. `file://`, geht durch — genau die bandit-B310-Meldung) und **keine Ziel-Prüfung**
(keine Blockade privater/interner/localhost-Adressen). Timeout (30 s) und Größen-Deckel
(50 MB) sind vorhanden, adressieren aber nur DoS, nicht SSRF.

**Threat-Model-Einordnung:** Über den unauthentisierten `POST /sources`-Endpunkt (F-01)
kann ein Wert wie `http://127.0.0.1:<port>/…` oder eine interne Adresse gesetzt werden;
beim Refresh löst der Server eine Anfrage an dieses Ziel aus und liefert bis zu 50 MB des
Antworttexts als „Blocklist-Inhalt" zurück (lesbar über die Source-Ansicht). Damit lassen
sich interne, nur von localhost erreichbare Dienste anfragen/auslesen. **High.** TLS-Verify
ist hier NICHT betroffen (Default-`urllib`-Kontext verifiziert Zertifikate).

---

### F-03 — Aktiv-intrusive Default-Credential-Logins ohne Auth und ohne Rate-Limit  **[High]**

**Ort:** `backend/infrastructure/security/default_creds.py`
- HTTP-Basic-Login-Versuche: `:119` (`opener.open(req, ...)` mit
  `Authorization: Basic <base64>`, `:113-116`).
- FTP-Login-Versuche: `:150-153` (`ftplib.FTP().connect(...); ftp.login(user, pwd)`).
- Auslösender Endpunkt: `backend/api/security.py:286` `POST /api/security/default-creds`
  (Body: `host`, `ports`, `vendor`).

**Belege:**
- **Echte Login-Versuche: JA.** Es werden aktiv Anmeldungen mit einer Liste bekannter
  Default-Zugangsdaten (`DEFAULT_CREDS`/`DEVICE_CREDS`, `:38-86`) gegen das Zielgerät
  gefahren — nicht bloß Banner gelesen.
- **Opt-in / automatisch:** Läuft NUR auf expliziten Request des `POST`-Endpunkts. Kein
  automatischer Aufruf aus Scan/Scheduler/Monitor (die einzigen Referenzen auf
  `CheckDefaultCreds`/`check_host` sind der api-Endpunkt + die Verdrahtung in `app.py`).
  Der auslösende Endpunkt ist aber **unauthentisiert** (F-01).
- **Rate-Limit:** **Keins.** Nur ein internes Cap pro Port (max. 8 HTTP-Versuche `creds[:8]`
  `:112`, max. 4 FTP-Versuche `[:4]` `:148`). Kein Delay/Throttle/Semaphore zwischen
  Versuchen oder zwischen Hosts.

**Threat-Model-Einordnung:** Ein lokaler Angreifer (oder eine fremde Seite, die den POST
absendet) kann CERNIS als unauthentisierten Credential-Stuffing-Proxy gegen beliebige
LAN-Geräte missbrauchen — aktive, potenziell protokollierte/aussperrende Login-Versuche im
Namen des Nutzers, ohne Ratenbegrenzung. Dies ist per Auftrag als DF5-Finding zu benennen,
nicht zu fixen. **High.**

---

### F-04 — sniffd-IPC: keine Obergrenze für die Frame-Länge → unbegrenzte Speicher-Allokation (DoS)  **[Medium]**

**Ort:** `backend/infrastructure/sniffd/protocol.py:110-111`
```
(length,) = _LEN_PREFIX.unpack(header)   # ">I" = bis 4 GiB, ungeprüft
body = _recv_exactly(sock, length)       # akkumuliert 'length' Bytes ohne Deckel
```
`_recv_exactly` (`:79-94`) sammelt bis `length` Bytes in einer Liste; es gibt **keinen
`_LEN_PREFIX_MAX`-Check** vor der Allokation. Betrifft beide Richtungen: sowohl der Helfer-
Server (`backend/infrastructure/sniffd/server.py`, nutzt dieselbe `recv_message`) als auch
der Client (`sniffd_client/base.py`) parsen so.

**Threat-Model-Einordnung:** Ein fehlerhafter oder bösartiger Peer mit einem riesigen
Längen-Präfix treibt die Gegenseite in unbegrenzte Speicher-Allokation (DoS). **Mildernd:**
Der AF_UNIX-Socket liegt in einem `tempfile.mkdtemp(prefix="cernis-sniffd-")`-Verzeichnis
(`sniffd_client/base.py:141`), das per Python-Default **0700** ist — nur der eigene Nutzer
kann connecten. Damit ist es keine Cross-User-/Remote-Fläche, sondern ein same-user-DoS
bzw. Robustheitsmangel an einer Privilegien-Naht. **Medium.**

---

### F-05 — AppleScript-Injection in beiden Desktop-Notifiern (unescapte Interpolation in osascript)  **[Medium]**

**Ort (Neucode-Adapter):**
- `backend/infrastructure/alerting/notifier.py:62-63`:
  ```
  sub = f'subtitle "{subtitle}" ' if subtitle else ""
  script = f'display notification "{message}" with title "{title}" {sub}sound name "Basso"'
  ```
  `title`/`message`/`subtitle` fließen **unescaped** in den osascript-Programmtext.
- `backend/infrastructure/monitoring/notifier.py:59` baut `message` aus `event.label` und
  delegiert an `modules.monitor._notify_macos`, wo der String gebaut wird
  (`backend/modules/monitor.py:187`, gleiches Muster).

**Herkunft der Werte bis zur api-Naht:**
- alerting: `application/alerting/use_cases.py:239` `title = f"CERNIS PRO — {rule.name}"`,
  `:241` `self._notifier.macos(title, message, subtitle=target)`. `rule.name` wird frei per
  `POST /api/alerting/rules` gesetzt (`api/alerting.py:243-256`, `body.name` → `add_rule`).
- monitoring: `event.label` stammt aus dem Monitor-Ziel, frei per
  `POST /api/monitor/targets` (`api/monitoring.py:603`, `body.label`).

**Belege:** Der Aufruf erfolgt zwar als Argumentliste (`subprocess.run(["osascript","-e",script])`,
kein `shell=True` → **keine** Shell-Injection), ABER der interpolierte String IST ein
AppleScript-Programm. Ein `"` in `rule.name`/`label` bricht aus dem String-Literal aus und
erlaubt das Einschleusen weiterer AppleScript-Befehle → Code-Ausführung im osascript-Kontext.

**Threat-Model-Einordnung:** Nur auf **macOS** wirksam (`osascript` existiert nur dort; auf
Linux `FileNotFoundError` → no-op). Der Rewrite-Scope ist „nur Linux x64", der Code ist aber
real und trägt die Schwachstelle, falls die macOS-Kette reaktiviert wird. Kein `notify-send`
im Code (nur osascript) — die im Auftrag genannte notify-send-Frage entfällt mangels
notify-send. **Medium** (plattformbedingt latent, Code belegbar).

---

### F-06 — Bekannte CVEs in Python-Dependencies (pip-audit)  **[Medium]**

**Ort:** Lockfile-/Environment-Dependencies (pip-audit, voller Output im Anhang):

| Paket | Version | ID | Fix |
|-------|---------|----|-----|
| cryptography | 48.0.0 | GHSA-537c-gmf6-5ccf | 48.0.1 |
| pydantic-settings | 2.14.1 | GHSA-4xgf-cpjx-pc3j | 2.14.2 |
| starlette | 1.1.0 | PYSEC-2026-249 | 1.3.1 |
| starlette | 1.1.0 | PYSEC-2026-248 | 1.3.0 |

**Threat-Model-Einordnung:** `starlette` ist die HTTP-Basis unter FastAPI und damit direkt
an der exponierten (wenn auch unauthentisierten) localhost-Angriffsfläche; `cryptography`
und `pydantic-settings` sind Kern-Deps. Konkrete Ausnutzbarkeit im CERNIS-Kontext ist **zu
prüfen** (die Advisory-Details wurden hier nicht gegen den Code verifiziert), aber vier
CVEs mit verfügbaren Fix-Versionen rechtfertigen ein Dependency-Update. **Medium.**

---

### F-07 — Argument-Injection ohne `--`-Terminator in externen CLI-Tools (dig/traceroute/ping)  **[Low]**

**Ort:**
- `backend/infrastructure/diagnostics_linux.py:505-506` — `["dig","+noall","+answer",query,record_type]`;
  `query` ist ungeprüfter Query-Parameter (`api/diagnostics.py:296` `query: str`).
- `backend/infrastructure/diagnostics_linux.py:537-538` — traceroute mit `args` inkl.
  `target` als letztem Element (`:544`); `target` ungeprüft (`api/diagnostics.py:313`).
- `backend/infrastructure/resolver/dns_ptr.py:43-44` — `["dig", *args]`.
- `backend/modules/monitor.py:138/142` (`ping`, via Adapter `monitoring/pinger.py:44`
  `_ping_burst(target.host, ...)`; `target.host` frei per `POST /monitor/targets`).

**Belege:** Alle Aufrufe sind Argumentlisten ohne `shell=True` → **keine** Shell-Injection.
Aber vor dem nutzergesteuerten Wert steht **kein `--`-Terminator**; beginnt der Wert mit `-`,
interpretiert das jeweilige Tool ihn als Option. Kein RCE (keine Shell), aber Verhalten des
externen Tools ist über Optionen manipulierbar.

**Threat-Model-Einordnung:** Niedrige Auswirkung (Flag-Verwirrung, kein Code-Exec), aber
erreichbar über unauthentisierte Endpunkte (F-01). Die konkrete Ausnutzbarkeit je Tool ist
**zu prüfen**. **Low.**

---

### F-08 — esbuild/vite Dev-Server-CVE (npm audit, nur Dev-Abhängigkeit)  **[Low]**

**Ort:** `frontend/` — `npm audit` (voller Output im Anhang):
`esbuild <=0.24.2` (GHSA-67mh-4wv8-2f99, moderate) über `vite <=6.4.2` (high). Fix nur über
`npm audit fix --force` (Breaking Change auf vite@8).

**Belege:** `npm audit --omit=dev` meldet **0 vulnerabilities** — die Schwachstelle steckt
ausschließlich in **Dev-Dependencies** (Vite-Dev-Server) und ist nicht Teil des ausgelieferten
(gebauten) Frontends.

**Threat-Model-Einordnung:** Die esbuild-Lücke erlaubt beliebigen Webseiten, Requests an den
laufenden **Dev-Server** zu senden und Antworten zu lesen — relevant nur während der lokalen
Entwicklung, nicht im ausgelieferten Produkt. **Low.**

---

### F-09 — TLS-Zertifikatsprüfung im default-creds-Check deaktiviert  **[Low]**

**Ort:** `backend/infrastructure/security/default_creds.py:106-109`
```
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_OPTIONAL
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
```

**Belege:** Für den HTTPS-Zweig des Credential-Checks ist Hostname-Prüfung aus und
Zertifikatsprüfung auf optional gesetzt — TLS-Verify effektiv deaktiviert.

**Threat-Model-Einordnung:** Für einen Default-Creds-Scan gegen LAN-Geräte mit
Selbstsignat-Zertifikaten ist das eine bewusste, im Kontext teils nachvollziehbare Wahl
(die Geräte tragen fast nie gültige Zertifikate). Es bedeutet aber, dass die (ohnehin
schwachen) Test-Credentials über eine nicht authentifizierte TLS-Verbindung an einen
potenziell untergeschobenen Endpunkt gehen. Isoliert Low; im Verbund mit F-03 zu beachten.
**Low.**

---

### Geprüfte Nicht-Befunde (Scanner-Treffer, die nach Prüfung entfallen)

- **B105/B107 „hardcoded password"** an `api/alerting.py:225`, `application/diagnostics/use_cases.py:124`,
  `alerting/smtp_config.py:111`, `scanning/fritz_detail.py:55`, `scanning/fritz_hosts.py:81`:
  Redaktions-Marker (`""`), Settings-**Key**-Namen bzw. leere Default-Parameter — **keine**
  echten Secrets. False-Positive.
- **B608 „SQL injection"** an `alerting/rule_repository.py:145`, `blocklist_entries_db.py:114-115`,
  `modules/storage.py:104`: Interpolation betrifft ausschließlich `?`-Platzhalter-Anzahl bzw.
  hartkodierte Whitelist-Spaltennamen/Konstanten; alle Werte sind parameter-gebunden. Siehe
  B4-Matrix. False-Positive.
- **B104 „bind all interfaces"** an `application/blocklist/parsing.py:25`: `0.0.0.0` steht dort
  als **Daten-Sentinel** einer HOSTS-Datei-Filterung, kein Socket-Bind. False-Positive.
- **B402/B321 „FTP insecure"** an `security/default_creds.py`: bewusster Teil des intrusiven
  Checks (F-03) — kein separater Befund.
- **self_host.py:** vom Auftrag unter B8 gelistet, enthält aber **keine externen Fetches**
  (nur `psutil.net_if_addrs()` — lokale Interface-Ermittlung). Keine SSRF-Fläche.

---

## 5. Teil-B-Matrix (Punkt für Punkt)

| Punkt | Gegenstand | Ergebnis | Ort / Beleg |
|-------|-----------|----------|-------------|
| **B1** | CORS-Default restriktiv? | **kein Fund** (korrekt, kein `"*"`-Fallback) | `infrastructure/config.py:28-33`, `app.py:2240` |
| **B1** | Auth/Autorisierung auf den API-Routen? | **FUND** — gar keine Auth (Critical) | ganze `backend/api/`; 74 mutierende Endpunkte offen; F-01 |
| **B1** | WebSockets mit Origin-/Auth-Prüfung? | **FUND** — keine (Critical, Teil F-01) | `ws_scan.py:365`, `ws_monitor.py:65`, `ws_pcap.py:54` |
| **B2** | Shell-/Kommando-Injection (subprocess/osascript)? | **kein `shell=True`/`os.system`; aber FUND osascript-String-Injection** | kein `shell=True` im Backend; F-05 (`alerting/notifier.py:62-63`, `monitoring/notifier.py`→`modules/monitor.py:187`) |
| **B2** | Argument-Injection (fehlender `--`-Terminator)? | **FUND (Low)** | F-07 (`diagnostics_linux.py:505/537`, `resolver/dns_ptr.py:43`, `modules/monitor.py:138`) |
| **B2** | notify-send-Werte unescaped? | **kein Fund** — kein `notify-send` im Code (nur osascript, siehe F-05) | Backend-weite Suche: kein `notify-send` |
| **B3** | GET gibt Secrets roh zurück? | **kein Fund** — Secrets werden gefiltert (REDACTED) | `application/settings/use_cases.py:31-41`, `domain/settings.py:61`; SMTP: `api/alerting.py:216-229` |
| **B3** | secret_store stiller Klartext-/base64-Fallback? | **kein Fund** — ehrlicher Fehler (`SecretStoreUnavailableError`) | `infrastructure/secret_store.py:61-94` |
| **B4** | String-gebautes SQL statt Binding in `*_db.py`? | **kein Fund** — alle Werte parameter-gebunden | 19 Dateien geprüft; einzige f-string-SQL-Stellen (`blocklist_entries_db.py:115`, `alerting/rule_repository.py:145`) = Platzhalter/Whitelist, keine externen Werte |
| **B4** | Tabellen-/Spaltennamen aus Variablen? | **kein Fund** — nur hartkodierte Whitelist-Spalten | `alerting/rule_repository.py:39/142` (`_UPDATABLE`), `blocklist_entries_db.py:31` (`_KIND_DOMAIN` konstant) |
| **B5** | AF_UNIX-Socket-Dir 0700? | **kein Fund** — `mkdtemp` = 0700 | `sniffd_client/base.py:141` |
| **B5** | Frame-Längen-Obergrenze? | **FUND (Medium)** — keine Grenze, unbegrenzte Allokation | F-04 (`sniffd/protocol.py:110-111`) |
| **B5** | Helfer-Spawn aus schreibbarem/nutzerbeeinflusstem Ort? | **kein Fund** — an `sys.executable`/festen Repo-Pfad gebunden, kein PATH-Lookup | `sniffd_client/base.py:75-87` |
| **B6** | default_creds: echte Login-Versuche? | **FUND** — ja, HTTP-Basic + FTP (High) | F-03 (`security/default_creds.py:119`, `:150-153`) |
| **B6** | Opt-in oder automatisch? Rate-Limit? | opt-in (nur `POST`, kein Auto-Trigger), aber Endpunkt unauth.; **kein Rate-Limit** | `api/security.py:286`; Cap `creds[:8]`/`[:4]`, kein Throttle |
| **B7** | agent-Server auf 0.0.0.0 / `changeme`-Default / erreichbar? | **kein Fund** — keine Server-Seite existiert (nur Client) | `api/agent.py` nur Client-/Verwaltungs-Routen; `infrastructure/agent/scan_client.py` = WS-Client; Token aus SecretStore (`... or ""`, kein Default) |
| **B8** | self_host + blocklist_fetcher: URL-Herkunft/TLS/SSRF? | **FUND (High)** — SSRF im blocklist_fetcher; self_host ohne Fetch | F-02 (`blocklist_fetcher.py:64-67`, URL aus `api/blocklist.py:320`); TLS-Verify bei fetcher AN; `self_host.py` kein Fetch |

---

## 6. Anhang — vollständige Roh-Ausgabe der Scanner (wörtlich)

### 6.1 bandit — Neucode (`uv run bandit -r backend -x backend/tests,backend/build,backend/dist,backend/modules`)

Exit-Code: 1 (bandit: Fund vorhanden; kein Scanner-Fehler).

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.12.3
Working... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:01
Run started:2026-07-03 13:04:46.483135+00:00

Test results:
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: ''
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html
   Location: backend/api/alerting.py:225:16
224	    if raw is None:
225	        return {"password": ""}
226	    # Alle Felder ausser password roh durchreichen; password redigiert ans Ende.

--------------------------------------------------
>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.
   Severity: Medium   Confidence: Medium
   CWE: CWE-605 (https://cwe.mitre.org/data/definitions/605.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html
   Location: backend/application/blocklist/parsing.py:25:46
24	# HOSTS-Sentinels: nur Bind-Adressen, KEINE echten Threat-IPs -> verwerfen.
25	_HOSTS_SENTINELS: frozenset[str] = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})
26	

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'cpnetcheck_token'
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html
   Location: backend/application/diagnostics/use_cases.py:124:24
123	# ein normales Setting. Hier als benannte Konstanten, damit der Lese-Pfad eindeutig ist.
124	_CPNETCHECK_TOKEN_KEY = "cpnetcheck_token"
125	_CPNETCHECK_URL_KEY = "cpnetcheck_url"

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/cernis_cli.py:35:13
34	        req = urllib.request.Request(url, data=body, headers=headers, method=method)
35	        with urllib.request.urlopen(req, timeout=30) as resp:
36	            return json.loads(resp.read())

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/data/fetch_geoasn.py:32:9
31	    req = urllib.request.Request(url, headers={"User-Agent": "CERNIS-PRO/2.0"})
32	    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
33	        return resp.read()

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/data/fetch_oui.py:16:13
15	        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "LANScan/1.0"})
16	        with urllib.request.urlopen(req, timeout=30) as resp:
17	            raw = resp.read().decode("utf-8", errors="ignore")

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:139:23
138	        detail_template="Prozess {subject} laeuft aus einem temporaeren Verzeichnis ({value}).",
139	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
140	    ),

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:139:32
138	        detail_template="Prozess {subject} laeuft aus einem temporaeren Verzeichnis ({value}).",
139	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
140	    ),

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:139:45
138	        detail_template="Prozess {subject} laeuft aus einem temporaeren Verzeichnis ({value}).",
139	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
140	    ),

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:154:23
153	        "-- moeglicher Tarnverdacht.",
154	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
155	    ),

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:154:32
153	        "-- moeglicher Tarnverdacht.",
154	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
155	    ),

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/domain/analysis/rules.py:154:45
153	        "-- moeglicher Tarnverdacht.",
154	        path_prefixes=("/tmp/", "/dev/shm/", "/var/tmp/"),
155	    ),

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/infrastructure/agent/pinger.py:39:9
38	    )
39	    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
40	        decoded = json.loads(response.read())

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/alerting/notifier.py:29:0
28	import asyncio
29	import subprocess
30	

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/infrastructure/alerting/notifier.py:65:8
64	        # Arg-Liste ohne shell=True -> keine Shell-Injection (Altcode-treu).
65	        subprocess.run(
66	            ["osascript", "-e", script],
67	            timeout=_OSASCRIPT_TIMEOUT,
68	            capture_output=True,
69	        )
70	

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/alerting/notifier.py:65:8
64	        # Arg-Liste ohne shell=True -> keine Shell-Injection (Altcode-treu).
65	        subprocess.run(
66	            ["osascript", "-e", script],
67	            timeout=_OSASCRIPT_TIMEOUT,
68	            capture_output=True,
69	        )
70	

--------------------------------------------------
>> Issue: [B101:assert_used] Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b101_assert_used.html
   Location: backend/infrastructure/alerting/rule_repository.py:115:8
114	        # lastrowid ist nach erfolgreichem INSERT mit AUTOINCREMENT immer gesetzt.
115	        assert rule_id is not None
116	        return rule_id

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: backend/infrastructure/alerting/rule_repository.py:145:27
144	        with self._connect() as conn:
145	            conn.execute(f"UPDATE alert_rules SET {assignments} WHERE id = ?", params)
146	

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: ''
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html
   Location: backend/infrastructure/alerting/smtp_config.py:111:20
110	        else:
111	            payload["password"] = ""
112	

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: backend/infrastructure/blocklist_entries_db.py:114:16
113	            rows = conn.execute(
114	                "SELECT source_id, value FROM blocklist_entries "
115	                f"WHERE kind = '{_KIND_DOMAIN}' AND value IN ({placeholders})",
116	                candidates,

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/infrastructure/blocklist_fetcher.py:66:17
65	        try:
66	            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
67	                raw: bytes = response.read(self._max_bytes + 1)

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/diagnostics_linux.py:70:0
69	import shutil
70	import subprocess
71	from collections.abc import Sequence

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/infrastructure/diagnostics_linux.py:505:20
504	    try:
505	        completed = subprocess.run(
506	            ["dig", "+noall", "+answer", query, record_type],
507	            capture_output=True,
508	            text=True,
509	            timeout=_DIG_TIMEOUT_SECS,
510	            check=False,
511	        )
512	    except subprocess.TimeoutExpired:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/diagnostics_linux.py:505:20
504	    try:
505	        completed = subprocess.run(
506	            ["dig", "+noall", "+answer", query, record_type],
507	            capture_output=True,
508	            text=True,
509	            timeout=_DIG_TIMEOUT_SECS,
510	            check=False,
511	        )
512	    except subprocess.TimeoutExpired:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/diagnostics_linux.py:537:20
536	    try:
537	        completed = subprocess.run(
538	            args,
539	            capture_output=True,
540	            text=True,
541	            timeout=_TRACEROUTE_TIMEOUT_SECS,
542	            check=False,
543	        )
544	    except subprocess.TimeoutExpired as exc:

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/infrastructure/diagnostics_linux.py:763:20
762	    try:
763	        completed = subprocess.run(
764	            ["nmap", "--script", "broadcast-dhcp-discover"],
765	            capture_output=True,
766	            text=True,
767	            timeout=_NMAP_DHCP_TIMEOUT_SECS,
768	            check=False,
769	        )
770	    except subprocess.TimeoutExpired as exc:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/diagnostics_linux.py:763:20
762	    try:
763	        completed = subprocess.run(
764	            ["nmap", "--script", "broadcast-dhcp-discover"],
765	            capture_output=True,
766	            text=True,
767	            timeout=_NMAP_DHCP_TIMEOUT_SECS,
768	            check=False,
769	        )
770	    except subprocess.TimeoutExpired as exc:

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/interfaces_linux.py:33:0
32	import re
33	import subprocess
34	

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/interfaces_linux.py:46:17
45	    try:
46	        result = subprocess.run(
47	            cmd,
48	            capture_output=True,
49	            timeout=5,
50	            encoding="utf-8",
51	            errors="replace",
52	        )
53	        return result.stdout or ""

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/resolver/dns_ptr.py:25:0
24	import shutil
25	import subprocess
26	

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/infrastructure/resolver/dns_ptr.py:43:20
42	    try:
43	        completed = subprocess.run(
44	            ["dig", *args],
45	            capture_output=True,
46	            text=True,
47	            timeout=_DIG_TIMEOUT_SECS,
48	            check=False,
49	        )
50	    except subprocess.TimeoutExpired:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/resolver/dns_ptr.py:43:20
42	    try:
43	        completed = subprocess.run(
44	            ["dig", *args],
45	            capture_output=True,
46	            text=True,
47	            timeout=_DIG_TIMEOUT_SECS,
48	            check=False,
49	        )
50	    except subprocess.TimeoutExpired:

--------------------------------------------------
>> Issue: [B107:hardcoded_password_default] Possible hardcoded password: ''
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b107_hardcoded_password_default.html
   Location: backend/infrastructure/scanning/fritz_detail.py:55:4
54	
55	    def __init__(self, host: str, user: str = "", password: str = "", port: int = 49000) -> None:
56	        self._host = host
57	        self._user = user
58	        self._password = password
59	        self._port = port
60	

--------------------------------------------------
>> Issue: [B107:hardcoded_password_default] Possible hardcoded password: ''
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b107_hardcoded_password_default.html
   Location: backend/infrastructure/scanning/fritz_hosts.py:81:4
80	
81	    def __init__(self, host: str, user: str = "", password: str = "", port: int = 49000) -> None:
82	        self._host = host
83	        self._user = user
84	        self._password = password
85	        self._port = port
86	

--------------------------------------------------
>> Issue: [B310:blacklist] Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.
   Severity: Medium   Confidence: High
   CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
   Location: backend/infrastructure/security/cve.py:96:13
95	    try:
96	        with urllib.request.urlopen(req, timeout=10) as resp:
97	            data: dict[str, Any] = json.loads(resp.read())

--------------------------------------------------
>> Issue: [B402:blacklist] A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
   Severity: High   Confidence: High
   CWE: CWE-319 (https://cwe.mitre.org/data/definitions/319.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b402-import-ftplib
   Location: backend/infrastructure/security/default_creds.py:25:0
24	import base64
25	import ftplib
26	import ssl

--------------------------------------------------
>> Issue: [B321:blacklist] FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.
   Severity: High   Confidence: High
   CWE: CWE-319 (https://cwe.mitre.org/data/definitions/319.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b321-ftplib
   Location: backend/infrastructure/security/default_creds.py:150:18
149	        try:
150	            ftp = ftplib.FTP()
151	            ftp.connect(host, port, timeout=timeout)

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/sniffd/sniff_core.py:41:0
40	import struct
41	import subprocess
42	import threading

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/infrastructure/sniffd/sniff_core.py:196:14
195	    try:
196	        out = subprocess.run(
197	            ["ip", "route", "show", "default"],
198	            capture_output=True,
199	            text=True,
200	            timeout=3,
201	            check=False,
202	        ).stdout
203	        match = re.search(r"\bdev\s+(\S+)", out)

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/sniffd/sniff_core.py:196:14
195	    try:
196	        out = subprocess.run(
197	            ["ip", "route", "show", "default"],
198	            capture_output=True,
199	            text=True,
200	            timeout=3,
201	            check=False,
202	        ).stdout
203	        match = re.search(r"\bdev\s+(\S+)", out)

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/infrastructure/sniffd/sniff_core.py:520:20
519	                        summary["info"] = qd.qname.decode() if qd else ""
520	                    except Exception:
521	                        pass
522	                elif summary["dst_port"] == 5353:

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/sniffd_client/base.py:36:0
35	import socket
36	import subprocess
37	import sys

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/sniffd_client/base.py:147:25
146	        try:
147	            self._proc = subprocess.Popen(_spawn_command(socket_path))
148	        except OSError as exc:

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/infrastructure/traffic_linux.py:41:0
40	import socket
41	import subprocess
42	import time

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/infrastructure/traffic_linux.py:100:17
99	    try:
100	        result = subprocess.run(
101	            cmd,
102	            capture_output=True,
103	            timeout=5,
104	            encoding="utf-8",
105	            errors="replace",
106	        )
107	        return result.stdout or ""

--------------------------------------------------
>> Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
   Severity: Medium   Confidence: Medium
   CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html
   Location: backend/sniffd.py:12:23
11	
12	_DEFAULT_SOCKET_PATH = "/tmp/cernis-sniffd.sock"
13	

--------------------------------------------------

Code scanned:
	Total lines of code: 46167
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 28
		Medium: 16
		High: 2
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 15
		High: 31
Files skipped (0):
```

### 6.2 bandit — Altcode `backend/modules` (`uv run bandit -r backend/modules`, ADR-0007-eingezäunt)

Exit-Code: 1 (Fund vorhanden). Getrennt ausgewiesen, damit Alt- von Neucode-Funden unterscheidbar ist.

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.12.3
Run started:2026-07-03 13:04:57.733481+00:00

Test results:
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/alerting.py:8:0
7	import smtplib
8	import subprocess
9	import json

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: backend/modules/alerting.py:106:23
105	    if parts:
106	        conn.execute(f"UPDATE alert_rules SET {', '.join(parts)} WHERE id=?", vals + [rule_id])
107	        conn.commit()

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/alerting.py:148:8
147	        script = f'display notification "{message}" with title "{title}" {sub}sound name "Basso"'
148	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
149	    except Exception:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/alerting.py:148:8
147	        script = f'display notification "{message}" with title "{title}" {sub}sound name "Basso"'
148	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
149	    except Exception:

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/alerting.py:149:4
148	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
149	    except Exception:
150	        pass
151	

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: backend/modules/devices_db.py:142:23
141	        params.append(mac.upper())
142	        conn.execute(f"UPDATE devices SET {', '.join(parts)} WHERE mac=?", params)
143	

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/discovery.py:3:0
2	import asyncio
3	import subprocess
4	import platform

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/discovery.py:63:14
62	    if system == "Darwin":
63	        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
64	        for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/discovery.py:63:14
62	    if system == "Darwin":
63	        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
64	        for line in out.splitlines():

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/discovery.py:69:14
68	    elif system == "Windows":
69	        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
70	        for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/discovery.py:69:14
68	    elif system == "Windows":
69	        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
70	        for line in out.splitlines():

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/discovery.py:76:18
75	        try:
76	            out = subprocess.run(["ip", "neigh"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
77	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/discovery.py:76:18
75	        try:
76	            out = subprocess.run(["ip", "neigh"], capture_output=True, encoding="utf-8", errors="replace").stdout or ""
77	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/discovery.py:83:8
82	                        arp_map[parts[0]] = mac
83	        except Exception:
84	            pass
85	    return arp_map

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:121:4
120	            candidates.append(saved)
121	    except Exception:
122	        pass
123	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:140:12
139	                    candidates.append(fqdn)  # prefer FQDN over raw IP
140	            except Exception:
141	                pass
142	            if gw not in candidates:

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:144:4
143	                candidates.append(gw)  # also try raw IP as fallback
144	    except Exception:
145	        pass
146	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:188:20
187	                        return host
188	                    except Exception:
189	                        pass  # TR-064 handshake failed, skip
190	                else:

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:192:8
191	                    return host
192	        except Exception:
193	            pass
194	    return None

--------------------------------------------------
>> Issue: [B107:hardcoded_password_default] Possible hardcoded password: ''
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b107_hardcoded_password_default.html
   Location: backend/modules/fritzbox.py:200:4
199	class FritzBox:
200	    def __init__(self, host: str, port: int = 49000, user: str = "", password: str = ""):
201	        if not HAS_FRITZ:
202	            raise RuntimeError("fritzconnection not installed. Run: pip install fritzconnection")
203	        self.host = host
204	        self.port = port
205	        self.user = user
206	        self.password = password
207	        self._fc: Optional[FritzConnection] = None
208	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:361:12
360	                s.wlan_24_clients = count
361	            except Exception:
362	                pass
363	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/fritzbox.py:382:12
381	                s.wlan_5_clients = count
382	            except Exception:
383	                pass
384	

--------------------------------------------------
>> Issue: [B112:try_except_continue] Try, Except, Continue detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b112_try_except_continue.html
   Location: backend/modules/fritzbox.py:419:16
418	                        clients.append(client)
419	                except Exception:
420	                    continue
421	        return clients

--------------------------------------------------
>> Issue: [B112:try_except_continue] Try, Except, Continue detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b112_try_except_continue.html
   Location: backend/modules/fritzbox.py:445:12
444	                })
445	            except Exception:
446	                continue
447	        return [h for h in hosts if h["ip"] or h["mac"]]

--------------------------------------------------
>> Issue: [B112:try_except_continue] Try, Except, Continue detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b112_try_except_continue.html
   Location: backend/modules/fritzbox.py:480:12
479	                break  # found working service
480	            except Exception:
481	                continue
482	        return rules

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/interfaces.py:3:0
2	import socket
3	import subprocess
4	import platform

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/interfaces.py:46:17
45	    try:
46	        result = subprocess.run(
47	            cmd, capture_output=True, timeout=5,
48	            encoding="utf-8", errors="replace"
49	        )
50	        return result.stdout or ""

--------------------------------------------------
>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.
   Severity: Medium   Confidence: Medium
   CWE: CWE-605 (https://cwe.mitre.org/data/definitions/605.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html
   Location: backend/modules/interfaces.py:183:40
182	        gw_raw = {}
183	        r_out = _run(["route", "print", "0.0.0.0"]) or ""
184	        for line in r_out.splitlines():

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/ipv6.py:10:0
9	import socket
10	import subprocess
11	import re

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/ipv6.py:59:4
58	            return f"{first:02x}:{b[1]}:{b[2]}:{b[5]}:{b[6]}:{b[7]}"
59	    except Exception:
60	        pass
61	    return ""

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/ipv6.py:105:18
104	        if sys == "Darwin":
105	            out = subprocess.run(["ndp", "-a"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
106	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/ipv6.py:105:18
104	        if sys == "Darwin":
105	            out = subprocess.run(["ndp", "-a"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
106	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/ipv6.py:113:18
112	        elif sys == "Windows":
113	            out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"], capture_output=True, encoding="utf-8", errors="replace", timeout=5).stdout or ""
114	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/ipv6.py:113:18
112	        elif sys == "Windows":
113	            out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"], capture_output=True, encoding="utf-8", errors="replace", timeout=5).stdout or ""
114	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/ipv6.py:119:18
118	        else:
119	            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
120	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/ipv6.py:119:18
118	        else:
119	            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
120	            for line in out.splitlines():

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/ipv6.py:127:4
126	                        ndp[ip] = parts[mac_idx].lower()
127	    except Exception:
128	        pass
129	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/ipv6.py:153:4
152	        await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
153	    except Exception:
154	        pass
155	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/ipv6.py:168:8
167	            hostname = socket.gethostbyaddr(ip + f"%{interface}" if ip_type == "link-local" else ip)[0]
168	        except Exception:
169	            pass
170	

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/mdns.py:82:8
81	                    self.services[key] = svc
82	        except Exception:
83	            pass
84	

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/monitor.py:7:0
6	import asyncio
7	import subprocess
8	import platform

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/monitor.py:188:8
187	        script = f'display notification "{message}" with title "{title}" sound name "Basso"'
188	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
189	    except Exception:

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/monitor.py:188:8
187	        script = f'display notification "{message}" with title "{title}" sound name "Basso"'
188	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
189	    except Exception:

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/monitor.py:189:4
188	        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
189	    except Exception:
190	        pass
191	

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/portscan.py:3:0
2	import asyncio
3	import subprocess
4	import re

--------------------------------------------------
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Severity: Low   Confidence: High
   CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b110_try_except_pass.html
   Location: backend/modules/portscan.py:77:8
76	            await writer.wait_closed()
77	        except Exception:
78	            pass
79	        return PortResult(

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/portscan.py:125:14
124	        ]
125	        out = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=45)
126	        output = out.stdout

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: backend/modules/resolver.py:4:0
3	import socket
4	import subprocess
5	import re

--------------------------------------------------
>> Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b607_start_process_with_partial_path.html
   Location: backend/modules/resolver.py:25:14
24	    try:
25	        out = subprocess.run(
26	            ["nmblookup", "-A", ip],
27	            capture_output=True, encoding="utf-8", errors="replace", timeout=3
28	        ).stdout
29	        name = ""

--------------------------------------------------
>> Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b603_subprocess_without_shell_equals_true.html
   Location: backend/modules/resolver.py:25:14
24	    try:
25	        out = subprocess.run(
26	            ["nmblookup", "-A", ip],
27	            capture_output=True, encoding="utf-8", errors="replace", timeout=3
28	        ).stdout
29	        name = ""

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Medium
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: backend/modules/storage.py:104:27
103	            params.append(mac)
104	            conn.execute(f"UPDATE known_devices SET {', '.join(updates)} WHERE mac=?", params)
105	        else:

--------------------------------------------------

Code scanned:
	Total lines of code: 2143
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 47
		Medium: 4
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 5
		High: 46
Files skipped (0):
```

### 6.3 pip-audit (`uv run pip-audit`)

Exit-Code: 1 (bekannte CVEs gefunden; kein Scanner-Fehler).

```text
Found 4 known vulnerabilities in 3 packages
Name              Version ID                  Fix Versions
----------------- ------- ------------------- ------------
cryptography      48.0.0  GHSA-537c-gmf6-5ccf 48.0.1
pydantic-settings 2.14.1  GHSA-4xgf-cpjx-pc3j 2.14.2
starlette         1.1.0   PYSEC-2026-249      1.3.1
starlette         1.1.0   PYSEC-2026-248      1.3.0
```

### 6.4 npm audit — Produktion (`npm audit --omit=dev`, in `frontend/`)

Exit-Code: 0.

```text
found 0 vulnerabilities
```

### 6.5 npm audit — alle (`npm audit`, in `frontend/`)

Exit-Code: 1 (Dev-Dependency-Funde).

```text
# npm audit report

esbuild  <=0.24.2
Severity: moderate
esbuild enables any website to send any requests to the development server and read the response - https://github.com/advisories/GHSA-67mh-4wv8-2f99
fix available via `npm audit fix --force`
Will install vite@8.1.3, which is a breaking change
node_modules/esbuild
  vite  <=6.4.2
  Depends on vulnerable versions of esbuild
  node_modules/vite


2 vulnerabilities (1 moderate, 1 high)

To address all issues (including breaking changes), run:
  npm audit fix --force
```
