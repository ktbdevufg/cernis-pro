# ADR 0008 — agent-Client: Keystore-Token, WS-Kanal vereinheitlicht, Server-Seite zurückgestellt

- **Status:** Akzeptiert
- **Datum:** 2026-06-04
- **Phase:** Phase 2, Schritt A.3 (agent-Client: Adapter + Use-Cases)
- **Bezug:** Findings S1/S3 (`vision_features_202605.md` §1.2); ADR 0001 (Secret-Handling / keine stillen Fallbacks, Variante B); ADR 0007 (systemnahe Adapter dürfen `modules/` — hier bewusst NICHT angewandt); `phase0_ist_analyse.md` (Migrationsreihenfolge: `agent` nach `capture`); Characterization-Test `tests/characterization/test_agent_rest_contract.py`

## Kontext

Die agent-Funktion in v1 (`modules/agent.py`) ist die Client-Seite eines Remote-Scan-Proxys: Die Haupt-Instanz hält Stammdaten registrierter Remote-Agenten, pingt sie (`/agent/info`) und proxyt Scans über einen WebSocket (`/agent/scan`). Drei konkrete Befunde, S3-nah:

1. **Stiller Fernet-Krypto-Pfad.** Der Agent-Token wurde Fernet-verschlüsselt in der DB-Spalte `remote_agents.token` abgelegt (`save_agent` → `modules.crypto.encrypt`). `crypto.py` enthält denselben stillen Fallback wie bei settings (ADR 0001): `encrypt()` gibt bei jeder Exception den **Klartext** zurück, `decrypt()` schluckt Fehler zu `""`, plus `b64:`-Schein-Obfuskation. Ein verschlüsselter Token in der DB ist damit nur scheinbar geschützt.

2. **Gebrochener Token-Kanal beim Proxy-Scan.** Der Client legt den Token in den **WebSocket-Header** (`extra_headers={"X-Agent-Token": token}`, `modules/agent.py:161`). Die Server-Seite prüft ihn aber im **Body der ersten Nachricht** (`config.get("token")`, `modules/agent.py:212`). Der Header-Token erreicht den Body-Check nie — der Auth-Pfad ist gebrochen. Der Characterization-Test dokumentiert das AS-IS und behauptet **nicht**, dass der Kanal funktioniert.

3. **Stille Fallbacks an den ausgehenden Clients.** `ping_agent` fängt jede Exception zu `{"reachable": False}` (semantisch korrekt, aber stumm); `proxy_scan` schmuggelt einen Verbindungsfehler als **Pseudo-Host** (`{"error": str(e)}`) in die **Ergebnisliste** — ein Fehler, der als Ergebnis getarnt durchläuft. `import websockets` ist zudem ein optionaler `try/except ImportError` mit Fallback-Pseudo-Ergebnis, obwohl `websockets` in v2 eine deklarierte Dependency ist.

Vorbereitet ist bereits (vorheriger Commit): `domain/agent` ist tokenlos migriert (`RemoteAgent` ohne `token`-Feld, ohne `to_dict`-Maske), das Key-Schema liegt als reine Funktion `token_key(id)` vor, die Ports (`AgentRepository`/`AgentPinger`/`AgentScanClient`) sind tokenfrei bzw. nehmen den Token als Parameter, und `domain.agent` ist im `independence`-Contract CI-hart isoliert. **Leere DB ist der Stand** (Scope: leere DB akzeptabel).

## Entscheidung

1. **Keystore statt Fernet (Variante B, Repository token-frei).** Der Token lebt im `SecretStore` (OS-Keystore, `KeyringSecretStore`) unter `token_key(id)`, exakt wie die settings-Secrets (ADR 0001). `SqliteAgentRepository` schreibt **nur** `id/name/url/enabled/cidrs` und fasst die DB-Spalte `token` (sowie die toten Spalten `last_seen`/`version`/`platform`) nicht an. Es gibt **keinen neuen Krypto-Port** und `modules/crypto.py` wird nicht nachgebaut. Der Use-Case orchestriert die Trennung: `SaveAgent` = `repository.save` + `secret_store.set(token_key(id), token)`; `DeleteAgent` löscht beides; `Ping`/`Scan` lesen den Token aus dem SecretStore und reichen ihn an Pinger/ScanClient.

2. **Kein ADR 0007 für agent.** Die agent-Adapter importieren `modules/` **nicht**. Anders als scanning/monitoring (systemnahe Wegwerf-Schicht vor möglichem Sprachwechsel) ist die agent-Client-I/O dünn und stabil: der Krypto-Pfad ist durch den `SecretStore` ersetzt, Ping/Scan sind nativ über `urllib`/`websockets` reimplementiert. Eine `modules`-Ausnahme wäre weder nötig noch gerechtfertigt; der import-linter-Contract bleibt für `infrastructure.agent` lückenlos.

3. **Token-Kanal auf den Body der ersten WS-Nachricht vereinheitlicht.** Der Scan-Client sendet als erste Nachricht `json.dumps({**config, "token": token})` und legt **keinen** Token in einen Verbindungs-Header. Begründung: (a) die — zurückgestellte — Server-Seite prüft den Token genau dort (`config.get("token")`), also ist der Body der Kanal, den eine künftig geheilte Server-Seite mit dem geringsten Eingriff findet; (b) ein In-Band-Auth-Frame ist transport-, proxy- und versions-robuster als `extra_headers` beim WS-Handshake (das Kwarg wurde über `websockets`-Versionen hinweg umbenannt, einige Proxies strippen Custom-Header beim Upgrade). Der `ping`-Pfad (`/agent/info`) bleibt beim `X-Agent-Token`-**Header** — das ist plain HTTP-GET, wo der Header korrekt und unstrittig ist; der Mismatch betraf ausschließlich den WS-Scan-Pfad.

4. **Server-Seite zurückgestellt.** `create_agent_app`/`/agent/info`/`/agent/scan` (das Standalone-Deployable auf dem Remote-Host) wird in A.3 **nicht** migriert. Der Client legt den Token aber body-seitig so ab, dass die spätere Server-Heilung ihn ohne weitere Client-Änderung findet.

5. **Kein Token-Migrationspfad.** Es gibt keine Fernet→Keystore-Umschlüsselung alter Tokens. Leere DB ist der Stand; ein Migrationsskript wäre Arbeit für einen Datenbestand, den es nicht gibt.

6. **S3-Heilung an den Clients.** `ping`: Unerreichbarkeit bleibt ein legitimes Ergebnis (`AgentPingResult(reachable=False, error=...)`) — AS-IS —, ist aber nicht mehr stumm (`logger.warning("agent_ping_failed", ...)`). `scan`: ein Verbindungs-/Übertragungsfehler wird **nicht** als Pseudo-Host in die Ergebnisliste geschmuggelt, sondern als typisierter `AgentScanError` propagiert (plus `logger.warning`); die api-Schicht mappt ihn später auf einen Statuscode. `websockets` wird top-level importiert (deklarierte Dependency), kein optionaler Import mit Fallback. Korruptes `cidrs`-JSON ist ein `CorruptAgentError` mit id-Bezug (Muster `CorruptDeviceError`), kein leerer Roh-Fallback.

## Konsequenzen

**Positiv**
- Kein Klartext-/Schein-verschlüsselter Token in der DB: das Geheimnis lebt ausschließlich im OS-Keystore (Variante B). Ein Keystore-Ausfall greift über `SecretStoreUnavailableError` denselben 503-Handler wie bei settings (`app.py`) — kein stiller Erfolg.
- Repository token-frei: man kann nicht leaken, was nicht da ist (analog zur tokenlosen `RemoteAgent`).
- Der WS-Token-Kanal ist clientseitig geheilt und auf den robusteren Body-Kanal vereinheitlicht; eine künftige Server-Heilung ist ein lokaler Eingriff.
- Keine stillen Fallbacks mehr an den ausgehenden Clients (Scan-Fehler typisiert, Import hart, JSON hart) — ohne die legitime reachability-Semantik des Pings zu verbiegen.
- `infrastructure.agent` bleibt frei von `modules/`; der import-linter-Contract steht für dieses Paket lückenlos (kein ADR-0007-Footprint).

**API-Vertragsänderung**
- **Keine** in diesem Schritt. A.3 liefert Adapter + Use-Cases; die lebenden REST-Routen (`GET/POST /api/agents`, `DELETE`, `…/ping`, `…/scan`) laufen weiter über den Altcode (`main.py`). Die api-seitige Verdrahtung und die daraus folgenden Vertragsanpassungen (z. B. `AgentScanError` → Statuscode, 404 aus `AgentNotFoundError`) kommen im api-Folgeschritt.

**Kosten / Migration**
- Drei Adapter + fünf Use-Cases statt eines Moduls — Mehraufwand, getragen vom Variante-B-Referenzmuster und der CI-harten Schichtung.
- **Strangler:** `modules/agent.py` (inkl. der zurückgestellten Server-Seite) und `modules/crypto.py` bleiben vorerst bestehen, bis die api-Routen auf die neuen Use-Cases umgehängt sind. Löschung des agent-Altcodes erst nach diesem Folgeschritt; `crypto.py` erst, wenn auch der letzte settings-Konsument migriert ist (vgl. ADR 0001).
- Die Server-Seite ist bewusst offen: bis sie geheilt ist, ist der Proxy-Scan-Auth-Pfad nur clientseitig vorbereitet, nicht end-to-end funktionsfähig. Das ist dokumentiert und gewollt (Scope: Server-Seite zurückgestellt).
