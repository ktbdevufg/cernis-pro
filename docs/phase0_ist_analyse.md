# CERNIS PRO — Phase 0: Ist-Analyse des Backends

**Stand:** 2026-05-27
**Grundlage:** `backend/` (35 Python-Module, 8.796 Zeilen), analysiert ohne Build-Artefakte
**Zweck:** Vollständiges Bild des Ist-Zustands als Grundlage für die Strangler-Fig-Migration (Phase 2)
**Bezug:** `pre_release_202605.md` (Plan), `vision_features_202605.md` (Vision/Findings)

---

## 1. Zusammenfassung

Das Backend ist ein FastAPI-Monolith: **`main.py` mit 1.961 Zeilen** trägt **100 API-Endpunkte** (inkl. 3 WebSockets) und importiert **29 Module**. Datenpersistenz läuft über **9 Module**, die direkt `sqlite3.connect(DB_PATH)` aufrufen — kein zentrales Persistence-Layer. Insgesamt **15 Tabellen** in einer einzigen `cernis.db`. Es existiert **kein einziger Test**.

Alle Findings des Principal-Reviews (A1–A6, S1–S5) sind im Code faktisch bestätigt. Zwei Befunde sind **gravierender** als im Review notiert (siehe 6).

---

## 2. Modul-Inventar

### 2.1 Persistenz-Module (greifen direkt auf SQLite zu) — Finding A2

| Modul | Zeilen | Tabellen | Zweck |
|---|---|---|---|
| `storage.py` | 146 | `settings`, `known_devices`, `scan_history` | Settings-KV, Alt-Geräte-Tabelle, Scan-Historie |
| `devices_db.py` | 154 | `devices`, `device_ip_history` | Neue, reiche Geräte-Tabelle + IP-Verlauf |
| `alerting.py` | 311 | `alert_rules`, `alert_history` | Alarm-Regeln, SMTP/macOS-Notify |
| `monitor.py` | 299 | `monitor_events`, `rtt_history` | Host-Monitoring, RTT-Verlauf |
| `arp_guard.py` | 197 | `arp_baseline`, `arp_alerts` | ARP-Spoofing-Erkennung |
| `sla.py` | 133 | `sla_targets`, `sla_samples` | SLA-/Verfügbarkeitsmessung |
| `scheduler.py` | 167 | `scan_schedules` | Geplante Scans |
| `agent.py` | 269 | `remote_agents` | Remote-Agent-Verwaltung |
| `metrics.py` | 240 | (liest aus o.g.) | Prometheus/Influx/HomeAssistant-Export |

### 2.2 Reine Helfer-Module (kein DB-Zugriff, keine Modul-Kopplung)

Diese 20 Module sind **gut isolierbar** — sie sind Adapter-Kandidaten ohne State:
`crypto`, `cve`, `default_creds`, `discovery`, `fritzbox`, `interfaces`, `internet`, `ipv6`, `lldp`, `mdns`, `nettools`, `pcap`, `portscan`, `report`, `resolver`, `snmp`, `ssdp`, `tls`, `vendor`, `wol`

### 2.3 Sonderfälle

- `db_path.py` (75 Z.) — **sauber gelöst**: env → macOS-Bundle → Windows → Linux-XDG → Dev-Fallback. Bleibt im Rewrite als Infrastruktur erhalten.
- `arp_guard.py` — **einziges** Persistenz-Modul mit Modul-Kopplung (importiert `discovery`, `vendor`).
- `cernis_cli.py` (312 Z.), `generate_manual.py` (577 Z.) — CLI/Doku, außerhalb der API.

---

## 3. Domänen-Karte

Aus Endpunkt-Präfixen und Modulen abgeleitet. Bildet die Basis für die `ports/`-Schnitte.

| Domäne | Module | API-Präfix | Tabellen |
|---|---|---|---|
| **scanning** | discovery, portscan, nettools, resolver, vendor | `/api/arp`, `/api/scan`, `/ws/scan` | scan_history |
| **devices** | devices_db, storage | `/api/devices/*` | devices, device_ip_history, known_devices |
| **monitoring** | monitor, sla | `/api/monitor/*`, `/api/sla/*`, `/ws/monitor` | monitor_events, rtt_history, sla_targets, sla_samples |
| **alerting** | alerting | `/api/alerts/*` | alert_rules, alert_history |
| **security** | arp_guard, default_creds, cve, tls | `/api/security/*`, `/api/cve/*`, `/api/tls/*` | arp_baseline, arp_alerts |
| **capture** | pcap, lldp | `/api/pcap/*`, `/api/lldp/*`, `/ws/pcap` | — |
| **fritzbox** | fritzbox | `/api/fritz/*` | — |
| **discovery-ext** | mdns, ssdp, ipv6, snmp | `/api/mdns`, `/api/ssdp`, `/api/ipv6/*`, `/api/snmp/*` | — |
| **agent** | agent | `/api/agents/*` | remote_agents |
| **scheduler** | scheduler | `/api/schedules/*` | scan_schedules |
| **settings** | storage | `/api/settings/*` | settings |
| **tools** | internet, nettools | `/api/tools/*`, `/api/internet/*` | — |
| **export/metrics** | metrics, report | `/api/export/*`, `/metrics` | (liest) |

### 3.1 Geplante neue Domänen (aus Vision-Doc)
`traffic` (Per-App-Monitoring), `process` (Prozess-Sicht), `analysis` (interpretierende Schicht). Noch nicht im Code — Greenfield in der neuen Architektur.

---

## 4. Vollständiges DB-Schema (15 Tabellen, alle in `cernis.db`)

```
devices            (mac PK, vendor, label, tags, notes, category, is_known,
                    first_seen, last_seen, last_ip, times_seen, open_ports,
                    hostname, os_guess)                          ← devices_db
device_ip_history  (id PK, mac, ip, seen_at)                     ← devices_db
known_devices      (mac PK, label, tags, notes, is_known,
                    first_seen, last_seen)                        ← storage  [REDUNDANT]
settings           (key PK, value)                               ← storage
scan_history       (id PK, scanned_at, cidr, host_count,
                    result_json)                                 ← storage
alert_rules        (id PK, name, rule_type, target, threshold,
                    notify_email, notify_macos, enabled,
                    last_triggered)                              ← alerting
alert_history      (id PK, rule_id, rule_name, rule_type, target,
                    message, ts, datetime)                       ← alerting
monitor_events     (id PK, target_id, label, event, rtt_ms,
                    ts, datetime)                                ← monitor
rtt_history        (id PK, target_id, rtt_ms, loss_pct, ts)      ← monitor
arp_baseline       (ip PK, mac, vendor, first_seen, last_seen)   ← arp_guard
arp_alerts         (id PK, alert_type, ip, old_mac, new_mac,
                    old_vendor, new_vendor, severity, message,
                    ts, datetime)                                ← arp_guard
sla_targets        (id PK, target_id UNIQUE, label, host,
                    enabled, created_at)                         ← sla
sla_samples        (id PK, target_id, ts, alive, rtt_ms)         ← sla
scan_schedules     (id PK, name, cidr, profile_id, schedule,
                    enabled, last_run, next_run, created_at)     ← scheduler
remote_agents      (id PK, name, url, token, enabled, last_seen,
                    version, platform, cidrs)                    ← agent
```

### 4.1 Schema-Befunde
- **`devices` vs. `known_devices`: echte Redundanz.** `devices` (14 Spalten) ist der nie zu Ende geführte Nachfolger von `known_devices` (7 Spalten). Beide haben `mac` als PK und überlappende Spalten (label, tags, notes, is_known, first/last_seen). → Im Rewrite: zu **einer** `devices`-Tabelle hinter `DeviceRepository`-Port zusammenführen, `known_devices`-Daten migrieren.
- **Inkonsistente Zeitstempel:** mal `TEXT datetime('now')`, mal `REAL` (Unix-ts), teils beides (`ts` + `datetime`) in derselben Tabelle. → Im Rewrite vereinheitlichen (Empfehlung: UTC-ISO-8601 TEXT *oder* durchgängig REAL, nicht gemischt).
- **`remote_agents.token` im Klartext** gespeichert (hängt mit S3/S4 zusammen).
- **JSON-in-TEXT** (`tags`, `open_ports`, `result_json`, `cidrs`) — pragmatisch ok, aber im Domänenmodell als typisierte Felder abbilden.

---

## 5. API-Inventar & State

- **100 Endpunkte** in `main.py`, davon **3 WebSockets** (`/ws/monitor`, `/ws/pcap`, `/ws/scan`).
- **Catch-all** `/{full_path:path}` + `/` servieren das React-Frontend (StaticFiles-Ersatz).
- **State:** `_fritz_cache: dict` (Modul-Global in main.py), `run_monitor()` als Background-Task via `asyncio.create_task`. → Finding A3: Lebenszyklen unklar, im Composition Root explizit machen.

---

## 6. Security-Findings — Code-Verifikation (Stand Ist)

| # | Status | Code-Beleg |
|---|---|---|
| S1 | **bestätigt** | `main.py:191` `CORSMiddleware allow_origins=["*"]`; **0** der 100 Endpunkte haben `Depends`/Auth |
| S2 | **bestätigt** | `osascript` in `alerting.py:148`, `monitor.py:188` — Script-String per Interpolation |
| S3 | **schlimmer als notiert** | `crypto.py`: `encrypt()` fällt bei Exception **still auf `return plaintext`** zurück; `decrypt()` akzeptiert Klartext als „legacy"; zusätzlich `b64:`-Obfuskation als Schein-Sicherheit |
| S4 | **bestätigt** | `agent.py`: Default `--host 0.0.0.0`, Default-Token `changeme`, `allow_origins=["*"]` |
| S5 | (Doku, nicht im Code prüfbar) | Pcap-Rechte-Empfehlung — im Doku-Teil adressieren |

**Gravierender als Review:** S3. Der stille Plaintext-Fallback bedeutet: Bei jedem Crypto-Fehler werden Secrets unbemerkt im Klartext gespeichert — der Nutzer glaubt sie verschlüsselt. Das ist genau der „stille Fallback", den der Vorzeige-Anspruch (keine stillen Fallbacks) verbietet. **Priorität im Rewrite.**

---

## 7. Empfohlene Migrations-Reihenfolge

Begründet aus Isolierbarkeit (Helfer-Module = einfach) und Kopplung (Persistenz = schwerer).

> **Aktualisiert durch ADR 0006:** `devices` wird **vor** `scanning` migriert (scanning schreibt via `update_device_from_scan` in `devices` und liest `get_known_devices`). Die ursprüngliche Analyse-Reihenfolge ist als historischer Ist-Stand erhalten; unten sind nur die Positionen `devices`↔`scanning` getauscht, die Befunde bleiben unverändert.

1. **`settings`** (Phase 1, Referenz) — kleinste Persistenz-Domäne, 1 Tabelle, klar isoliert. Etabliert das Repository-Port-Muster.
2. **`devices`** — hier die `devices`/`known_devices`-Zusammenführung. Mittel-komplex wegen Datenmigration.
3. **`scanning`** — Kernfeature; Helfer-Module (discovery, portscan, nettools, resolver, vendor) sind state- und DB-frei, also leicht hinter Ports zu ziehen. `scan_history` als erste echte Repository-Nutzung.
4. **`monitoring`** (monitor + sla) — 4 Tabellen, Background-Task (State!), WebSocket. Anspruchsvoll.
5. **`alerting`** — hängt an monitoring; S2 (osascript) hier mit sicherem Notification-Port lösen.
6. **`security`** (arp_guard, cve, tls, default_creds) — arp_guard hat Modul-Kopplung, daher nach scanning/devices.
7. **`capture`** (pcap, lldp) — WebSocket, erhöhte Rechte (knüpft an S5 + neues traffic-Rechtemodell).
8. **`agent`** — S4 hier lösen (sichere Defaults). Tokens verschlüsseln.
9. **Hilfsmodule & tools** (mdns, ssdp, snmp, ipv6, internet, report, metrics, fritzbox, wol).

**Neue Domänen** (`traffic`, `process`, `analysis`) erst **nach** Stabilisierung des Bestands — als Greenfield in der dann erprobten Architektur.

---

## 8. Offene Punkte für die Diskussion

- **Zeitstempel-Vereinheitlichung:** TEXT-ISO vs. REAL — Entscheidung vor `monitoring`-Migration nötig.
- **`metrics.py`** liest quer über mehrere Domänen-Tabellen. Im Hexagonal-Modell: eigener Read-Port oder Query-Service? In Phase 2 klären.
- **`fritzbox` als eigene Domäne oder Adapter** von `scanning`/`tools`? Tendenz: eigener Adapter, da gerätespezifisch.
- **`data/`-Freigabe ist gegenstandslos:** keine sensible Laufzeit-DB im Repo; `backend/data/` enthält nur `oui.json` (öffentliche Hersteller-Liste) + `fetch_oui.py`. Schema vollständig aus Code rekonstruiert (dieser Bericht). DB entsteht erst zur Laufzeit unter den OS-Pfaden aus `db_path.py`.

---

**Dokument-Status:** abgeschlossen für Backend-Code. Erweiterbar um `frontend/` + `src-tauri/`, falls für API-Vertrags-Analyse nötig.
