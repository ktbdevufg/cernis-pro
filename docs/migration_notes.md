# CERNIS PRO 2.0 — Migrations-Notizen

**Stand:** 2026-05-27
**Zweck:** Festhalten, wo die uv-Lock-Auflösung (Phase 1, Schritt 1) Abhängigkeiten deutlich über die `>=`-Untergrenzen aus `backend/requirements.txt` (v1) gehoben hat. Die Major-Sprünge sind **kein akutes Problem** — der Altbestand läuft weiter —, aber sie sollen bei der jeweiligen Domänen-Migration (Phase 2) präsent sein, damit ein Breaking Change nicht überrascht.

**Lesart:** v1-Pin = dokumentierte Untergrenze aus `requirements.txt`. v2-Lock = von uv aufgelöste Version (Neuestes im erlaubten Bereich, Stand heute). Stichworte sind Hinweise zum Changelog-Check **vor** der Migration, keine abschließende Analyse.

---

## Major-Sprünge (vor der jeweiligen Domänen-Migration prüfen)

### pysnmp — `>=6.1.0` → `7.1.27` (Major 6 → 7)
- Betrifft Domäne **discovery-ext** (`snmp`).
- Stichworte: pysnmp 7 ist ein Rewrite — synchrone HLAPI entfernt, **asyncio-only**; Paket-/Import-Struktur reorganisiert (`pysnmp.hlapi.asyncio`). Synchroner SNMP-Code aus v1 läuft auf 7 nicht unverändert.
- Konsequenz: Bei `snmp`-Migration den Adapter gegen die asyncio-HLAPI neu schreiben.

### psutil — `>=5.9.0` → `7.2.2` (Major 5 → 7)
- Betrifft die geplanten Domänen **process** und **traffic** (und alles, was Verbindungen/Prozesse liest).
- Stichworte: psutil 6.0 hat deprecte APIs entfernt — u. a. `Process.connections()` → `net_connections()`; einige Plattform-Konstanten/Felder geändert. psutil 7 weitere Cleanups.
- Konsequenz: Verbindungs-/Prozess-Adapter auf die neuen Methodennamen prüfen.

### websockets — `>=12.0` → `16.0` (Major 12 → 16)
- Betrifft die WS-Endpunkte (`/ws/scan`, `/ws/monitor`, `/ws/pcap`) bei **scanning/monitoring/capture**.
- Stichworte: ab websockets 13 ist die Legacy-API (`websockets.legacy`/`websockets.server`) deprecated/entfernt, neue asyncio-Implementierung (`websockets.asyncio`). Praktisches Risiko für die App eher gering, da die WS-Endpunkte über Starlette/uvicorn laufen, nicht über die High-Level-API von `websockets` direkt — bei direkter Nutzung (z. B. Remote-Agent) jedoch prüfen.

### cryptography — `>=41.0.0` → `48.0.0` (Major 41 → 48)
- Betrifft Domäne **settings** (Secret-Handling, `crypto.py`) — also Schritt 6.
- Stichworte: viele Majors dazwischen; entfernt/deprected vor allem Low-Level- und Alt-Algorithmen. **Fernet** (von `crypto.py` genutzt) ist über alle Versionen stabil → geringes Risiko für unseren Anwendungsfall, aber Magnitude festhalten.

### fastapi / starlette — fastapi `>=0.111.0` → `0.136.3`, starlette → `1.1.0`
- Betrifft **app.py** direkt (Schritt 3) — Lifespan/Middleware-Aufbau.
- Stichworte: neuere FastAPI/Starlette bevorzugen den **Lifespan-Kontext** statt `@app.on_event`; starlette hat mit 1.0 einige Cleanups. app.py von Anfang an mit Lifespan bauen (kein `on_event`).

---

## Minor/Patch — unkritisch, nur zur Vollständigkeit

| Modul | v1-Pin | v2-Lock |
|---|---|---|
| uvicorn[standard] | >=0.29.0 | 0.48.0 |
| zeroconf | >=0.132.0 | 0.149.16 |
| reportlab | >=4.0.0 | 4.5.1 |
| fritzconnection | >=1.13.0 | 1.15.1 |
| dnspython | >=2.4.0 | 2.8.0 |
| apscheduler | >=3.10.0 | 3.11.2 |
| websocket-client | >=1.7.0 | 1.9.0 |
| scapy | >=2.5.0 | 2.7.0 |

scapy 2.5 → 2.7: kein Major-Sprung, aber `capture` nutzt scapy intensiv — bei Migration kurz gegen das 2.6/2.7-Changelog gegenchecken (entfernte Python-Versionen, Layer-Details).

---

**Pflege:** Diese Datei wird pro Domänen-Migration ergänzt/abgehakt, wenn der jeweilige Major-Sprung tatsächlich verifiziert wurde.
