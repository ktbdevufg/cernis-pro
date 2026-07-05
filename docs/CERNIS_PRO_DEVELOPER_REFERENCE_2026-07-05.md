# CERNIS PRO 2.0 — Entwickler-Gesamtreferenz

**Datum:** 2026-07-05 · **Stand:** `rewrite/v2` == `e1c9114` (CI gruen)
**Zweck:** Die *eine* konsolidierte Einstiegsreferenz fuer Entwickler. Buendelt die bisher verstreute
Projektdoku (Architektur & Vision, Domaenen-Referenz, Build & Plattform, Glossar, Security-Audit) zu
einer aktuell gueltigen Gesamtsicht. Detailtiefe bleibt in den Spezialdokumenten und ADRs — hier steht
der Ueberblick mit Verweisen, keine Duplikate.

**Verweis-Konvention:**
- Status/Fortschritt → Master-Aufgabenliste.
- Entscheidungs-Details → `docs/adr/` (45 ADRs, Nygard-Format).
- Sicherheits-Details → `docs/SECURITY_AUDIT_2026-07-03.md` + `docs/LICENSE_AUDIT_2026-07.md`.

---

## 1. Was CERNIS PRO ist

Lokaler, passiver Netzwerk- und System-Scanner fuer das eigene Heim-/SOHO-Netz (Desktop-App).
**Produkt-These:** Werkzeug fuer den *muendigen Anwender* — ehrliche Fakten, echte Kontrolle, kein
Bevormunden, kein Schoenfaerben. CERNIS aendert nichts, es zeigt und ordnet ein. Die einzige bewusste
Ausnahme vom Passiv-Prinzip ist die Standardzugangs-Pruefung (scharfe Opt-in-Sonderfunktion, ADR 0044/0045).

**Anspruch:** Best-Effort-Best-Practice-Referenzprojekt — maschinell erzwungene Architekturregeln,
durchgaengige Typisierung, keine toten Pfade, keine stillen Fallbacks, Tests als Voraussetzung,
Doku parallel zum Code (ADRs).

---

## 2. Herkunft: der Rewrite

v2.0 ist ein **strukturierter Backend-Rewrite** von v1.0.0 (nicht Patchen), ausgeloest durch einen
Principal-Review mit gravierenden Findings:
- Monolithische `main.py` (~1.961 Zeilen, 100 Endpunkte, 29 Module, **kein Test**).
- SQLite-Zugriffe in 9 Modulen verstreut; State ueber Modulebenen; agent-feindlich.
- Sicherheitsmaengel (CORS `*`, unauth Endpunkte, AppleScript-Injection, Klartext-Secrets).

**Antwort:** hexagonale Schichtung, ein Repository-Adapter, DI im Composition Root, Characterization-Tests,
CI-Gate. v1.0.0 als `v1.0.0-final` eingefroren; Entwicklung auf `rewrite/v2`. Frontend/Tauri-Shell
bleiben weitgehend unangetastet (eigener GUI-Block spaeter, startet mit Mockups).

---

## 3. Architektur

**Hexagonale 5-Ring-Architektur**, per import-linter mit **8 Contracts** CI-hart erzwungen:

```
domain  ←  ports  ←  application  ←  infrastructure  ←  api
```

Regeln:
- `domain` kennt nichts (nur stdlib + dataclasses; **kein** Pydantic/FastAPI/structlog — ADR 0002).
- `ports` kennt hoechstens `domain`.
- `application` kennt nicht `infrastructure`/`api`.
- `api` ruft nur `application` (nicht domain/ports/infrastructure direkt).
- `infrastructure` kennt nicht `application`/`api`.
- **independence-Contract:** jedes `domain.*`-Subpaket kennt nur sich selbst — keine Domaene-zu-Domaene-Kopplung.
- neue Ringe importieren NICHT den Altcode (`modules/`).

**Querschnitt-Prinzipien:**
- `application` liefert rohe Domaenen-Daten; die **Wire-Form baut der api-Rand** (kein `.to_dict()` in der Domaene).
- Brauchen Domaenen fremde Daten → eigene `Observed*`/`Exportable*`-Typen + Projektion im Composition Root, statt Kopplung.
- **Kein stiller Fallback:** Leerzustand ist gueltig und ehrlich (`""`/`None`/`[]`); echte Fehler werden benannt, nie verschluckt.
- **Rechte ehrlich:** root-pflichtige Features liefern ehrliche 403 mit Handlungshinweis; rootloser Normalfall bleibt nutzbar.
- **Keine Nutzer-Configfiles:** editierbare Einstellungen in SQLite.

**Eingezaeunte Altcode-Ausnahme (ADR 0006/0007):** nur `infrastructure.scanning/monitoring/alerting`
darf alte `modules/`-Funktionen importieren (subtraktiv via `ignore_imports`, dokumentierte
Uebergangskopplung fuer die systemnahe Schicht). domain/ports/application/api bleiben hart.

**Privilege-Separation (ADR 0041):** der Sniff-Helfer `cernis-sniffd` traegt als einzige Komponente
CAP_NET_RAW; das unprivilegierte Backend spricht ihn on-demand ueber AF_UNIX-IPC (laengen-praefixiertes
NDJSON). scapy ist in `backend/infrastructure/sniffd/_scapy.py` gekapselt.

---

## 4. Domaenen (Ueberblick)

Vollstaendige Details je Domaene → **Domaenen-Referenz** + ADRs. Kurzueberblick der Bausteine:

**Kern/Bestand:** settings (0001/0002) · devices (0006) · scanning (0007) · monitoring · security + alerting ·
capture (0010) · agent (0008, Server-Seite zurueckgestellt).

**Analyse/Auswertung:** interfaces (0009) · traffic (0010) · process (0011) · analysis (0012/0013,
Auffaelligkeits-Engine + Flag-Familie 0019–0031) · diagnostics (0014/0038) · export (0015).

**Gegenstellen-Aufloesung (Alleinstellungsmerkmal):** resolver (0016) — neutrale Fakten nebeneinander
(PTR/Forward, TLS-Cert, RDAP, Geo/ASN), jede Quelle `{value, source}`, fehlend ehrlich `null`, kein
Urteil. sni (0017) — der real angefragte Hostname, macht die Buendelung App→Domain→Server ehrlich moeglich.

**Weitere:** fritz_detail (0018, TR-064-Snapshot) · Topologie-Graph (0035) · Route zum Ziel (0036) ·
cve (0037, Drip-Worker gegen Bestand) · outbound_log (0039, Aussenkontakte) · blocklist (0040,
lokale Bewertung — Liste urteilt, nicht CERNIS) · dns_bypass (netzweiter DNS-Waechter) ·
dns_trust (0042/0043, Vertrauensmodell) · behavior (Verhaltensprofile) · reporting.

**Standardzugangs-Pruefung (0044/0045):** scharfe Opt-in-Sonderfunktion. Session-Arm-Flag,
Privatnetz-Guard (RFC1918/loopback/link-local), TLS-Haertung mit self-signed-Kennzeichnung, Rate-Limit.
Modellbasierter Workflow: Geraetewahl → Hersteller/Modell-Ermittlung → drei Faelle
(Entwarnung/Kandidaten/keine Infos) → gezielte Pruefung nur gewaehlter Kandidaten gegen echte offene
Ports → Historie. Kuratierte, pflegbare Credential-Liste mit Konfidenz-Stufen.

---

## 5. Reporting

Sechs Berichtstypen, einheitliche Architektur (neutrale In/Out-Typen → reine Aggregation → duenner
Use-Case → PDF-Modell → Wire-Out → Runner-Protocols → Composition Root → Frontend-View → Kachel):
Sicherheits-, Bestands-, CVE-, Aussenkontakte-, DNS-Waechter-, Verhaltensprofil-Bericht.

**Pfad-Hinweis:** Reporting-Views liegen unter `frontend/src/components/` (nicht `views/`);
`ReportingView.jsx` (Kachel-Uebersicht) in `views/`. PDF-Renderer: `backend/infrastructure/export_pdf.py`.

---

## 6. Toolchain, Build & CI

**Stack:** FastAPI/Python (uv) + React/Vite + Tauri v2, SQLite (aiosqlite), pydantic v2.
**Qualitaets-Gates (5-Gate, immer aus Repo-Root):**
`ruff format --check` · `ruff check` · `lint-imports` (8 Contracts) · `mypy` (strict) · `pytest`.
Frontend-Gate: `npm run build`. **CI:** GitHub Actions, zwei Jobs (quality + frontend).

**Persistenz:** ein Adapter hinter Repository-Port; Secrets im OS-Keystore (keyring/libsecret, ADR 0001).
**Build:** PyInstaller (frozen); Sniff-Helfer separat gebaut (ADR 0041). scapy fuer capture+sni.

**Bekannter Flake:** `test_start_pcap_returns_started_or_error` (sniffd, CAP_NET_RAW/BrokenPipe) — immer ignorieren.

**Multi-Plattform-Roadmap (nach Backend-Abschluss):** Fedora x64 → Ubuntu ARM → Fedora ARM →
Windows x64 → Windows ARM → macOS Silicon.

---

## 7. Sicherheit (Zusammenfassung)

Vollstaendiger v2-Audit: `docs/SECURITY_AUDIT_2026-07-03.md` (9 Befunde, Naht-Matrix, Scanner-Rohausgabe).
Behoben: F-01 Et.1 (Origin-Guard HTTP+WS), F-02 (SSRF), F-04–F-07. Zurueckgestellt mit Begruendung:
F-01 Et.2 (lokaler Shared-Token), F-08 (esbuild/vite dev-only). Als Feature geloest: F-03/F-09
(default-creds, ADR 0044/0045). Kernprinzipien „kein stiller Fallback" und „Rechte ehrlich" ziehen
sich durch alle Domaenen.

---

## 8. Lizenz

**GPL-2.0-only** (siehe `LICENSE`, `docs/LICENSE_AUDIT_2026-07.md`). scapy (GPL-2.0-only, im Sniffer)
zwingt v2 und schliesst GPLv3 aus. Bekannter offener Punkt: `requests` (Apache-2.0, transitiv via
`fritzconnection`) steht in Spannung zu GPLv2 — in der Praxis bei unmodifizierter Nutzung meist
toleriert, bei erhoehten Compliance-Anforderungen juristisch zu bewerten. GPLv3 waere nur nach
Abloesung von scapy moeglich (abgrenzbarer Block mittlerer Groesse: Capture via libpcap/AF_PACKET +
eigenes Parsing inkl. CDP/LLDP).

---

## 9. Arbeitsweise (Kurzfassung)

- Karl entscheidet das *Was* (Produkt), Claude das *Wie* (Architektur/Technik); nur echte Produktfragen eskalieren.
- Aenderungen einzeln, „erst verstehen, dann fixen"; 5-Gate gruen vor jedem Commit; Staging explizit (nie `git add .`).
- Code-Aenderungen ueber den zweistufigen Claude-Code-Workflow; kein Amend/Force-Push auf Gepushtes.
- Grosse Feature-Bloecke in Etappen mit gruenem Gate je Etappe; EIN Push am Milestone-Ende mit CI-Watch.
- Detaillierte Regeln → Arbeitsregeln-Dokument.

---

## 10. Konsolidierte Quellen (Herkunft dieser Referenz)

| Bereich | Detailquelle |
|---|---|
| Vision, Rewrite-Anlass, Produkt-These | Architektur & Vision |
| Domaenen im Detail, ADR-Liste | Domaenen-Referenz + `docs/adr/` |
| Build, Toolchain, Plattform | Build & Plattform |
| Begriffe | Glossar (48 Eintraege) |
| Sicherheit | `docs/SECURITY_AUDIT_2026-07-03.md` |
| Lizenz | `docs/LICENSE_AUDIT_2026-07.md`, `docs/THIRD_PARTY_LICENSES.md` |
| Status | Master-Aufgabenliste |

**Historische Dokumente** (Referenz, nicht mehr aktiv pflegen): `docs/phase0_ist_analyse.md`,
`docs/pre_release_202605.md`, `docs/vision_features_202605.md`, `docs/migration_notes.md`,
`docs/CERNIS_PRO_snapshot.json`.
