# CERNIS PRO 2.0.0 — Release-Notes

**Release-Datum:** 2026-07-05
**Tag:** `v2.0.0` · **Commit:** `8e072f2` (rewrite/v2, CI gruen)
**Lizenz:** GPL-2.0-only

---

## Ueberblick

CERNIS PRO 2.0.0 ist ein vollstaendiger, strukturierter Backend-Rewrite von v1.0.0. Aus einem
FastAPI-Monolithen (~1.961 Zeilen `main.py`, kein Test) wurde eine hexagonale, maschinell
architektur-gepruefte, durchgaengig getestete Anwendung.

---

## Projekt-Kennzahlen

| Kennzahl | Wert |
|---|---|
| Entwicklungszeitraum | 2026-03-30 bis 2026-07-05 (~3 Monate) |
| Commits auf `rewrite/v2` | 468 |
| Quellcode-Zeilen (Backend + Frontend) | 165.467 |
| Quellcode-Dateien | 796 |
| Architektur-Entscheidungen (ADRs) | 45 |
| import-linter-Contracts | 8 (CI-hart) |

---

## Kernpunkte gegenueber v1.0.0

**Architektur**
- Hexagonale 5-Ring-Architektur (domain ← ports ← application ← infrastructure ← api), per
  import-linter mit 8 Contracts CI-hart erzwungen.
- Ein Repository-Adapter statt verstreuter SQLite-Zugriffe; Dependency Injection im Composition Root.
- Durchgaengige Typisierung (mypy strict), keine toten Pfade, keine stillen Fallbacks.
- Vollstaendige Test-Abdeckung als CI-Gate (5-Gate-Kette).

**Funktionsumfang**
- Passives Live-Monitoring, Aussenkontakte-Aufzeichnung, netzweiter DNS-Waechter, Verhaltensprofile.
- Mehrstufige Gegenstellen-Aufloesung (resolver + SNI) — neutrale Fakten statt Urteil.
- Sechs Berichtstypen (Sicherheit, Bestand, CVE, Aussenkontakte, DNS-Waechter, Verhaltensprofil), PDF.
- CVE-Monitoring gegen den Geraete-Bestand; FritzBox-Detailauslese (TR-064).
- Standardzugangs-Pruefung als scharfe, geraete-/modellbasierte Opt-in-Sonderfunktion.
- Dynamisches Nutzungs-Ranking im Startseiten-Schnellzugriff.
- Benutzerhandbuch als reportlab-PDF (DE/EN), In-App-Hilfe.

**Sicherheit**
- Vollstaendiger v2-Sicherheits-Audit (9 Befunde dokumentiert, behoben/bewusst zurueckgestellt).
- Privilege-Separation: nur der Sniff-Helfer `cernis-sniffd` traegt CAP_NET_RAW.

**Lizenz**
- GPL-2.0-only. Lizenz-Audit dokumentiert Vertraeglichkeit aller ausgelieferten Abhaengigkeiten und
  den bekannten offenen Punkt (requests/Apache via fritzconnection).

---

## Bekannte offene Punkte (v2.1 / spaeter)

- Hersteller-Normalisierung bei der Standardzugangs-Pruefung (AVM-Matching).
- requests/Apache-Lizenz-Spannung — bei erhoehten Compliance-Anforderungen juristisch zu bewerten;
  GPLv3 waere nur nach Abloesung von scapy moeglich.
- Zurueckgestellt: F-01 Etappe 2 (lokaler Shared-Token), F-08 (esbuild/vite dev-only).

---

## Ausblick

Multi-Plattform-Roadmap (Fedora/Ubuntu/Windows/macOS), GUI-Redesign-Block, v3.0-Ideen
(IoT-/Geraeteklassen-Erfassung, TR-064-Router-Adapter, KI-Konzept).
