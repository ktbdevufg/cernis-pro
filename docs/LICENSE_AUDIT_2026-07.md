# CERNIS PRO 2.0 — Lizenz-Audit

**Datum:** 2026-07-05
**Ergebnis:** Gesamtwerk lizenziert als **GPL-2.0-only** (GPLv2).
**Methodik:** `pip-licenses` ueber die aufgeloeste uv-Umgebung + Einzelverifikation der kritischen Pakete
gegen SPDX-Header/offizielle Quellen. Trennung Runtime- vs. dev-Abhaengigkeiten ueber `uv tree`.

---

## Kernergebnis

Die Ziel-Lizenz **GPLv3 ist nicht moeglich**, solange **scapy** (Sniffer, Runtime-Pflicht) eingebunden
ist: scapy ist **GPL-2.0-only** (per SPDX-Header im Code und PyPI-Metadaten festgeschrieben, ohne
"or later"-Option). GPL-2.0-only und GPLv3 sind gegenseitig inkompatibel. Damit erbt das Gesamtwerk die
GPLv2-Beschraenkung → **Lizenzwahl GPL-2.0-only**.

---

## Offener rechtlicher Punkt (bewusst dokumentiert, nicht versteckt)

**Es besteht eine Spannung zwischen zwei Runtime-Abhaengigkeiten:**

| Paket | Lizenz | Rolle | Zieht Richtung |
|---|---|---|---|
| scapy | GPL-2.0-only | Sniffer (direkt) | **GPLv2** (schliesst v3 aus) |
| requests | Apache-2.0 | transitiv via `fritzconnection` | **GPLv3** (nicht v2-kompatibel) |

`requests` wird **nicht direkt** genutzt, aber `fritzconnection` (Runtime-Pflicht, real genutzt in
`backend/api/system.py`, `backend/app.py`, `backend/modules/fritzbox.py`) zieht es zwingend nach.

**Konsequenz ehrlich:** Streng juristisch ist der aktuelle Dependency-Satz mit **keiner** reinen
GPL-Version zu 100 % konfliktfrei — scapy blockiert v3, requests(Apache) blockiert v2.

**Praxis-Einordnung (keine Rechtsberatung):** Die Apache-2.0/GPLv2-Inkompatibilitaet betrifft nach
verbreiteter Auffassung primaer das *Kombinieren/Modifizieren* von Code. Die bloße *Nutzung* einer
unmodifizierten Apache-2.0-Bibliothek als separater Baustein wird in GPLv2-Projekten in der Praxis
haeufig toleriert. Wasserdicht ist das nicht — es ist eine Rechtsfrage, die bei Bedarf juristisch zu
bewerten ist (Empfehlung fuer die Geschaeftsleitung).

**Drei Auswege (falls vollstaendige Konfliktfreiheit verlangt wird):**
1. **GPLv2 belassen + requests/Apache-Spannung akzeptieren** (tolerierte Praxis, jetzige Wahl).
2. **GPLv3 anstreben** → erfordert **Ablösung von scapy** (Capture via libpcap/AF_PACKET + eigenes
   Paket-Parsing inkl. CDP/LLDP; scapy ist in `backend/infrastructure/sniffd/_scapy.py` gekapselt →
   abgrenzbarer Block mittlerer Groesse). requests bleibt dann unproblematisch.
3. **Beides abloesen** (scapy + fritzconnection/requests) → aufwaendig, da fritzconnection ein
   Kern-Feature (FritzBox-Auslese) traegt.

---

## Runtime-Abhaengigkeiten (ausgeliefertes Werk) — GPLv2-Vertraeglichkeit

| Paket | Lizenz | GPLv2-vertraeglich? | Anmerkung |
|---|---|---|---|
| scapy | GPL-2.0-only | ja (identisch) | zwingt die Lizenzwahl |
| fastapi | MIT | ja | |
| uvicorn | BSD-3-Clause | ja | |
| pydantic / pydantic-settings | MIT | ja | |
| structlog | MIT OR Apache-2.0 | ja | MIT-Zweig gewaehlt |
| cryptography | Apache-2.0 OR BSD-3-Clause | ja | **BSD-Zweig gewaehlt** |
| zeroconf | LGPL-2.1-or-later | ja | "or later" → mit GPLv2 vereinbar |
| reportlab | BSD | ja | |
| fritzconnection | MIT | ja (selbst) | zieht aber requests (Apache, s.o.) |
| requests (transitiv) | Apache-2.0 | **offener Punkt** | siehe oben |
| psutil | BSD-3-Clause | ja | |
| pysnmp | BSD | ja | |
| dnspython | ISC | ja | |
| apscheduler | MIT | ja | |
| websockets | BSD-3-Clause | ja | ersetzt websocket-client |
| keyring | MIT | ja | |
| certifi | MPL-2.0 | ja | dateibasiertes copyleft, vertraeglich |
| pathspec | MPL-2.0 | ja | |

**Entfernt im Zuge des Audits:** `websocket-client` (Apache-2.0-only, war der einzige direkt vermeidbare
Apache-Konflikt) → migriert auf `websockets` (BSD-3-Clause) in `backend/cernis_cli.py`.

---

## Nicht ausgelieferte Abhaengigkeiten (dev-group, irrelevant fuer die Werk-Lizenz)

Nur fuer Entwicklung/CI, werden nicht mitgeliefert und beeinflussen die Werk-Lizenz nicht:
`ruff`, `mypy`, `pytest`, `import-linter`, `pre-commit`, `bandit`, `pip-audit` (+ dessen transitive
Deps: `cachecontrol`, `cyclonedx-python-lib`, `msgpack`, `sortedcontainers`, `requests`, `stevedore`,
`license-expression`, `py-serializable`, `pip-api`).

**pyinstaller** (GPLv2) ist ein **Build-Werkzeug**, kein Bestandteil des ausgelieferten Werks.

---

## Nicht mitgeliefert / deaktiviert

- **EasyList / EasyPrivacy** (GPL-2.0-only Blocklisten): bleiben **deaktiviert** und werden nicht
  gebuendelt — sie wuerden bei einer spaeteren GPLv3-Umstellung ohnehin blockieren.
- Blocklisten werden generell per URL geladen, nicht mitgeliefert.

---

## Umgesetzte Massnahmen

- [x] `LICENSE` (GPL-2.0, offizieller Volltext) im Repo-Root.
- [x] Lizenz-Metadaten: `pyproject.toml` (`license = "GPL-2.0-only"` + OSI-Classifier),
      `frontend/package.json` (`"license": "GPL-2.0-only"`).
- [x] `websocket-client` (Apache-2.0-only) entfernt, auf `websockets` (BSD-3) migriert, `uv.lock` aktualisiert.
- [x] `docs/THIRD_PARTY_LICENSES.md` (vollstaendige Auflistung).
- [x] Dieser Audit-Report.

---

## Empfehlung fuer die Geschaeftsleitung

GPLv2 ist der **jetzt umsetzbare** Stand. Falls eine strikt konfliktfreie oder eine GPLv3-Lizenzierung
gewuenscht ist, ist die **scapy-Ablösung** der entscheidende (abgrenzbare, mittelgroße) Arbeitsblock.
Die requests/Apache-Spannung sollte bei erhoehten Compliance-Anforderungen juristisch bewertet werden.
