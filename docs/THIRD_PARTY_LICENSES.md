# Third-Party-Lizenzen — CERNIS PRO 2.0

CERNIS PRO 2.0 ist als **GPL-2.0-only** lizenziert (siehe `LICENSE`). Dieses Dokument listet die
Abhaengigkeiten des **ausgelieferten Werks** (Runtime) mit ihren Lizenzen. Entwicklungs-/CI-Werkzeuge
werden nicht mitgeliefert und sind am Ende separat vermerkt.

Stand: 2026-07-05. Erhebung: `pip-licenses` ueber die aufgeloeste uv-Umgebung + Einzelverifikation.
Details zur Lizenz-Kompatibilitaet: `docs/LICENSE_AUDIT_2026-07.md`.

---

## Runtime-Abhaengigkeiten (Python, ausgeliefert)

| Paket | Version | Lizenz |
|---|---|---|
| apscheduler | >=3.10.0 | MIT |
| cryptography | >=48.0.1 | Apache-2.0 OR BSD-3-Clause (BSD-Zweig gewaehlt) |
| dnspython | >=2.4.0 | ISC |
| fastapi | >=0.111.0 | MIT |
| fritzconnection | >=1.13.0 | MIT (zieht transitiv `requests`, Apache-2.0) |
| keyring | >=25.7.0 | MIT |
| psutil | >=5.9.0 | BSD-3-Clause |
| pydantic | >=2.7.0 | MIT |
| pydantic-settings | >=2.14.2 | MIT |
| pysnmp | >=6.1.0 | BSD |
| reportlab | >=4.0.0,<5 | BSD |
| scapy | >=2.5.0 | GPL-2.0-only |
| structlog | >=24.1.0 | MIT OR Apache-2.0 (MIT-Zweig gewaehlt) |
| uvicorn[standard] | >=0.29.0 | BSD-3-Clause |
| websockets | >=12.0 | BSD-3-Clause |
| zeroconf | >=0.132.0 | LGPL-2.1-or-later |

### Wesentliche transitive Runtime-Abhaengigkeiten

| Paket | Lizenz | Herkunft |
|---|---|---|
| requests | Apache-2.0 | via fritzconnection — siehe Lizenz-Audit (offener Punkt) |
| certifi | MPL-2.0 | via requests |
| charset-normalizer / idna / urllib3 | MIT / BSD / MIT | via requests |

Die vollstaendigen Lizenz-Volltexte der Abhaengigkeiten liegen in den jeweiligen Paket-Distributionen
(`*.dist-info/`) der ausgelieferten Umgebung und werden beim Bundling mitgefuehrt.

---

## Build-Werkzeug (nicht Teil des ausgelieferten Werks)

| Paket | Lizenz | Rolle |
|---|---|---|
| pyinstaller | GPL-2.0 (mit Bundling-Ausnahme) | erzeugt das Bundle, wird nicht mitgeliefert |

---

## Entwicklungs-/CI-Werkzeuge (dev-group, nicht ausgeliefert)

Beeinflussen die Werk-Lizenz nicht:
`ruff` (MIT), `mypy` (MIT), `pytest` (MIT), `import-linter` (BSD), `pre-commit` (MIT),
`bandit` (Apache-2.0), `pip-audit` (Apache-2.0) samt transitiver dev-Deps
(`cachecontrol`, `cyclonedx-python-lib`, `msgpack`, `sortedcontainers`, `stevedore`,
`license-expression`, `py-serializable`, `pip-api`).

---

## Frontend (Node, Build-Zeit)

Das ausgelieferte Frontend ist statisch gebaut (Vite). Die Build-Abhaengigkeiten (npm) sind ganz
ueberwiegend MIT/ISC/BSD. Eine vollstaendige Frontend-Lizenzliste kann bei Bedarf via
`license-checker` erzeugt werden.
