# ADR 0007 — scanning-Infrastructure-Adapter dürfen `modules/` importieren (eng eingezäunt)

- **Status:** Akzeptiert
- **Datum:** 2026-05-28
- **Phase:** Phase 2, Schritt S.3 (scanning-Ports)
- **Bezug:** `vision_features_202605.md` Abschnitt 5.2 (die eine gekapselte Ausnahme: systemnahe Adapter); CLAUDE.md (Importregeln, „neue Ringe importieren NICHT den Altcode"); ADR 0003 (`ignore_imports`/Optionen am Contract als Präzedenz); `pyproject.toml` `[tool.importlinter]`

## Kontext

Der `import-linter`-Contract „neue Ringe importieren NICHT den Altcode (modules/)" verbietet allen fünf Ringen (`domain`, `ports`, `application`, `infrastructure`, `api`) den Import aus `modules/`. Das hält den Altcode strikt aus den sauberen Ringen heraus; der einzige Legacy-Bezug liegt im Composition Root (`app.py`, nicht analysiert).

Die scanning-Domäne ist die systemnächste des Bestands: Host-Discovery (ICMP/ARP), Portscan (socket/nmap), mDNS/SSDP, IPv6 (NDP/EUI-64) und FRITZ!Box (TR-064). Genau diese Schicht ist in `vision_features_202605.md` Abschnitt 5.2 als **die eine geplante, gekapselte Ausnahme** benannt: Sie soll hinter einem stabilen Port so liegen, dass sie **bei Bedarf in einer systemnäheren Sprache neu geschrieben werden kann, ohne den Rest anzufassen** — aber **nicht jetzt**, mitten im Rewrite.

Die scanning-Adapter (S.4) gegen den bestehenden, funktionierenden `modules/`-Code zu verdrahten statt ihn zeilenweise in `infrastructure/scanning/` zu reimplementieren, vermeidet **Wegwerf-Arbeit**: Eine sorgfältige Python-Reimplementierung der systemnahen Schicht würde — falls 5.2 eintritt — kurz darauf wieder verworfen. Das widerspricht der Strangler-Linie (kein temporärer Umbau, der absehbar zurückgebaut wird) und dem Snapshot-Grundsatz „erst Struktur, Sprachwechsel falls nötig lokal und später".

## Entscheidung

Die scanning-**Infrastructure-Adapter** dürfen `modules/` importieren — und **nur sie**. Die Ports (`backend/ports/scanning.py`) kennen weiterhin ausschließlich `domain/scanning` + stdlib; die Domänen- und Logik-Ringe (`domain`, `ports`, `application`, `api`) bleiben CI-hart von `modules/` getrennt.

Maschinisch umgesetzt **subtraktiv** über `ignore_imports` am bestehenden Contract, **nicht** als zweiter Contract:

```toml
[[tool.importlinter.contracts]]
name = "neue Ringe importieren NICHT den Altcode (modules/)"
type = "forbidden"
source_modules = ["domain", "ports", "application", "infrastructure", "api"]
forbidden_modules = ["modules"]
ignore_imports = [
    "infrastructure.scanning -> modules",
    "infrastructure.scanning.* -> modules.*",
]
unmatched_ignore_imports_alerting = "none"
```

**Warum subtraktiv und nicht additiv:** Ein `forbidden`-Contract kann nur *verbieten*, nie *erlauben*. Ein separater zweiter Contract könnte die Sperre des ersten also gar nicht aufheben — die Lockerung *muss* am bestehenden Contract hängen. `ignore_imports` schneidet ausschließlich die Kante `infrastructure.scanning(.*) -> modules(.*)` aus der Prüfung; `source_modules`/`forbidden_modules` bleiben unverändert. Jeder andere Ring und jeder andere infrastructure-Adapter bleibt vom **selben** Contract weiter gegen `modules/` geblockt.

`unmatched_ignore_imports_alerting = "none"`, weil die ignorierten Importe in S.3 (nur Ports) noch nicht im Graphen existieren — der scanning-Adapter kommt erst in S.4. Ohne diese Einstellung bräche `lint-imports` über die (noch) nicht gefundene `ignore`-Expression ab.

## Konsequenzen / Sicherheitsnachweis

Die Mechanik wurde mit zwei temporären Proben empirisch belegt (jeweils `PYTHONPATH=backend uv run lint-imports`, danach zurückgebaut):

1. **`modules`-Import außerhalb scanning** (Probe-Import in `infrastructure/_probe_outside.py`): **BROKEN.** Der Guardrail greift unverändert für alle nicht-scanning-Adapter.
2. **`modules`-Import in `infrastructure/scanning/`** (Probe-Import in `infrastructure/scanning/_probe_inside.py`): **KEPT.** Die Ausnahme greift genau dort, wo sie soll.

Vor und nach den Proben: **7 Contracts, 7 kept, 0 broken.** Die sechs übrigen Contracts (domain-Reinheit, Schichtung, Framework-Freiheit) sind von der Änderung unberührt.

**Positiv**
- Keine Wegwerf-Reimplementierung der systemnahen Schicht; die scanning-Adapter verdrahten sich gegen den erprobten `modules/`-Code hinter stabilen Ports.
- Die Ausnahme ist maschinell auf `infrastructure.scanning` begrenzt — sie kann nicht unbemerkt in andere Adapter oder Ringe lecken; jeder Versuch bricht CI (Probe 1).
- Logik-Ringe bleiben rein: `ports/scanning.py` importiert nur `domain/scanning`; `application`/`domain`/`api` sehen `modules/` nie.

**Kosten / Restfenster (temporär)**
- Die Ausnahme ist **bewusst temporär.** Sie fällt weg, sobald die systemnahe Schicht ersetzt ist (Sprachwechsel gemäß 5.2 *oder* eine native Reimplementierung nach Stabilisierung). Dann werden die beiden `ignore_imports`-Zeilen samt `unmatched_ignore_imports_alerting` gelöscht und der Contract steht wieder lückenlos für alle Ringe.
- Solange sie besteht, ist `infrastructure/scanning/` die einzige Stelle, an der Alt- und Neu-Code aneinanderstoßen. Das ist gewollt und genau die in 5.2 vorgesehene Kapselungsgrenze.
