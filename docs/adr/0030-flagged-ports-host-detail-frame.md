# ADR 0030 — host_detail-Frame: flagged_ports (getroffene Ports je Severity-Stufe, Achse B) als zweites Feld

- **Status:** Akzeptiert
- **Datum:** 2026-06-17
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Erweitert die WS-getriebene Scan-Tabelle (`host_detail`-Frame) um ein zweites Achse-B-Signal, verdrahtet ausschließlich im Composition Root (`app.py` + `ws_scan.py`).
- **Bezug:** ADR 0029 (host_detail-`analysis_severity` — Achse B, Host-Maximum; identisches best-effort-/Default-/Loop-/Single-Source-Muster, baut direkt darauf auf: `_observed_host`/`_severity_for_host`/`_build_filtered_provider` existieren); ADR 0025 (`host_backdoor_port`, critical) + ADR 0027 (`host_remote_access_port`, notable — die beiden portbasierten Default-Regeln, beide `kind="host_remote_port"` mit `ports: frozenset[int]`); ADR 0024 (`host_port_count`, anzahlbasiert — trägt bewusst NICHT bei); ADR 0023/0027/0028 (Provider-Stack Composite→Configured→Filtered).

## Kontext

Das `host_detail`-Frame trägt seit ADR 0029 `analysis_severity` — das **Host-Maximum** der Achse B (`"critical"` | `"notable"` | `null`): die höchste Auffälligkeits-Bewertung des Hosts gegen die konfigurierten Regeln. Das ist ein **einzelner** Wert pro Host und reicht, um den Host als Ganzes (die Host-Pille) einzufärben.

Was fehlt, ist die **Granularität auf Portebene**: Das Frontend (Schnitt 6b, Variante C) soll die **konkret betroffenen** offenen Port-Böppel einfärben (orange = notable, rot = critical) — und dafür muss es wissen, *welche* Ports die Auffälligkeit ausgelöst haben. `analysis_severity` trägt nur das Maximum, nicht die schuldige Portmenge.

> **Zweites Achse-B-Feld:** `flagged_ports = {"critical": [...], "notable": [...]}` — die konkret getroffenen offenen Ports pro Severity-Stufe (sortierte Integer-Listen, leere Stufe = `[]`).

Beide Felder sind Achse B (Urteil über den aktuellen Portstand), ergänzen einander, ersetzen einander nicht: `analysis_severity` = „wie schlimm ist dieser Host?", `flagged_ports` = „welche Ports sind schuld?".

**Portbasiert ist nicht jede Achse-B-Regel.** Nur `kind == "host_remote_port"`-Regeln tragen eine konkrete `ports`-Menge — bei ihnen gibt es einen „schuldigen" Port. Die Default-Regeln dieser Art sind `host_remote_access_port` (notable, auffällig-Liste) und `host_backdoor_port` (critical, Backdoor-Liste). `host_port_count` (anzahlbasiert) und `host_new` (kein Port) färben **keinen** einzelnen Port — sie bleiben Teil von `analysis_severity` (die Pille kann auffällig sein, OHNE dass ein Port markiert ist; Grund z. B. „zu viele Ports"), tragen aber **nicht** zu `flagged_ports` bei. Das ist gewollt, kein zu reparierender Defekt.

## Entscheidung

1. **MENGENSCHNITT, KEIN STRING-PARSEN.** Die getroffene Portmenge ist `host.open_ports & rule.ports` — der Schnitt der offenen Host-Ports mit der `ports`-Menge der Regel. Das `value`-Feld der Observation (ein Komma-String) wird **NICHT** geparst: die Format-Kopplung an den `detail_template`-String wäre fragil. `open` wird mit **demselben** Ausdruck wie `_observed_host` gebildet (`{p.port for p in host.ports if p.state == "open"}`) — keine zweite Definition von „offen".

2. **FREIE FUNKTION `_flagged_ports_for_host(host, provider) -> dict[str, list[int]]`** (in `app.py`). Iteriert über `provider.get_rules()`, nimmt nur `kind == "host_remote_port"`-Regeln, sammelt pro `rule.severity` (`"critical"`/`"notable"`) die Union der Schnitte (mehrere Regeln gleicher Stufe → Vereinigung) und liefert je Stufe eine **sortierte** Liste. Hosts ohne `ip` → leere Form (kein bewertbares Subjekt, gleiche Linie wie `_severity_for_host`). Die leere Default-Form (`{"critical": [], "notable": []}`) stammt aus `_empty_flagged_ports` — EINE Quelle der Achse-B-Stufenmenge (`_FLAGGED_SEVERITIES`).

3. **SINGLE SOURCE: EIN PROVIDER, EINE PROJEKTION, EIN AUFRUF FÜR BEIDE ACHSE-B-FELDER.** `_flagged_ports_for_host` nutzt **denselben gefilterten Provider** wie `_severity_for_host` über die Engine sieht (`_build_filtered_provider`, ADR 0029). Es wird **kein zweiter Provider** gebaut. Die WS-Verdrahtung `_build_axis_b` (ersetzt das 0029-`_build_severity`) baut pro Verbindung **einmal** einen gefilterten Provider + **eine** `AnalyzeSnapshot`-Instanz und schließt sie in **ein kombiniertes Callable** `(EnrichedHost, bool) -> (Severity | None, dict[str, list[int]])`: die Severity aus dem Engine-Lauf, die `flagged_ports` aus dem Mengenschnitt über genau diesen Provider. So können die beiden Achse-B-Felder nicht auseinanderlaufen.

4. **KONSISTENZ-INVARIANTE.** Weil beide Felder aus demselben Provider + derselben „offen"-Projektion kommen, gilt:
   - `flagged_ports["critical"]` nicht leer ⇒ `analysis_severity == "critical"`.
   - `flagged_ports["notable"]` nicht leer und `critical` leer ⇒ `analysis_severity ∈ {"notable", "critical"}`.

   Die Invariante ist im Test festgenagelt (`test_axis_b_consistency_critical_port_implies_critical_severity`).

5. **EIN BEST-EFFORT-WRAPPER FÜR BEIDE FELDER.** Das 0029-`_severity_safe` wird zu `_axis_b_safe(axis_b, host, is_known) -> (str | None, dict)` umgebaut: **ein** `try/except`, **ein** Callable-Aufruf, beide Felder zusammen. Wirft das Callable, wird der Fehler gefangen, als Warnung geloggt (`host_analysis_axis_b_failed`) und `(None, {"critical": [], "notable": []})` zurückgegeben — „im Zweifel keine Auffälligkeit, keine geflaggten Ports". Im WS-Loop: `frame["analysis_severity"], frame["flagged_ports"] = _axis_b_safe(...)` — `analysis_severity` wird **nicht** doppelt berechnet.

6. **UNABHÄNGIG VON KURATIERUNG.** `flagged_ports` wird — wie `analysis_severity` — **außerhalb** des `if kuratiert is not None:`-Blocks gesetzt. Achse B braucht keine Kuratierung; ein brandneuer Host kann auffällige Ports haben. Disjunkt von `new_ports`/`is_changed` (Achse A, an einem devices-Vorzustand hängend).

7. **DEFAULT im Frame-Schema = leere Form.** `_host_detail_frame` setzt `flagged_ports: {"critical": [], "notable": []}` zu den Default-Keys (jetzt **27 Keys** statt 26). So ist das Feld **immer** im Frame, auch wenn die Anreicherung übersprungen wird. `_host_detail_frame` bleibt reine Projektion ohne I/O.

## Konsequenzen

- Das `host_detail`-Frame trägt **+1 Feld** (`flagged_ports`, 26 → 27 Keys). Das Frontend kann die Host-Pille (`analysis_severity`) UND die einzelnen Port-Böppel (`flagged_ports`) unabhängig einfärben.
- **Ein Engine-/Provider-Lauf liefert beide Achse-B-Felder** (kombiniertes Callable). `make_ws_scan` behält seine sechste Factory — der Typ wird von `SeverityFactory` zu `AxisBFactory` (kombiniertes Paar-Callable); alle Aufrufer (`app.py` + Tests) sind angepasst.
- Die Konsistenz-Invariante zwischen `analysis_severity` und `flagged_ports` ist strukturell garantiert (gemeinsamer Provider/Projektion) und testabgesichert.
- `_flagged_ports_for_host`/`_empty_flagged_ports` sind direkt unit-testbar (freie Funktionen, kein WS-/DB-Setup nötig).

## Nicht Teil dieser Entscheidung

- **`host_port_count`/`host_new` tragen bewusst NICHT zu `flagged_ports` bei** — sie färben keinen einzelnen Port. Kein Versuch, anzahl-/neu-basierte Auffälligkeit auf eine Portmenge abzubilden.
- **Kein String-Parsen** des Observation-`detail`/`value`-Felds — nur Mengenschnitt.
- **Achse A (`new_ports`, `is_changed`, `is_known`) bleibt unberührt.**
- **Kein Acknowledge / keine flagged_ports-Historie** — `flagged_ports` ist ein flüchtiges Frame-Faktum des aktuellen Scans (der Folgescan bewertet neu).
- **Keine zweite Provider-/Projektions-Kopie** — die 0029-Single-Source (`_build_filtered_provider`, `_observed_host`-„offen"-Ausdruck) wird wiederverwendet.
