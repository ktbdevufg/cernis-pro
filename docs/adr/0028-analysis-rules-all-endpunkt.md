# ADR 0028 — analysis: lesender Endpunkt `GET /api/analysis/rules/all` (alle aktiven Regeln mit Toggle-Status)

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reines Backend: EIN neuer lesender Endpunkt + Composition-Root-Runner. Keine neue Domäne, kein neuer Use-Case, kein neuer Port, keine Änderung an den Regeln selbst.
- **Bezug:** ADR 0023 (per-Settings deaktivierbare Regeln — `analysis_disabled_rules`, `_FilteredRuleProvider`, identisches defensives Settings-Lese-Muster); ADR 0027 (`_ConfiguredRuleProvider` — 5a-Injektion von Schwelle/Portlisten, Provider-Kette im Composition Root); ADR 0012/0022 (analysis-Domäne, `Rule` als Daten); CLAUDE.md (keine stillen Fallbacks, Finding S3; api → nur application).

## Kontext

Die Einstellungs-UI (Block „Regel-An/Aus") muss dem Nutzer genau die Regeln zum Ein-/Ausschalten anbieten, die die Engine tatsächlich auswertet: die eingebauten Built-in-Regeln (`host_remote_access_port`, `host_many_high_ports`, `host_backdoor_port`, `new_host_seen`, …) **und** die benutzer-eigenen Regeln.

Der bestehende Endpunkt `GET /api/analysis/rules` liefert über `ListUserRules` ausschließlich die **gespeicherten eigenen** Regeln — die Built-in-Defaults sind bewusst nicht Teil dieser Liste (sie ist die Quelle der Regel-Verwaltung, nicht der Toggle-UI). Diesen Endpunkt umzudeuten wäre falsch: er ist korrekt „nur eigene Regeln" und wird von der Regel-Verwaltung (POST/DELETE) genutzt.

Zwei zusätzliche Anforderungen an die Toggle-UI:

1. Sie braucht **auch die deaktivierten** Regeln, sonst könnte man eine einmal abgeschaltete Regel nicht wieder einschalten — sie wäre aus der Liste verschwunden.
2. Sie muss die Regeln **so sehen, wie die Engine sie auswertet**, also nach der 5a-Injektion (Schwelle/Portlisten aus ADR 0027), damit z. B. die in den Settings gesetzten auffälligen Ports sichtbar sind.

## Entscheidung

1. **NEUER, REIN LESENDER ENDPUNKT.** `GET /api/analysis/rules/all` liefert ALLE aktuell aktiven Regeln (Built-in + User), jede im bestehenden Wire-Format (`_rule_to_dict`) **plus** einem zusätzlichen Feld `disabled: bool`. Der bestehende `/api/analysis/rules` bleibt unverändert „nur eigene Regeln".

2. **QUELLE: `configured` VOR DEM FILTER.** Der Endpunkt zieht aus demselben Provider-Stack wie die Engine, aber bewusst nur bis `_ConfiguredRuleProvider` (NACH der 5a-Injektion), **vor** dem `_FilteredRuleProvider` — denn die UI muss die deaktivierten Regeln sehen, um sie wieder einschalten zu können. Provider-Kette der Engine: `Composite (Defaults + User) → Configured (Override) → Filtered (deaktivierte raus)`; dieser Endpunkt stoppt bei `Configured`.

3. **`disabled`-FLAG AUS DERSELBEN QUELLE WIE DER FILTER.** Das `disabled`-Flag pro Regel ergibt sich aus der Settings-Liste `analysis_disabled_rules`: `id` drin → `disabled: true`, sonst `false`. Die defensive Lese-Logik ist in eine freie Funktion `_read_disabled_rule_ids` (Composition Root) extrahiert, die **sowohl** der `_FilteredRuleProvider` **als auch** der neue Runner nutzen — so sehen Engine-Filter und UI-Liste garantiert dieselbe Menge (eine ehrliche Single Source).

4. **API-RING DOMAIN-FREI, RUNNER PER DEPENDENCY.** Der Runner (`ListAllRulesRunner`) kommt wie jeder andere als Composition-Root-verdrahtetes Callable per FastAPI-Dependency herein (Muster `provide_analyze`/`provide_list_user_rules`). Er liefert `(Rule, disabled)`-Paare (`Rule` als `Any`, kein domain-Import). Der api-Rand serialisiert über das vorhandene `_rule_to_dict` und ergänzt das Feld: `{**_rule_to_dict(rule), "disabled": flag}` — **kein** zweites Wire-Format.

5. **DEFENSIVES LESEN, S3-KONFORM.** Gleiche Linie wie ADR 0023/0027: fehlender Key / Nicht-Listen-Wert → leere disabled-Menge (kein Log, frische DB ist normal); kaputtes JSON (`CorruptSettingError`) → **geloggte Warnung** + leere disabled-Menge. Fail-safe-Richtung: im Zweifel zeigt die UI alles als aktiv — niemand wird heimlich abgeschaltet. Eine leere Lage (keine Regeln) ist gültig (`[]`), kein Fehler.

## Abgrenzung

Reines lesendes Backend. Der Schreibpfad (eine Regel an-/abschalten) läuft über die bestehenden Settings-Endpunkte (`analysis_disabled_rules` schreiben) — kein neuer Schreib-Endpunkt. Es wird nichts vorgebaut, was die UI nicht braucht.

## Konsequenzen

**Positiv**
- **Der Block „Regel-An/Aus" hat eine ehrliche Single Source:** der Endpunkt liefert exakt die Regeln, die die Engine auswertet (inkl. Built-ins, inkl. 5a-Injektion), mit ihrem Toggle-Status. Keine Frontend-Doppelquelle der Regel-Liste nötig.
- **Filter und UI sehen dieselbe disabled-Menge:** durch die gemeinsame freie Funktion `_read_disabled_rule_ids` kann die Anzeige nicht von der tatsächlichen Filterung abweichen.
- **Keine Domänen-/Engine-Kopplung:** der api-Ring bleibt domain-frei; die Quelle ist der bestehende Provider-Stack, nichts an Regeln/Engine ändert sich.
- **Bestehender `/rules`-Endpunkt unangetastet:** er bleibt „nur eigene Regeln" für die Regel-Verwaltung.
- **Fail-safe:** ein kaputtes `analysis_disabled_rules` führt zu „alles aktiv" mit geloggter Warnung, nie zu 500 (S3).

**Offen / später**
- **Schreib-/Toggle-UI** dockt über die bestehenden Settings-Endpunkte an — eigener Schnitt.
