# ADR 0023 — analysis: Regel-Aktivierung per Settings-Filter (`analysis_disabled_rules`)

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine, additive Verdrahtung im Composition Root (`app.py`); keine neue Domäne, kein neuer Use-Case, kein neuer Port, kein neuer Endpunkt, keine Änderung an den Regeln selbst.
- **Bezug:** ADR 0012 (analysis-Domäne — `Rule` als Daten, `Observation` wertneutral, Engine als reine Funktion); Konzept Auffälligkeits-Engine, Achse B / §3.4 (Regeln abschaltbar); Muster `_load_custom_targets` (`application/monitoring/use_cases.py` — defensives Lesen einer Settings-Liste); CLAUDE.md (keine stillen Fallbacks, Finding S3).

## Kontext

Die Auffälligkeits-Engine soll dem Nutzer erlauben, einzelne Regeln **abzuschalten** — sowohl die eingebauten `DEFAULT_RULES` als auch die benutzer-eigenen, gespeicherten Regeln (Konzept Auffälligkeits-Engine, Achse B / §3.4). Eine deaktivierte Regel erzeugt schlicht keine Beobachtungen mehr.

`Rule` (`domain/analysis/rules.py`) ist bewusst ein reines Datenobjekt **ohne** `enabled`-Flag: eine Regel ist Konfiguration-als-Daten, und ihre Aktivierung ist eine Nutzer-Einstellung, kein Attribut der Regel selbst. Ein `enabled`-Feld an `Rule` würde zwei Konzepte vermischen (die deklarative Bedingung der Regel und der persistente Nutzer-Wunsch, sie zu sehen) und müsste für jede Built-in-Regel im Code gepflegt werden — also Code-Änderung statt reiner Konfiguration.

Gebraucht wird daher ein Mechanismus, der Regeln **ohne Code-Änderung an den Regeln** abschaltet: die Liste der deaktivierten Regeln ist reine Konfiguration (Daten), die eingebauten Regeln im Code bleiben unangetastet.

## Entscheidung

1. **Deaktivierungs-Liste als Settings-Key.** Die Menge der abgeschalteten Regeln liegt als generischer Settings-Wert unter dem Key `analysis_disabled_rules` — ein JSON-Array von `rule_id`-Strings. Sie wird über den vorhandenen `SettingsRepository`-Port gelesen. Kein eigener Port, keine eigene Tabelle: die Aktivierung ist eine gewöhnliche Einstellung wie jede andere.

2. **Filter-Wrapper im Composition Root.** Ein kleiner Wrapper-Provider `_FilteredRuleProvider` (`app.py`) umschließt den `_CompositeRuleProvider` und sitzt damit **vor** ihm im Lesepfad: `rule_provider = _FilteredRuleProvider(composite, repository())`. Er erfüllt selbst strukturell den `ports.analysis.RuleProvider` (`get_rules() -> tuple[Rule, ...]`) — wie der Composite ein reiner Verdrahtungs-Wrapper. `get_rules` liest die deaktivierten IDs aus den Settings und gibt nur die Regeln des inneren Providers zurück, deren `id` nicht in der Menge liegt. Reihenfolge der durchgelassenen Regeln bleibt unverändert.

3. **Built-in-Regeln unangetastet.** `DEFAULT_RULES` und die User-Regeln im Code ändern sich nicht. Konfiguration = reine Daten: der Filter wirkt erst beim Verdrahten, die Domäne bleibt rein und ohne Aktivierungs-Begriff.

4. **Kein eigener Endpunkt, kein UI in diesem Schnitt.** Das spätere *Schreiben* der Liste trägt der generische Settings-Endpunkt (die Einstellung wird wie jede andere gesetzt). Eine Einstellungs-UI ist ein eigener, späterer Schnitt. Dieser Schnitt liefert nur den Lese-/Filterpfad.

5. **Defensiver Leer-Zustand.** Fehlender Key (frische DB ist normal) **oder** Nicht-Listen-Wert (z. B. ein Dict oder Int) → `frozenset()`, also „nichts deaktiviert, alle Regeln an". Eine gemischte Liste filtert nur die String-Einträge als `rule_id`; Nicht-String-Einträge werden übersprungen, nicht zum Absturz gebracht.

6. **Fail-safe bei kaputtem JSON.** Ein nicht dekodierbarer Roh-Wert in der DB lässt `SettingsRepository.get()` einen `CorruptSettingError` werfen (kein stiller Roh-Fallback, das ist die S3-Heilung des Adapters). `_FilteredRuleProvider` fängt diesen Fehler, **loggt eine Warnung** (`analysis_disabled_rules_corrupt`) und fällt fail-safe auf „alle Regeln an" zurück — **kein Scan-Abbruch**. Begründung: der Filter ist ein Nebenpfad in der Analyse; eine kaputte Komfort-Einstellung darf nicht den ganzen Scan fällen. Die fail-safe-Richtung ist bewusst „mehr zeigen, nichts heimlich unterdrücken" — eine defekte Deaktivierungs-Liste blendet niemals still Beobachtungen aus. S3-konform, weil der Fehler **benannt und geloggt** wird, nicht still verschluckt. Das defensive Lesemuster folgt `_load_custom_targets` (`application/monitoring/use_cases.py`), erweitert um den Fang von `CorruptSettingError`.

## Konsequenzen

**Positiv**
- **Additiv, kein Vertragsbruch.** Ein Wrapper im Composition Root, ein Settings-Key. Bestehende Regeln, die Engine, der `RuleProvider`-Port und alle Konsumenten sind unberührt. Default (kein Key) = alle Regeln aktiv — das bisherige Verhalten bleibt exakt erhalten.
- **Regeln bleiben reine Daten.** Kein `enabled`-Flag an `Rule`, keine Code-Änderung zum Abschalten. Die Aktivierung ist Konfiguration, sauberer Schnitt zwischen Regel (Daten) und Nutzer-Wunsch (Settings).
- **Port unverändert.** `_FilteredRuleProvider` erfüllt `ports.analysis.RuleProvider` strukturell (gleiche Signatur wie der Composite). Kein neuer Port, kein neuer Adapter, keine neue Tabelle.
- **Robust.** Fehlender Key, Nicht-Liste, gemischte Typen und kaputtes JSON führen alle zu einem definierten, sicheren Verhalten — fail-safe „alle Regeln an", im Fehlerfall geloggt.

**Offen / später**
- **Schreiben der Liste:** läuft über die generischen Settings-Endpunkte — eigener, späterer Schnitt (kein eigener analysis-Endpunkt).
- **Einstellungs-UI:** die Oberfläche zum An-/Abwählen einzelner Regeln ist ein eigener, späterer Schnitt; dieses ADR liefert nur den Lese-/Filterpfad.
