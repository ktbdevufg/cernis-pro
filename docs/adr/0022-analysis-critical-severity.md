# ADR 0022 — analysis-Domäne: dritte Severity-Stufe `critical` (additiv eingeführt)

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine, additive Erweiterung der Domänen-Semantik der analysis-Domäne (`domain/analysis`); keine neue Domäne, kein neuer Use-Case, keine Verdrahtung im Composition Root, keine neue Regel.
- **Bezug:** ADR 0012 (analysis-Domäne — zwei neutrale Severity-Stufen `info`/`notable`, `Rule` als Daten, `Observation` wertneutral, Engine als reine Funktion); ADR 0021 (`kind`-Feld der Observation, Klassifikations- vs. Wertungs-Achse); ADR 0002 (domain bleibt framework-/URL-frei); CLAUDE.md (keine stillen Fallbacks).

## Kontext

ADR 0012 hat `Severity` bewusst auf **zwei neutrale Stufen** festgelegt — `info` (reine Einordnung) und `notable` („fällt auf") — als Ausdruck der roten Linie „zeigen + einordnen, nie urteilen". Diese zwei Stufen genügten für die Start-Regeln: alles war entweder eine bloße Einordnung oder etwas, das auffällt.

Die geplante Auffälligkeits-Engine braucht eine **dritte, stärkste Stufe**. Ihre Achse B (die visuelle „rot"/„kritisch"-Markierung) verlangt eine Severity, die über `notable` hinausgeht — eine Beobachtung, die nicht nur auffällt, sondern die **stärkste Auffälligkeit** des Spektrums darstellt. Mit nur zwei Stufen müsste die Engine `notable` doppelt belegen (einmal „fällt auf", einmal „rot/kritisch"), was die Severity-Achse mehrdeutig machte.

Wichtig: Es geht **nicht** um ein Werturteil. `critical` ist die stärkste Auffälligkeit, kein „gefährlich"/„unsicher" — die rote Linie aus ADR 0012 bleibt unangetastet. `critical` ordnet stärker ein, es urteilt nicht.

Die erste tatsächliche `critical`-Quelle (eine Backdoor-Port-Regel) ist ein **späterer Schnitt**. Dieses ADR führt die Stufe **rein additiv** ein: das Vokabular und die Sortier-Ordnung existieren, aber **keine** Built-in-Regel setzt `critical` aktuell.

## Entscheidung

1. **`Severity` wird um `"critical"` erweitert** (`domain/analysis/rules.py`): `Literal["info", "notable", "critical"]`. Reine Vokabular-Erweiterung der bestehenden `type`-Union (PEP 695), kein neuer Import — domain bleibt rein (stdlib + dataclasses + typing). Die Modul- und Alias-Kommentare nennen jetzt alle drei Stufen mit ihrer Bedeutung: `info` = reine Einordnung, `notable` = „fällt auf", `critical` = stärkste Stufe (bewertend, für die Auffälligkeits-Engine).

2. **Reihenfolge der Stärke: `critical > notable > info`.** Im Sortier-Rang der Engine (`_SEVERITY_RANK`, `domain/analysis/engine.py`) wird `critical` mit dem kleinsten Rang versehen (`{"critical": 0, "notable": 1, "info": 2}`) — kleinerer Rang sortiert zuerst, also `critical` an die Spitze. Der Sortierschlüssel selbst bleibt unverändert: `(severity-Rang, rule_id, subject)` aufsteigend. Determinismus unberührt.

3. **Additiv, ohne Quelle.** Keine Regel in `DEFAULT_RULES` setzt `critical`. Die Stufe wird eingeführt, damit die spätere Backdoor-Port-Regel (und die Auffälligkeits-Engine) sie nutzen kann, ohne die Domänen-Semantik im selben Schnitt aufzureißen. Eine zur Laufzeit übergebene Regel **darf** `critical` bereits setzen — die Engine sortiert sie korrekt an die Spitze (per Test belegt).

4. **Keine Werturteils-Verschiebung.** `critical` ist die stärkste Stufe der **Auffälligkeit**, kein moralisches Urteil („gefährlich"/„sicher"). Die rote Linie aus ADR 0012 bleibt: analysis zeigt + ordnet ein, urteilt nie. Genauso bleibt die Trennung aus der Validierung (`validation.py`) bestehen: `Severity` (info/notable/critical) bewertet eine BEOBACHTUNG, `IssueSeverity` (error/warning) bewertet die REGEL — die beiden Konzepte werden nicht vermischt.

## Konsequenzen

**Positiv**
- **Auffälligkeits-Engine bekommt ihre stärkste Stufe:** Achse B kann „rot/kritisch" auf eine eigene Severity abbilden, statt `notable` mehrdeutig zu überladen.
- **Rein additiv:** ein Literal-Wert, ein Rang-Eintrag, aktualisierte Kommentare. Bestehende Regeln, Tests und Konsumenten sind unberührt; kein Vertrag wird gebrochen (nur erweitert). Die bestehenden Sortier-Tests (notable vor info) bleiben grün.
- **domain bleibt rein:** `Severity` ist domänen-eigenes Vokabular, kein Framework-/URL-Bezug. Keine neue Domäne, kein neuer Use-Case, keine Verdrahtung.
- **Determinismus unverändert:** gleicher Sortierschlüssel, nur ein zusätzlicher Rang. Gleiche Eingabe → gleiche, gleich sortierte Ausgabe.

**Offen / später**
- **Erste `critical`-Quelle:** die Backdoor-Port-Regel als eigener Schnitt — bewusst NICHT Teil dieses ADR. Bis dahin ist `critical` Vokabular ohne Built-in-Setzer.
- **Auffälligkeits-Engine (Achse B):** die rot/„kritisch"-Markierung im Frontend nutzt diese Stufe, ist aber ein eigener, späterer Schnitt.
