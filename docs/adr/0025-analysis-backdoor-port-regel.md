# ADR 0025 — analysis-Domäne: Regel `host_backdoor_port` (erster echter `critical`-Setzer)

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine, additive Daten-Erweiterung der analysis-Domäne (`domain/analysis`): ein neuer `help_kind`, eine neue Built-in-Regel, ein neuer URL-Eintrag im Adapter. KEIN neuer `kind`, KEINE Engine-Änderung, keine bestehende Regel geändert, keine neue Domäne, kein Use-Case, keine Verdrahtung im Composition Root, kein UI, kein Endpunkt, keine Settings-Anbindung.
- **Bezug:** ADR 0012 (analysis-Domäne — `Rule` als Daten, `Observation` wertneutral, Engine als reine Funktion, Dispatch pro `kind`); ADR 0002 (domain bleibt framework-/URL-frei, stdlib + dataclasses + typing); ADR 0021 (`kind`-Feld der Observation); ADR 0022 (Severity-Stufe `critical` additiv eingeführt — OHNE Setzer); ADR 0024 (host-Port-Count-Regel, jüngste host-Regel); CLAUDE.md (keine stillen Fallbacks).

## Kontext

Das Konzept (§5) nennt eine kuratierte Liste klassischer Backdoor-/Trojaner-Ports als auffälliges Signal: ein Host, der einen historisch bekannten Trojaner-Port offen hält, fällt deutlich auf. Diese Liste soll als **kritisch** eingestuft werden — die stärkste Auffälligkeitsstufe der Engine.

ADR 0022 hat die dritte Severity-Stufe `critical` **additiv eingeführt**, aber bewusst OHNE Setzer: keine Built-in-Regel hat sie bisher gesetzt, sie war nur in der Union und im Sortier-Rang vorhanden. Diese Backdoor-Liste ist der **erste echte `critical`-Setzer**.

Wichtig — **kein neuer `kind` nötig.** Die bestehende `kind="host_remote_port"`-Auswertung (`_eval_host_remote_port`) zählt bereits exakt das Richtige: „Host hält einen Port aus einer Portmenge offen". Die Backdoor-Regel unterscheidet sich von der vorhandenen `host_remote_access_port`-Regel nur in **Daten** — andere Portmenge, andere Severity, anderer `help_kind`. Damit ist sie ein weiterer `Rule`-Eintrag in `DEFAULT_RULES`, kein neuer Dispatch-Zweig im Domänen-Kern (Abgrenzung zu ADR 0024, wo ein echtes Zählen gegen eine Schwelle einen neuen `kind` rechtfertigte).

## Entscheidung

1. **Neue Default-Regel `host_backdoor_port`** in `DEFAULT_RULES` (`domain/analysis/rules.py`): `severity="critical"`, `kind="host_remote_port"` (bestehend, wiederverwendet), eigener `help_kind="backdoor_port"`, kuratierte `ports`-Menge. Thematisch direkt hinter `host_remote_access_port` (b2) und `host_many_high_ports` (b2b) gruppiert — alle drei werten ein GERÄT anhand seiner offenen Ports aus (Stand letzter Scan).

2. **Neuer `help_kind="backdoor_port"`** (`HelpKind`-Union erweitert): ein Backdoor-Port ist ein eigenes Hilfe-Thema, kein Fernzugriff — daher ein eigener Schlüssel statt einer Mitnutzung von `remote_access_port`.

3. **Kuratierte Portmenge** klassischer Trojaner-Ports: Back Orifice (31337, 31338), NetBus / NetBus Pro (12345, 12346, 20034), SubSeven (1243, 6711, 6712, 6713, 27374, 54283), Deep Throat (6670, 6771), Trinoo / DDoS-Klassiker (27444, 27665, 31335) sowie weitere Klassiker (1337, 30303, 32768, 65000).

4. **Engine unverändert.** Die Engine iteriert pro Regel; zwei `host_remote_port`-Regeln mit verschiedenen Portmengen und Severitys koexistieren problemlos. Ein Host, der z. B. 22 UND 31337 offen hält, erhält ZWEI unabhängige Befunde (notable Fernzugriff + critical Backdoor); die globale Sortierung (`_SEVERITY_RANK`) stellt die critical-Beobachtung nach vorn (**Zwei-Achsen-Gedanke** des Konzepts).

5. **Bündelung pro Host** (geerbt von `_eval_host_remote_port`): pro Host genau EINE Beobachtung — eine rote Markierung je Gerät, nicht eine je getroffenem Port. Die getroffenen Ports werden aufsteigend sortiert, kommagetrennt in den `{value}`-Platzhalter gebündelt.

6. **Neuer URL-Eintrag** `"backdoor_port" -> "https://de.wikipedia.org/wiki/Backdoor"` im `_HELP_URLS`-Dict des `StaticHelpLinkResolver` (`infrastructure/analysis.py`): eine real existierende, thematisch passende Wikipedia-Seite, im Stil der übrigen Einträge (de.wikipedia, keine projekteigene Domain).

## Ehrlichkeit (rote Linie)

Die Liste ist eine **kuratierte Klassiker-Sammlung historischer Trojaner-Ports** und wird ausdrücklich ehrlich eingeordnet (Konzept §5): sie ist nostalgisch/historisch nützlich, fängt **moderne Malware aber kaum** — die nutzt 443/DNS/dynamische Ports. Sie erzeugt **kein falsches Sicherheitsgefühl**: ein Treffer ist ein klares Signal, aber KEIN vollständiger Malware-Scan. Der `detail_template`-Text und der Hilfe-Link halten das ehrlich.

`"critical"` meint hier **stärkste Auffälligkeit** (ein bekannter Backdoor-Port ist ein klares Signal), NICHT ein moralisches Urteil („gefährlich"/„sicher"). Die rote Linie aus ADR 0012/0022 bleibt unangetastet: analysis ordnet ein, es urteilt nicht.

## Konsequenzen

**Positiv**
- **Rein additiv:** eine neue Regel, ein neuer `help_kind`, eine neue URL. KEINE Engine-Änderung; bestehende Regeln, Evals und Tests bleiben unberührt; kein Vertrag wird gebrochen, nur erweitert.
- **Erster echter `critical`-Setzer:** die in ADR 0022 eingeführte Stufe erhält ihre erste Built-in-Quelle; die Zwei-Achsen-Koexistenz mit der notable-Fernzugriffsregel ist ausdrücklich gewollt und durch einen Test abgesichert.
- **mypy-strict erzwingt Vollständigkeit:** der neue `help_kind` muss im URL-Dict aufgelöst werden (Adapter-Test prüft die Abdeckung) — kein stiller Fallback.
- **domain bleibt rein:** reine Daten-Erweiterung (stdlib + dataclasses + typing), kein I/O, deterministisch.

**Offen / später**
- **Konfigurierbare/erweiterbare Liste:** eine per Settings + UI pflegbare und uploadbare Backdoor-Liste ist ein eigener, späterer Schnitt. Hier steht nur die fixe, kuratierte Default-Liste.
