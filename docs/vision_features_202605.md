# CERNIS PRO — Produktvision, Qualitätsanspruch & Feature-Brainstorming 2026-05

**Stand:** 2026-05-27
**Projekt:** CERNIS PRO (LAN-Scanner Desktop-App → lokales Netzwerk- & System-Troubleshooting-Werkzeug)
**Repository:** `ktbdevufg/cernis-pro` (Branch `dev`)
**Bezug:** Ergänzt `pre_release_202605.md`. Dieses Dokument hält Produktvision, Qualitätsanspruch und Feature-Brainstorming fest. Es ist **Input für Phase 0** (Ist-Analyse) des Rewrites, kein Feinkonzept.
**Status:** Lebend. Brainstorming-Runde abgeschlossen, Features noch nicht final geschnitten.

---

## 0. Übergeordneter Anspruch: Best-Effort-Best-Practice-Vorzeigeprojekt

CERNIS PRO soll **nicht nur funktionieren**, sondern ein **Vorzeigeprojekt** sein — in Code-Qualität, Architektur und Dokumentation auf einem Niveau, vor dem auch erfahrene Principal-Entwickler den Hut ziehen.

Das ist die Messlatte, an der jede Entscheidung in diesem und im Planungsdokument zu messen ist. Es ist kein Schmuck-Satz, sondern ein operativer Maßstab:

- **Code-Qualität:** klare Schichtung, maschinell erzwungene Architekturregeln, durchgängige Typisierung, keine toten Pfade, keine stillen Fallbacks.
- **Testbarkeit:** Tests sind Voraussetzung, nicht Beiwerk. Keine Änderung ohne grünen CI-Lauf.
- **Dokumentation:** entsteht **parallel** mit dem Code (ADRs, Docstrings, `docs/`-Struktur), nicht nachträglich. Am Ende jeder Phase ist Doku fertig, nicht "noch zu tun".
- **Nachvollziehbarkeit:** jede größere Entscheidung wird als Architecture Decision Record (ADR) festgehalten — ein Principal kann den Weg rekonstruieren, nicht nur das Ergebnis sehen.

Dieser Anspruch ist der direkte Gegenentwurf zu den Mängeln, die der externe Principal-Review aufgedeckt hat (siehe Abschnitt 1). Der Rewrite ist die Gelegenheit, aus einem funktionierenden, aber strukturell mangelhaften v1.0.0 ein vorbildliches v2.0.0 zu machen.

---

## 1. Principal-Review: Findings und wie die Architektur sie adressiert

Der externe Review eines Principal Master Developers hat gravierende Mängel in zwei Dimensionen aufgezeigt: **Code-Qualität/Architektur** und **Sicherheit**. Die Entscheidung lautet: **kein Patchen, sondern strukturierter Backend-Rewrite.** Dieser Abschnitt führt jedes Finding auf und hält fest, *wie* der Rewrite es vollumfänglich adressiert — denn genau daran misst sich der Vorzeige-Anspruch.

### 1.1 Architektur- und Qualitätsmängel

| # | Finding | Befund | Adressierung im Rewrite |
|---|---|---|---|
| A1 | Monolithische `main.py` | 2009 Zeilen — "würde einem menschlichen Entwickler um die Ohren gehauen" | Hexagonale Schichtung (api/application/domain/infrastructure); `main.py`/`app.py` macht nur noch Bootstrap. Maschinell per `import-linter` erzwungen. |
| A2 | SQLite-Zugriffe verstreut | Mehrere Module greifen direkt auf SQLite zu, kein zentrales Persistence-Layer | Persistence wird **ein** Adapter hinter einem Repository-Port. Kein Domänen- oder Application-Code kennt SQLite direkt. |
| A3 | State über Modulebenen verteilt | Modul-globaler State, unklare Lebenszyklen, schwer testbar | State wird explizit über Dependency Injection im Composition Root (`app.py`) verdrahtet. Keine Modul-Globals. Lebenszyklen sichtbar. |
| A4 | Keinerlei Test-Code | Kein einziger Unit-, Integration-, Smoke- oder E2E-Test | Tests als **Voraussetzung**: Characterization Tests vor jeder Migration; danach Unit/Integration pro Use-Case. CI-Gate: keine Änderung ohne grünen Lauf. |
| A5 | Mac-App startet nicht | Vermutung: nicht für Apple Silicon kompiliert oder Quarantine-Issue | In Phase 0 Build-Logs prüfen; Ursache (Code vs. Build/Signierung) trennen. macOS-Auslieferung später mit Signierung/Notarisierung (Apple-Developer-Mitgliedschaft vorhanden, siehe 6.3). |
| A6 | Agent-feindlich | Bei wachsendem Code verhaspeln sich Coding-Agents im überfüllten Kontext → Spaghetti, Bugs | Ports = explizite Verträge, an denen ein Agent arbeitet, ohne die Implementierung zu kennen. Kleine Module erzwungen → pro Session ein Use-Case. **Agent-friendly by design.** |

**Wichtig zu A6:** Hexagonal ist hier nicht nur "saubere Architektur" — es ist *agent-friendly architecture*. Das ist Teil des Vorzeige-Anspruchs: Der Code muss nicht nur für Menschen, sondern auch für Coding-Agents navigierbar sein, weil genau die ihn weiterentwickeln.

### 1.2 Sicherheitsmängel (Security-Review Teil 1)

| # | Severity | Bereich | Befund | Adressierung im Rewrite |
|---|---|---|---|---|
| S1 | **Critical** | API/Auth | `CORSMiddleware allow_origins=["*"]` global, **keine Auth** auf sensiblen Endpunkten (Pip-Install, Capture, Agent-Mgmt, Settings, WebSockets). Jede Webseite kann das Backend ansprechen. | Auth als zentraler Adapter/Middleware; CORS restriktiv; sensible Endpunkte hinter Auth. Löst sich durch zentrale Struktur fast von selbst. |
| S2 | **High** | macOS-Notifications | AppleScript-Injection via `osascript` über Alert-Namen/Monitor-Labels (`alerting.py:143`, `monitor.py:185`, `main.py:1044`, `main.py:385`) | Notifications werden ein Port mit sicherem macOS-Adapter (keine String-Interpolation in `osascript`; parametrisiert/escaped). |
| S3 | **High** | Settings/Secrets | `GET /api/settings` liefert Klartext-Secrets (Shodan API Key); Crypto-Helper fällt still auf Base64/Plaintext zurück (`crypto.py:41`, `:65`) | Secret-Management als eigener Port mit OS-Keystore-Adapter. **Keine stillen Fallbacks** — Fehlschlag ist Fehler, nicht Plaintext. Secrets nie im API-Response. |
| S4 | Medium | Remote-Agent | Default `0.0.0.0` + Shared-Secret `changeme` + permissives CORS (`agent.py:258–261`, `:187`) | Agent als eigener Adapter mit sicheren Defaults (localhost, kein Default-Secret, restriktives CORS). Erhöhte Rechte lokalisiert und sichtbar. |
| S5 | Medium | Pcap-Anleitung | Empfiehlt `/dev/bpf*` world-accessible (macOS) und `cap_net_raw` auf gesamte Backend-Binary (Linux) — schwächt Host-Sicherheit | Rechte-Modell minimal-invasiv: gezielte Capabilities statt pauschaler Binary-Rechte; Doku empfiehlt keine host-schwächenden Maßnahmen. Knüpft an das Rechte-Modell des Traffic-Features an (3.2). |

> **Hinweis:** Es existieren weitere Security-Findings (Teile 2+), die im **Audit der Phase 4** systematisch gegen den dann stabilen Code erhoben werden. S1–S5 sind die bisher genannten. Der Vorzeige-Anspruch verlangt, dass das Audit gegen *stabilen* Code läuft, nicht gegen ein bewegliches Ziel.

### 1.3 Verbindlichkeit

Diese Findings sind **nicht** optionale Verbesserungen, sondern der Existenzgrund des Rewrites. Jedes neue Feature (Abschnitt 3) und jede Architekturentscheidung (Abschnitt 4, 5) wird zusätzlich daran gemessen, ob sie ein Finding adressiert oder zumindest nicht verschärft. Insbesondere das neue Traffic-/Prozess-Feature berührt direkt S4 und S5 (erhöhte Rechte) — daher das bewusst restriktive Rechte-Modell in 3.2.

---

## 2. Produkt-These (Positionierung)

CERNIS PRO soll ein **ernstzunehmendes, aber bewusst gut bedienbares Werkzeug für den mündigen Einzelnen** sein — den technisch interessierten Anwender ("Tekkie"), der zwischen zwei Welten nichts Passendes findet:

- **Oben:** überdimensionierte Enterprise-/Monitoring-Suiten — vierstellige Kosten, für ein Heimnetz oder einen Einzelnen absurd, setzen quasi eine IT-Abteilung voraus.
- **Unten:** seichte App-Store-Tools — machen eine Sache hübsch, geben aber keine Tiefe, keine Verknüpfung, keine Mündigkeit.

**Die Lücke dazwischen ist das Ziel.** Nicht "so tief wie Enterprise", sondern "so *ernstzunehmend* wie Enterprise, aber bedienbar wie etwas Gutes".

### Leitsatz

> Nicht maximale Tiefe, sondern die **richtige** Tiefe — zugänglich gemacht.

### Prüffrage für jede Feature-Entscheidung

1. **Gibt das dem Anwender mehr Mündigkeit — oder nur mehr Oberfläche?**
   (Per-App-Traffic = Mündigkeit. eBPF-Mikrosekunden-Timing = Oberfläche/Ballast.)
2. **Bleibt der Wartungsaufwand für einen Solo-Entwickler tragbar?**
   ("Enterprise-like" darf niemals "Enterprise-Wartungsaufwand" heißen.)

Bewährt im Brainstorming: "Grob reicht" bei der Traffic-Rate (Mündigkeit ohne Ballast); "kein Virenscanner" und "Links statt eigener Bedrohungsdatenbank" (Wartungslast vermieden).

---

## 3. Designprinzip für die Oberfläche

Die gesamte Tool-Kategorie (Netzwerk-/System-Tools) sieht gleich aus: dichte Tabellen, Monospace, alles gleichzeitig sichtbar, der Mensch sucht die Nadel im Heuhaufen selbst. Das soll bewusst aufgebrochen werden.

1. **Nicht alles zeigen, sondern das Auffällige zeigen.** Die Oberfläche ist ruhig, wenn alles ruhig ist, und führt, wenn etwas los ist. Das Normale tritt zurück, das Auffällige tritt hervor. Direkte UI-Konsequenz aus "zeigen und einordnen" (Abschnitt 3.4 unten / Feature).
2. **Räumlich statt tabellarisch — mit Vorsicht.** Netzwerk ist von Natur aus eine Karte. **Warnung:** Netzwerk-Graphen sind berüchtigtes Blendwerk — bei vielen Knoten unlesbares Fadenknäuel. Nur einsetzen, wenn die Darstellung eine konkrete **Frage beantwortet**, nicht dekoriert.
3. **Vom Überblick ins Detail führen (Schichtung statt Weglassen).** Ruhige Einstiegsebene, Hineinzoomen auf Wunsch. Bedient Gelegenheitsnutzer und tiefgrabenden Tekkie in *einer* Anwendung.
4. **Sprache statt Symbole.** "Dropbox lädt gerade hoch, etwa 5 MB/s" statt RX/TX-Spalte. Benannte Dinge statt nackter Port-Nummern. Die Zahl bleibt einen Klick entfernt.

---

## 4. Feature-Bündel (Brainstorming-Ergebnis)

### 4.1 Grundausrichtung: Lokales Troubleshooting, kein Virenscanner

CERNIS PRO erweitert sich um eine **lokale Sichtbarkeits- und Troubleshooting-Schicht** für das System, auf dem es läuft. Bewusste Abgrenzung:

- **Kein** Virenscanner, **keine** Konkurrenz zu Sicherheits-Suiten.
- **Kein** Signatur-/Update-Backend (untragbare Wartungslast für Solo-Entwickler).
- **Stattdessen:** das Werkzeug für den "irgendwas-stimmt-nicht"-Moment — etwas **eingrenzen** (nicht abwehren).

### 4.2 Per-App-Netzwerkmonitoring — Tiefe: Stufe 1 + 2 (entschieden)

- **Stufe 1 — Verbindungen (User-Betrieb, rootless):** Welche App hat welche Verbindung offen — Ziel-IP, Port, Status. Quelle Linux: `/proc/net` / `sock_diag`-Netlink. Ohne Root nur **eigene** Prozesse.
- **Stufe 2 — Durchsatz (Root für alle Apps):** Grobe Rate rein/raus aus Sekunden-Polling der Socket-Byte-Zähler. **Kumulative Summen exakt**, nur Momentanrate "grob". Methode wie `nethogs`.
- **Stufe 3 — Live exakt (eBPF, ZURÜCKGESTELLT):** Kernel-Versionsabhängig (vgl. historische glib2-/Toolchain-Schmerzen), eigenes Projekt. Bei Bedarf später **zweiter Adapter hinter demselben Port** — kein Umbau.

**Brauchbarkeit "grob" (geklärt):** Für "welche App belastet die Leitung / wohin spricht sie" ausreichend. Schwäche nur bei kurzen Bursts und am Verbindungsende. Nachschärfbar ohne eBPF via Polling-Intervall (z. B. 250 ms) — ein Regler, kein Architektur-Sprung.

**Rechte-Modell (Vorgabe Karl, knüpft an S4/S5 an):**
- Alle rootless-Funktionen laufen im User-Betrieb.
- Will der Anwender Traffic aller Apps sehen → Meldung "CERNIS PRO muss als Root gestartet werden".
- Domäne fragt das Recht über einen Port ab, sperrt **nur** diesen Feature-Bereich bei fehlendem Recht.
- Bauphase: möglichst nur den **Backend-Prozess** privilegiert starten, nicht die GUI. Minimale, lokalisierte, sichtbare Rechte — direkter Gegenentwurf zu S5.

### 4.3 Prozess-Sicht

Aus `/proc` (kein eBPF nötig): CPU-Dauerlast; Prozesse ohne erkennbaren Pfad / aus temporären Verzeichnissen; Prozesskette (wer startete wen).

### 4.4 Interpretierende `analysis`-Schicht (Herzstück)

Schicht **über** den Datendomänen, die auffällige Muster **zeigt und einordnet — ohne zu urteilen**.

**Beispiel-Beobachtungen:** "Prozess spricht mit IP/Land, mit dem sonst nichts spricht"; "200 Verbindungen in 10 Min → Scanning-Verhalten"; "Verbindung zu typischem Fernzugriffs-Port"; Prozess-Auffälligkeiten (4.3).

**Rote Linie — bewusst nicht überschreiten:**
- **Zeigen und einordnen: ja.** ("Das fällt auf, hier ist der Kontext, du entscheidest.")
- **Urteilen / Entwarnung: nein.** Falsche Entwarnung ist gefährlicher als keine; ständiges Anschwärzen von Harmlosem wird ignoriert.
- Folgt aus der These: 08/15-Tool urteilt für dich, Enterprise überfordert dich — CERNIS PRO macht **kompetent**.

**Bewertung via Links statt eigener Datenbank (Vorgabe Karl):** Links zu weiterführenden Ressourcen statt eigener Bewertung → keine Bedrohungsdatenbank, **keine Wartungslast**. Nebeneffekt: **Lern-Werkzeug**.

**Detailtiefe der Links: bewusst später.** Erst Beobachtungen kennen, dann Ressourcen zuordnen. Festzuhalten ist nur **Prinzip** und **architektonische Verortung** (4 unten). Offene Detailfragen (notiert, nicht jetzt): Link-Ziele als Daten pflegen; **Privacy** (Links mit IP/Domain → bewusster Klick, keine Hintergrund-Abfragen — Punkt fürs Phase-4-Audit); Kontextabhängigkeit (interne IP ≠ externe IP ≠ Prozess).

### 4.5 Nur gestreift, nicht vertieft (offene Richtungen)

- **Was ist da:** Geräte-Historie & Fingerprinting; aktives Service-Scanning pro Host.
- **Was passiert:** DNS-Mitschnitt; Bandbreiten-Verlauf als Graph.
- **Stimmt was nicht:** "neues unbekanntes Gerät"; "bekanntes Gerät spricht erstmals mit neuem Ziel"; "App sendet ungewöhnlich viel raus".
- **Was tun damit:** Export, Reports, "Mail bei Ereignis X", Integration.

---

## 5. Technologie-Entscheidung (vom Entwickler getroffen)

> **Rollenklärung:** Karl ist kein Entwickler und hat die Wahl der Programmierumgebung ausdrücklich Claude als Entwickler-Experten übertragen. Das ist die ehrliche Arbeitsteilung: **Was** das Produkt können soll und für wen (Produktvision, Features, UX) entscheidet Karl. **Womit** es gebaut wird, entscheidet Claude und trägt die technische Verantwortung dafür. Die Begründungen unten dienen der Nachvollziehbarkeit, nicht der Rückdelegation der Entscheidung.

### 5.1 Entscheidung

**Der bestehende Stack wird weiterentwickelt, mit einer einzigen geplanten, gekapselten Ausnahme.**

- **Frontend → React im Tauri-Fenster (bleibt).** Web-Technologie gibt die volle gestalterische Freiheit, die das UI-Designprinzip (Abschnitt 3, "alte Tabellen aufbrechen") verlangt. Nichts anderes käme heran. Klar richtig, keine Diskussion.
- **App-Hülle → Tauri v2 (bleibt).** Leichtgewichtig, nativ auf allen fünf Zielplattformen, der schwerste Teil (plattformübergreifendes Bauen) ist bereits gelernt und bezahlt. Wegwerfen wäre Selbstsabotage.
- **Backend → Python für den Rewrite (bleibt zunächst).** Mit einer bewussten Ausnahme (5.2).

### 5.2 Die eine gekapselte Ausnahme: systemnahe Adapter

Die systemnahen Teile (Verbindungen pro App via `sock_diag`, Prozess-Daten via `/proc`, perspektivisch eBPF) werden hinter einer sauberen Schnittstelle (Port) so gekapselt, dass sie **bei Bedarf in einer systemnäheren Sprache neu geschrieben werden können, ohne den Rest anzufassen.**

**Begründung (zur Nachvollziehbarkeit):**
- Python ist beim plattformübergreifenden **Ausliefern** strukturell sperrig (PyInstaller pro Architektur eigener Interpreter; auf ARM-VM kein x64-Backend baubar; Scapy-Cache-Probleme — alles bereits erlebt).
- Die neuen Features sind **systemnah** — genau die Domäne, in der eine systemnahe Sprache glänzt und Python sich quält.
- **Aber: nicht jetzt wechseln.** Mitten im laufenden Rewrite zusätzlich die Sprache zu tauschen hieße, zwei riskante Dinge gleichzeitig zu tun — bei jedem Fehler unklar, welcher ihn verursacht. *Das* ist der Weg, der "knallt".
- **Sicherer Weg:** erst die Struktur sauber bauen (der laufende Rewrite), und sie so anlegen, dass ein späterer Sprachwechsel eines einzelnen Bauteils ein isolierter, ungefährlicher Eingriff ist — kein Eingriff am offenen Herzen.

### 5.3 Konsequenz

Die Technologiewahl ist damit **getroffen**, nicht offen. Die Sprache der systemnahen Adapter ist eine *spätere Ingenieurs-Mechanik* hinter einem stabilen Port, kein Grundsatzthema und keine Frage, mit der Karl behelligt wird. Entspricht der Snapshot-Regel "erst verstehen, dann entscheiden, kein Schnellschuss" — angewandt auf die Reihenfolge: Struktur zuerst, Sprachwechsel (falls nötig) lokal und später.

---

## 6. Architektur-Konsequenzen (Input für Phase 0)

### 6.1 Neue Domänen
- **`traffic`:** Per-App-Monitoring. Port `PerProcessTrafficProvider` (vorläufig). Erster Adapter (Linux): Stufe 1+2 über `/proc/net` / `sock_diag`. Stufe 3 (eBPF) = potenzieller späterer **zweiter Adapter hinter demselben Port**. Eigener Port für **Rechte-Abfrage** (rootless vs. Root).
- **`process`:** Prozess-Sicht aus `/proc`.
- **`analysis` / `insights`:** interpretierende Schicht über `scanning`, `traffic`, `process`.

### 6.2 Warum `analysis` die Architektur rechtfertigt
Bisheriger Einwand: ein reiner LAN-Scanner hat **wenig reine Domänenlogik** — ein Scan *ist* I/O, Hexagonal drohte "Architektur-Theater". `analysis` ändert das: konsumiert Daten anderer Domänen, produziert Beobachtungen, **kein** privilegierter Zugriff — reine, fast I/O-freie Domänenlogik. Genau der echte Domänen-Kern, der Tests verdient *und* lohnt. Liefert dem Backend die nachträgliche Rechtfertigung für die Hexagonal-Entscheidung — und damit für die Lösung von A1/A6.

### 6.3 Regeln als Daten, nicht als Code
"Auffällig" ("Verbindung in unübliches Land", "Prozess aus /tmp", "CPU-Dauerlast") wird zu **deklarierbaren Regeln**, die eine `RuleEngine` auswertet — erweiterbar, testbar, ohne zentrale Datei anzufassen. Unterstützt direkt den Vorzeige-Anspruch (Testbarkeit, keine Spaghetti).

### 6.4 Beobachtung trägt Hilfe-Kontext
`analysis` produziert "Beobachtung X **mit zugeordnetem Hilfe-Typ**". Die konkrete URL ist **Infrastruktur** — Lookup-Tabelle hinter einem Port, pflegbar ohne Domänen-Eingriff.

---

## 7. Plattform-Ziele

Linux ARM, Windows x64/ARM, macOS Silicon (offiziell signiert) — alle realistisch, das meiste bereits einmal gebaut.

- **macOS "offiziell mit Zertifikat":** kostenpflichtige Apple-Developer-Mitgliedschaft **ist vorhanden** → teuerster/bürokratisch sperrigster Brocken erledigt. Verbleibt: Signieren + Notarisieren als Build-Pipeline-Thema, zu klären **wenn die macOS-Auslieferung ansteht**, mit den dann aktuellen Apple-Konditionen (nicht aus dem Gedächtnis). Hängt mit A5 zusammen (Mac-Startproblem — Ursache Code vs. Build/Signierung in Phase 0 trennen).
- **Plattform-Fokus während Rewrite:** Linux x64 first (unverändert ggü. `pre_release_202605.md`), andere Plattformen via Ports gestubbt.

---

## 8. Status & nächste Schritte

### 8.1 Brainstorming
- [x] Übergeordneter Qualitätsanspruch definiert (Vorzeigeprojekt)
- [x] Principal-Findings (A1–A6, S1–S5) mit Adressierung dokumentiert
- [x] Produkt-These geschärft
- [x] Designprinzip Oberfläche umrissen
- [x] Kern-Features umrissen (Per-App-Traffic, Prozess-Sicht, `analysis` mit Links)
- [x] Technologie-Entscheidung getroffen
- [ ] Offene Richtungen aus 4.5 bei Bedarf in späterer Runde vertiefen

### 8.2 Verbindung zum Rewrite-Plan (`pre_release_202605.md`)
Input für **Phase 0 (Ist-Analyse)**: neue Domänen (`traffic`, `process`, `analysis`) in Domänen-Karte; Rechte-Modell als Port; `analysis` als reiner Domänen-Kern. Jedes Finding aus Abschnitt 1 bleibt verbindlicher Maßstab durch alle Phasen.

### 8.3 Weiterhin offen (aus `pre_release_202605.md`)
- [ ] **Freigabe `data/`-Verzeichnis** (SQLite-DBs) für **Schema-Analyse** (nur Schema, keine Inhalte) — betrifft jetzt auch Speicherung von Traffic-Historie.
- [ ] Phase 0 starten (nach Freigabe)
- [ ] `v1.0.0-final` taggen; Branch `rewrite/v2` abzweigen; beide Planungsdokumente unter `docs/` einchecken

---

**Dokument-Status:** lebend. Wird mit der Ist-Analyse (Phase 0) und weiteren Brainstorming-Runden fortgeschrieben.
