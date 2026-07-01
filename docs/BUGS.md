# CERNIS PRO 2.0 -- Offene Bugs & Regressionen

Zweck: dauerhafte, eigene Liste bekannter Bugs (getrennt von der Master-Aufgabenliste,
die Status/Aufgaben fuehrt, und von WISHES.md, die Ideen fuehrt). Neue Bugs oben anfuegen.

Legende: OFFEN | IN ARBEIT | BEHOBEN (mit Commit)

---

## OFFEN

### B-001 -- Kacheln zweite Reihe kleiner als erste Reihe (Frontend/CSS, Regression)
- Bereich: "Beobachten" (Screenshot Sitzung 23, 2026-07-01). Betrifft vermutlich alle
  Kachel-Bereiche mit mehr als einer Reihe.
- Symptom: Kacheln der zweiten Reihe (Logging-Aufgaben / Topologie / Prozesse) sind
  niedriger als die der ersten Reihe (Netzwerk-Scan / Gaeste-Wache / Per-App-Verkehr /
  Aussenkontakte / DNS-Waechter / Live-Monitoring).
- Historie: War frueher schon einmal gefixt -> Regression.
- Verdacht: Grid-Row-Hoehe / align-items in CardGrid bzw. AreaShell.css; eine Kachel mit
  weniger Textzeilen bestimmt die Row-Hoehe (Reihen wachsen nicht auf gleiche Hoehe).
  Zu pruefen: greift align-items: stretch nicht, oder wird die Hoehe pro Row statt ueber
  alle Rows bestimmt (grid-auto-rows / implizite Row-Hoehe)?
- Repro: Bereich "Beobachten" oeffnen, Reihe 1 (voll) mit Reihe 2 vergleichen.
- Noch NICHT angefasst (erst auf Karls Freigabe / im Zuge des naechsten Frontend-Blocks).
