# CERNIS PRO 2.0 -- Offene Bugs & Regressionen

Zweck: dauerhafte, eigene Liste bekannter Bugs (getrennt von der Master-Aufgabenliste,
die Status/Aufgaben fuehrt, und von WISHES.md, die Ideen fuehrt). Neue Bugs oben anfuegen.

Legende: OFFEN | IN ARBEIT | BEHOBEN (mit Commit)

---

## OFFEN

(keine)

## BEHOBEN
### B-001 -- Kacheln zweite Reihe kleiner als erste Reihe (Frontend/CSS, Regression)
- Behoben in Commit 527e9ea (2026-07-02, Sitzung 26).
- Ursache: .card-grid nutzte align-content:start ohne grid-auto-rows -> implizite Grid-Zeilen erhielten die Hoehe ihrer jeweils hoechsten Karte; ungleich hohe Reihen bei ungleichem Karteninhalt.
- Fix: grid-auto-rows: 1fr; im .card-grid-Block (frontend/src/components/AreaShell.css) -> alle impliziten Zeilen gleich hoch, Karten fuellen per stretch-Default -> einheitliches Raster ueber alle Reihen. Live im Bereich "Beobachten" verifiziert.
