# 0038 - diagnostics bekommt schmale Persistenz fuer das letzte Rogue-DHCP-Ergebnis

## Status

Akzeptiert

## Kontext

Die diagnostics-Domaene ist bisher persistenzfrei: alle ihre Pfade (DNS, traceroute,
Banner, externer Check, Rogue-DHCP) sind reine Frage-Antwort-Vorgaenge ohne Speicher
(ADR 0014). Die Rogue-DHCP-Erkennung (`DetectRogueDhcp`, Block 3) ist zusaetzlich
ROOT-PFLICHTIG ohne rootless Alternative: sie sendet ein rohes DHCP DISCOVER und sperrt
ehrlich, wenn kein Root vorliegt (kein stiller Fallback, S3).

Der spaetere Sicherheitsbericht soll den letzten bekannten Rogue-DHCP-Stand MIT Datum
zeigen. Er darf dafuer aber KEINEN aktiven (root-pflichtigen) Probe ausloesen -- ein
Bericht laeuft typischerweise ohne Root und soll nicht scheitern oder eskalieren. Ohne
einen festgehaltenen letzten Stand muesste der Bericht entweder selbst proben (verbietet
sich) oder den Rogue-DHCP-Teil leer lassen. Es fehlt also ein gespeicherter letzter Stand,
den der Bericht passiv lesen kann.

Es standen drei Wege offen: gar nichts speichern (Bericht kann Rogue-DHCP nicht zeigen);
eine Historie aller Laeufe fuehren; oder genau den letzten Lauf festhalten.

## Entscheidung

diagnostics bekommt erstmals eine schmale Persistenz, ausschliesslich fuer das
Rogue-DHCP-Ergebnis: gespeichert wird IMMER nur der LETZTE Lauf -- ein Datensatz,
ueberschreibend, mit Zeitstempel. KEINE Historie.

- Ein neuer Port `RogueDhcpStore` (`ports/diagnostics.py`) traegt den Vertrag:
  `save_latest(...)` ueberschreibt den einen Datensatz, `load_latest()` liest ihn (oder
  `None` = noch nie geprueft). Der Vertrag ist PORT-NEUTRAL (keine domain-Objekte): die
  Server gehen als rohe `(ip, mac|None, is_expected)`-Tupel herein und kommen als frozen
  Lese-Views `RogueDhcpServerRecord` / `LatestRogueDhcp` heraus -- Muster
  `ports.security.ArpAlertRecord`/`ArpBaselineRecord`, die die security-Persistenz
  ebenfalls ueber eigene Record-Typen statt ueber Domaenentypen fuehren.
- Ein neuer SQLite-Adapter `SqliteRogueDhcpRepository`
  (`infrastructure/rogue_dhcp_repository.py`) erfuellt den Port. Eine Tabelle
  `rogue_dhcp_latest`, die per festem Primaerschluessel (`id INTEGER PRIMARY KEY CHECK
  (id = 1)`) + UPSERT immer nur EINE Zeile haelt. Die Server-Liste liegt als JSON-Spalte
  (nicht als Detailtabelle), die Erwartungsmenge ebenso; `checked_ts` als REAL. Schema-Init
  idempotent im Konstruktor, Connection-Behandlung exakt wie die Vorbild-Adapter
  (`SqliteSettingsRepository`/`SqliteDeviceRepository`). Kaputtes JSON ist ein Fehler
  (`CorruptRogueDhcpError`), kein stiller Fallback (S3).
- Die SCHREIBNAHT sitzt im Use-Case `DetectRogueDhcp`: ein OPTIONALER `RogueDhcpStore`
  wird injiziert, und nach JEDEM erfolgreichen Lauf wird der letzte Stand ueberschreibend
  gespeichert. Der Zeitstempel `checked_ts` kommt als Parameter von `__call__` herein
  (Composition Root, `time.time()`) -- KEINE Wanduhr im Use-Case. Ist kein Store gesetzt
  (Default `None`), laeuft die reine Erkennung wie bisher.
- Ein duenner Lese-Use-Case `GetLatestRogueDhcp` reicht `load_latest()` durch (oder `None`)
  -- der spaetere Bericht liest darueber, ohne einen Probe auszuloesen.
- Der Composition Root (`app.py`) verdrahtet den Adapter lazy-memoisiert (wie die anderen
  Repos) und injiziert ihn samt `time.time()` in `DetectRogueDhcp`.

## Begruendung

Der letzte Stand ist genau das, was der Bericht braucht, und nicht mehr. Eine Historie
waere Vorbau (YAGNI): der Bericht zeigt einen Stand-mit-Datum, keinen Verlauf -- niemand
hat einen Verlauf angefragt, und ein ueberschreibender Singleton-Datensatz traegt den real
benoetigten Fakt vollstaendig, ohne Aufraeum-Politik, Retention oder Mengenwachstum.

Die Schreibnaht gehoert in den Use-Case, weil der bestehende Stil Persistenz-Nebenwirkungen
dort verdrahtet (`RunArpScan` -> `ArpGuardRepository`) und `DetectRogueDhcp` ohnehin schon
`SettingsRepository`/`InterfaceDiscoveryPort` liest. So bleibt "speichere den letzten Lauf"
eine einzige, getestete Naht statt einer am Composition Root nachgeklebten Nebenwirkung. Der
optionale Store haelt die reine Erkennung (und die Bestands-Tests) frei von Persistenz.

Der Zeitstempel kommt als Parameter herein, weil die diagnostics-Use-Cases uhrfrei bleiben
(Muster `cve.RunDripCheck(now, ...)` / monitoring): die Zeit ist ein von aussen gereichter
Fakt, kein im Use-Case erzeugter -- das haelt den Use-Case deterministisch testbar (S3).

Die JSON-Spalte statt einer Detailtabelle folgt dem Bestand (settings/devices halten
variable Listen als JSON-in-TEXT) und vermeidet fuer einen einzigen ueberschreibenden
Datensatz den Overhead von Join + Aufraeumen. Der feste Primaerschluessel mit CHECK
erzwingt die Singleton-Semantik strukturell statt per Konvention.

## Konsequenzen

- Der spaetere Sicherheitsbericht kann den letzten bekannten Rogue-DHCP-Stand mit Datum
  zeigen, ohne selbst einen root-pflichtigen Probe auszuloesen (passives Lesen).
- diagnostics ist nicht mehr vollstaendig persistenzfrei -- aber die Persistenz bleibt auf
  diesen einen Singleton-Datensatz begrenzt; die uebrigen diagnostics-Pfade bleiben
  speicherfrei.
- Es gibt keinen Verlauf: ein neuer Lauf ueberschreibt den vorigen. Will der Bericht spaeter
  doch einen Verlauf, ist das eine eigene, dann begruendete Erweiterung (kein Vorbau jetzt).
- Der Bericht-Code (api-Route + Frontend) ist NICHT Teil dieser Etappe; `GetLatestRogueDhcp`
  steht bereit, wird aber erst vom Bericht gebaut/verdrahtet.
- Der Singleton-Row mit festem Primaerschluessel ist im Bestand neu (alle anderen Repos
  halten Mehrzeilen-Tabellen) -- bewusst, weil der Auftrag genau einen ueberschreibenden
  Datensatz verlangt; die Wahl ist im Adapter als Klartext-Kommentar begruendet.
