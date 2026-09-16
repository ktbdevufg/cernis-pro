# 0040 — Außenkontakt-Bewertung gegen lokale Blocklists (eigene Domäne)

Status: akzeptiert · Datum: 2026-06-26 · Bereich: domain/blocklist, ports/blocklist,
application/blocklist, infrastructure (2 SQLite-Adapter + urllib-Fetcher), api/blocklist,
Scheduler-Handler, app.py-Verdrahtung

## Kontext

Die Außenkontakte-Ansicht zeigt, mit wem dieser Rechner spricht (Momentaufnahme + Aufzeichnung,
ADR 0039) — aber sie **ordnet die Gegenstellen nicht ein**. Ein Anwender sieht eine IP/Domain und
weiß nicht: ist das ein Tracker, ein Werbenetz, ein bekannter Malware-/Botnet-Host, oder harmlos?
Gewünscht war eine Einordnung gegen extern gepflegte Blocklists (StevenBlack, OISD, URLhaus, Feodo,
FireHOL …).

Die **rote Linie** dabei: *zeigen + einordnen, aber CERNIS urteilt nicht selbst.* Die Einordnung
(„dies ist ein Tracker") gehört der jeweiligen Liste, nicht CERNIS. Wir betreiben keine eigene
Reputations-Engine und treffen keine eigene Gut/Böse-Entscheidung — wir spiegeln, was eine vom
Anwender ausgewählte, extern gepflegte Liste sagt. Der Anwender bleibt mündig: er wählt die Listen,
die Strenge und die Gruppen.

Zwei Spannungen prägten den Entwurf:
1. **Lokal vs. Server:** Eine externe Reputations-API (VirusTotal o. ä.) wäre mächtig, hängt aber an
   der noch offenen Grundsatzentscheidung lokal-vs-server (Vision 5.x) und an Datenschutz (jede
   abgefragte IP verlässt den Rechner). Vorerst: **rein lokal**, gepflegte Listen werden geladen und
   indiziert.
2. **Lizenz vs. Nützlichkeit:** Die nützlichsten Tracker-/Werbe-Listen (EasyList/EasyPrivacy/AdGuard)
   sind **Copyleft** (GPL/CC-BY-SA). Das CERNIS-Lizenzmodell ist noch nicht final (GPLv3
   wahrscheinlich, aber unsicher) — ein mitgelieferter, automatisch geladener Copyleft-Datenbestand
   wäre ein Risiko, solange das ungeklärt ist.

## Entscheidung

Eine **eigene Domäne** `domain/blocklist.py` (Einzeldatei, ADR 0002: stdlib-rein, `StrEnum`-Vokabular
+ `frozen` Datenträger + reine zeitfreie Funktionen), getrennt von der Außenkontakte-Momentaufnahme.
Der Application-Ring (`application/blocklist/`) verwaltet Quellen, lädt, gleicht ab und prüft die
Gesundheit; der api-Ring (`api/blocklist.py`, prefix `/api/blocklist`) ist application-frei
(import-linter Regel 4 — `provide_*`-Marker, schmale Runner-Protocols, die Projektion Domäne→Wire
macht der Composition Root).

Weitere Festlegungen:

- **Lokale Listen + indizierte Einträge:** Zwei getrennte Persistenz-Belange (Muster `outbound_log`):
  `blocklist_sources` (die Quellen-DEFINITIONEN, Upsert — `status`/`enabled`/`entry_count` wandern)
  und `blocklist_entries` (die geparsten Einträge, getrennt nach `kind` domain/ip_cidr, indiziert für
  Set-Lookup bzw. CIDR-Iteration). Der Abgleich läuft host-lokal, ohne Netzaufruf pro Kontakt.

- **Fetcher als Protocol-NAHT:** Das Laden (Netz-I/O) liegt hinter dem `BlocklistFetcher`-Protocol IN
  `application`; die echte Impl (`UrllibBlocklistFetcher`, urllib + Timeout + Größendeckel + eigener
  User-Agent) lebt in `infrastructure` und erfüllt das Protocol **strukturell**, ohne `application` zu
  importieren. Die Fehlersemantik bleibt beidseitig sauber: der Fetcher wirft eine eigene
  Infrastruktur-Exception (`FetchFailed`), der `RefreshSource`-Use-Case fängt **breit** (`Exception`)
  und setzt status BROKEN. So läuft im Test kein echtes Netz (injizierter Fake-Fetcher), und keine
  Schicht nennt die andere.

- **Fälligkeit über `last_fetched_ts` (wie cve):** Der Auto-Refresh hängt am v2-Scheduler. Das
  `DailyWindow` ist ein **Tagesfenster** (03:00–04:00 lokal, alle Tage), kein „alle N Tage". Der Job
  tickt täglich; die **echte Fälligkeit** (alle `interval_days`) entscheidet `RefreshDueSources` über
  den `last_fetched_ts`-Vergleich (Muster cve `due_reason`). Derselbe Use-Case speist den
  Scheduler-Handler UND den manuellen „alle fälligen jetzt"-Knopf.

- **Strenge-Stufen + Gruppen-Schalter in Settings:** Die Anzeige-Strenge (`MatchStrictness`:
  CRITICAL_ONLY / RECOMMENDED / ALL) ist Domänenregel (`strictness_allows`); die Gruppen-Feinschalter
  (Tracker/Ads an-aus, Threat an-aus) sind Settings-/Application-Belang. Beides liegt im bestehenden
  Key-Value-`SettingsRepository` (**keine** neue Settings-Domäne) — eigene schmale Endpunkte unter
  `/api/blocklist/settings`, Strenge-Validierung im Schreibpfad (unbekannt → 422).

- **Lizenz-Hinweis-Heuristik verweigert nichts:** `detect_license_hint(url)` schätzt anhand des Hosts
  einen freundlichen Lizenz-HINWEIS (Attribution/Share-Alike beachten). Sie urteilt nicht und sperrt
  nichts — der mündige Anwender entscheidet selbst.

- **Werksliste lizenzrobust aktiv, Copyleft deaktiviert:** Die vorausgewählten `DEFAULT_SOURCES`
  (`enabled=True`) sind bewusst permissiv/public-domain (MIT/CC0/custom-free: StevenBlack, OISD,
  URLhaus, Feodo, FireHOL L1). Die Copyleft-Quellen (EasyList/EasyPrivacy) sind **mitgeliefert, aber
  DEAKTIVIERT** — erst nach Lizenzklärung durch den Anwender aktivieren, solange das CERNIS-
  Lizenzmodell unsicher ist (GPLv3 wahrscheinlich).

## Format-Familien

`BlocklistFormat` benennt die Parser-Familie; `application/blocklist/parsing.py` zerlegt zeitfrei/
netzfrei in normalisierte `(domains, ip_cidrs)` (dedupliziert, stabile Reihenfolge):

- **HOSTS** (`0.0.0.0 domain`): die Sentinel-Bind-Adressen (0.0.0.0/127.0.0.1/::) sind **keine
  Threat-IPs** und werden verworfen — es bleibt nur die Domain.
- **DOMAIN_LIST**: eine Domain (oder Wildcard `*.x.y`) pro Zeile; führendes `*.` wird gestrippt.
- **ADBLOCK** (`||domain^`): Domain extrahiert; Element-Hide- (`##`/`#@#`), Ausnahme- (`@@`) und
  Nicht-Domain-Regeln werden ignoriert.
- **IP_LIST**: eine IP/CIDR pro Zeile, per `ipaddress` validiert.
- **CSV_DOMAIN / CSV_IP**: erste plausible Spalte je Zeile, Header tolerant übersprungen.

## Konsequenzen

**Positiv:**
- Außenkontakte werden eingeordnet, ohne dass CERNIS selbst urteilt — die Einordnung gehört der Liste,
  der Anwender wählt Listen/Strenge/Gruppen.
- Rein lokal, kein Netzaufruf pro Kontakt, keine IP verlässt den Rechner beim Abgleich.
- Saubere Schichtung: der Fetcher-Protocol-Naht erlaubt einen späteren Wechsel der Lade-Schicht
  (oder eine Server-Variante) als lokalen Eingriff.
- Lizenzrobust per Default; Copyleft bleibt eine bewusste Anwender-Entscheidung.

**Negativ / bewusst offen:**
- **Kein `finished_at` der Listen-Aktualität jenseits `last_fetched_ts`:** Eine BROKEN-Quelle behält
  ihren letzten guten `entry_count`/`last_fetched_ts` (der Stand verfällt nicht); der `/health`-Befund
  + Ersatzvorschlag ist nur eine Empfehlung — **kein automatisches Löschen/Ersetzen** (das macht der
  Anwender über Delete/Add).
- **CIDR-Lookup linear:** Echte Netze werden iterierend per `ip_in_cidr` geprüft. Bei wenigen tausend
  Netzen (FireHOL L1) akzeptabel; bei deutlich größeren IP-Beständen wäre ein Intervall-Index nötig.

## Abgrenzung

- **Keine externe Reputations-API** (VirusTotal o. ä.): hängt an der späteren lokal-vs-server-
  Entscheidung (Vision 5.x) und am Datenschutz. Vorerst bewusst nicht.
- **Kein eigenes CERNIS-Urteil:** keine eigene Scoring-/Reputations-Engine — nur Spiegelung der
  ausgewählten Listen.
- **Keine Frontend-Änderung in diesem Schritt:** dieser Auftrag baut Ring 4+5 + Scheduler-Handler +
  Verdrahtung; die UI-Integration folgt separat.

## Nachtrag (2026-06-29): FireHOL Level 1 nachträglich deaktiviert

`firehol_level1` wird nachträglich auf `enabled=False` gesetzt (mitgeliefert, aber aus). Grund ist
**nicht** die Lizenz (MIT, robust), sondern **Bogon-Reibung**: FireHOL Level 1 führt bewusst
private/reservierte Netze (127/8, 192.168/16, 10/8) und träfe damit eigene Infrastruktur als
„Bedrohung“ — im Heim-/SOHO-Alltag praktisch nur Reibung statt echter Treffer. Aktive Threat-IPs
deckt `feodo_ipblocklist` (Feodo Tracker) ohne diese Bogon-Reibung ab. Der Eintrag bleibt in der
THREAT-Gruppe (kein Lizenz-, sondern ein Bogon-Grund) und kann vom Anwender jederzeit wieder
aktiviert werden.
