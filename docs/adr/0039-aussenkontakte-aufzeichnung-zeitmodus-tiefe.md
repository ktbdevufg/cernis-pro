# 0039 — Außenkontakte-Aufzeichnung als eigene Domäne mit Zeitmodus- und Tiefe-Achsen

Status: akzeptiert · Datum: 2026-06-25 · Bereich: domain/outbound_log, application/outbound_log,
infrastructure (3 SQLite-Adapter), api/outbound_log, Frontend OutboundView-Integration

## Kontext

Die bestehende Außenkontakte-Ansicht (`BuildOutboundContacts`, GET `/api/outbound/contacts`) liefert
eine **Momentaufnahme** der ausgehenden Verbindungen DIESES Rechners (host-lokal, rootless via
psutil/ss) — ohne Zeitachse. Für ehrliche „von-bis"-Aussagen („mit wem sprach dieser Rechner zwischen
20:00 und 22:00") fehlt eine Aufzeichnung über Zeit. Gewünscht war eine nutzergestartete Funktion
analog zu den Logging-Aufgaben, aber für Außenkontakte.

Zwei Spannungen prägten den Entwurf:
1. **Datenmenge vs. Zeitspanne:** Ein voller roher Zeitverlauf (jeder Tick einzeln) ist genau, aber
   datenintensiv; eine pro-Remote-IP verdichtete Sammlung ist kompakt, verliert aber die Einzelticks.
2. **Rechte vs. Aussagekraft:** Die Programm-Zuordnung (welche App telefoniert) braucht erweiterte
   Rechte (root/full_process_visibility); ohne sie bleibt die Zuordnung leer. Root darf nie erzwungen
   werden.

## Entscheidung

Eine **eigene Domäne** `domain/outbound_log.py` (Einzeldatei, kein Paket — wie devices.py,
diagnostics.py etc.), getrennt von der bestehenden `outbound`-Momentaufnahme. Zwei **orthogonale
Nutzer-Achsen** als Domänen-Enums:

- **Zeitmodus** `RecordingMode`: `DETAIL` (voller roher Zeitverlauf, **auf 24 h begrenzt**,
  `MAX_DETAIL_DURATION_S = 86400`, mit erklärtem Hinweis warum) ↔ `AGGREGATE` (pro Remote-IP
  verdichtet first/last/count/peak, zeitlich unbegrenzt). Die DETAIL-Begrenzung ist eine **bewusste,
  erklärte Nutzerentscheidung**, kein stilles Wegwerfen.
- **Detailtiefe** `DetailDepth`: `ANONYMOUS` (rootless, ohne App-Zuordnung) ↔ `APP_RESOLVED` (mit
  Programm-Zuordnung via full_process_visibility). Root wird nie erzwungen; ohne Rechte bleibt die
  Programm-Spalte ehrlich leer.

Weitere Festlegungen:
- **Tick-Intervall** (nur DETAIL): wählbar 30/60/300 s, Default 60. Validiert in der Domänen-
  `__post_init__` (`ALLOWED_INTERVALS`).
- **Dauer** (nur DETAIL): `max_duration_s`, Default voller 24-h-Deckel; AGGREGATE erzwingt `None`.
- **Konfliktregel:** host-weit darf nur **EINE** Aufzeichnung gleichzeitig `ACTIVE` sein
  (`RecordingConflict` beim Start/Resume → HTTP 409). Live-Monitoring und Außenkontakte-Aufzeichnung
  laufen aber **parallel** (getrennte Worker, getrennte Tabellen, keine geteilte Ressource).
- **Lifecycle** `RecordingState`: CREATED→ACTIVE→(PAUSED↔ACTIVE)→FINISHED. `effective_start` wird beim
  ersten Start gesetzt, beim Stop auf `None` zurückgesetzt (kein `finished_at` gespeichert — bewusst,
  s. Konsequenzen).
- **Persistenz:** 3 SQLite-Tabellen (outbound_log_recordings / _detail / _aggregate), 3 flache
  Adapter, 3 Repository-Protocols.
- **Worker:** `RunOutboundRecorder` (Muster `RunCveMonitor`), tickt best-effort, nutzt
  `BuildOutboundContacts` als Delta-Quelle (Mapping OutboundContact→ContactDelta), erzwingt am
  Tick-Ende die DETAIL-24h-Retention.
- **REST:** `/api/outbound/recordings` (eigener Zweig, getrennt von `/api/outbound/contacts`).
  mode/depth als rohe `str` über die Wire-Grenze; die str→Enum-Hebung passiert autoritativ im
  Use-Case (`CreateOutboundRecording`, Muster `capture_mode`), damit der api-Ring keine Domänen-Enums
  importiert (import-linter Regel 4). `InvalidRecordingTransition` wird aus `application` re-exportiert
  und dort gefangen (Muster `InvalidTaskTransition`).

## Konsequenzen

**Positiv:**
- Ehrliche „von-bis"-Berichte werden baubar (DETAIL liefert den Zeitverlauf, AGGREGATE die Bilanz).
- Maximale Wahlfreiheit für den mündigen Anwender (zwei orthogonale Achsen + Intervall + Dauer), ohne
  Root zu erzwingen und ohne stilles Datenverwerfen.
- Saubere Trennung von der Momentaufnahme; keine Vermischung der beiden Außenkontakte-Pfade.

**Negativ / bewusst offen:**
- **Kein `finished_at`:** Beim Stop wird `effective_start` verworfen, ein „beendet am"-Zeitstempel
  existiert nicht und kann nicht rekonstruiert werden. Die Karten zeigen daher nur „Erstellt am". Eine
  spätere Nachrüstung (DB-Spalte + Domänen-Feld) wäre nötig, falls die Beendet-Zeit gebraucht wird.
- **Befund-Ansicht (E5b) und „von-bis"-Bericht (E6) sind vorbereitet, aber nicht gebaut.** Der
  selectedId-State + Platzhalter sind in OutboundRecordingPanel angelegt; aggregate/detail-Endpunkte
  liefern bereits Daten.

## Verwandte Naht-Entscheidung (gleiche Sitzung, ohne eigene ADR-Nummer)

**ASN-Betreibername-Auflösung (F0/F0b):** Die lokale Geo/ASN-CSV (`backend/data/iptoasn-asn-*.csv`)
führt den Betreibernamen in Spalte 4 (z. B. CLOUDFLARENET), der zuvor verworfen wurde (frühere
A1-Entscheidung „asn_org immer None"). Diese ADR-begleitende Korrektur reicht ihn nun durch
(`CsvGeoAsnDb.lookup` füllt `asn_org`) und macht ihn im `ResolveEndpoint`-Use-Case als **Fallback**
wirksam: `asn_org = rdap.asn_org or rdap.org or geo.asn_org`, mit ehrlichem `SourceTag` (RDAP vs.
GEODB). Damit zeigen die Außenkontakte Klarnamen statt nackter „ASxxxxx"; gemischte Schreibweisen
(RDAP „Cloudflare, Inc." vs. CSV „CLOUDFLARENET") sind bewusst akzeptiert. Bleibt `null`, wenn weder
RDAP noch CSV etwas haben (S3-ehrlich). A1 ist damit aufgehoben.
