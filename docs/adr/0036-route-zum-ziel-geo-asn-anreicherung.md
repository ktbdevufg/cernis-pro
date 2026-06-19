# 0036 — Route zum Ziel: traceroute-Hops mit Geo/ASN, lokal + optionale RDAP-Nachladung

## Status

Akzeptiert

## Kontext

Die "Diagnose"-Ansicht bekommt eine Funktion "Route zum Ziel": der Nutzer gibt ein
Internet-Ziel (Domain/IP) ein, CERNIS zeigt den Netzweg dorthin als Hop-Liste — pro Hop
Hop-Nr., IP, Land, Betreiber/ASN, RTT. Das macht den bereits vorhandenen traceroute
sichtbar und reichert jeden Hop mit Geo/ASN an.

Befund am Code (verifiziert, nicht geraten):

- **traceroute** liefert bereits `GET /api/diagnostics/traceroute?target=&privileged=`
  über `RunTraceroute` (`application/diagnostics`) → `TracerouteResult` mit
  `hops: [{hop, address, rtt_ms}]`. Ein nicht-antwortender Hop hat `address/rtt_ms = None`
  (ehrliche Lücke). Fehlt das Binary → 503 (globaler `DiagnosticsToolMissing`-Handler).
  Rechte-Naht: `GET /api/diagnostics/traceroute/permission` → `{ok, error}` —
  privilegiert ist genauer, unprivilegiert funktioniert trotzdem (keine Sackgasse).
- **Geo/ASN** liefert `GeoAsnDbPort.lookup(ip) → GeoAsnRecord{country, asn, asn_org}` —
  **lokal + synchron**, kein Netz-I/O, leerer Record wenn nichts (kein Fehler). Der
  produktive Adapter `CsvGeoAsnDb` (`infrastructure/resolver`) befüllt aus vier lokalen
  CSVs **nur** `country` und `asn` (die ASN-**Nummer** als String); `asn_org` bleibt dort
  **strukturell immer `None`** (der Klartext-Org-Name steht nicht in der DB). `GeoAsnRecord`
  trägt **keine Koordinaten** — nur `country/asn/asn_org`.
- **RDAP** liefert über `RdapClient.lookup(ip) → RdapRawFacts` ein `org`-Feld (registrant/
  administrative entity, jCard `fn`) — der **Betreibername je IP** (nicht je ASN; RDAP-`asn`/
  `asn_org` sind dort bewusst `None`). Der Adapter ist laut Port-Vertrag **streng
  fehlertolerant**: bei jedem Fehlschlag (Timeout, HTTP-Fehler, kaputtes JSON) leerer
  `RdapRawFacts`, wirft nie.
- Quer-Domänen-Nähte gehören **ausschließlich** in den Composition Root (Regel 5, ADR 0035
  Muster `BuildTopology`/`application.export.ScanProvider`): weder Domäne noch Port nennt
  die jeweils andere Domäne; die independence der `domain.*`-Subpakete ist import-linter-hart.

## Entscheidung

### Warum nur Liste, keine Karte

`GeoAsnRecord` hat **keine Koordinaten** (nur `country/asn/asn_org`). Eine Karte mit
geschätzten Länder-Mittelpunkten wäre ein **stiller Fallback** (erfundene Geometrie aus
einem Ländercode) — verboten (Finding S3). Daher ausschließlich eine **Hop-Liste**; die
Flagge leitet das Frontend rein clientseitig aus dem ISO-Ländercode ab (Unicode-Regional-
Indicator), ohne Bild-/npm-Abhängigkeit und ohne externes Asset.

### Zwei getrennte Nähte (lokaler Hauptpfad + optionale RDAP-Nachladung)

Bewusst **zwei getrennte Endpunkte/Use-Cases**, nicht ein verschmolzener Pfad — die
Begründung ist Geschwindigkeit und Robustheit:

1. **Hauptpfad — lokal + synchron, schnell, root-frei.** `BuildRouteGeo`
   (`application/diagnostics`) bekommt den eigenen `RunTraceroute`-Use-Case (Hop-Quelle,
   eigene Domäne — erlaubt) und ein **quellen-agnostisches** Geo-Callable
   `GeoLookup = Callable[[str], dict[str, str | None]]` (IP → rohes `{country, asn, asn_org}`-
   dict). Pro **antwortendem** Hop (echte `address`) wird der Geo-Lookup gerufen; ein
   nicht-antwortender Hop (`address=None`) wird **nicht** angefragt und behält
   `country/asn/asn_org = None` — die Lücke bleibt sichtbar. `asn_org` ist hier **immer
   `None`** (die CSV-DB kennt es nicht) — ehrliche Leere, kein geratener Wert.
   Endpunkt: `GET /api/diagnostics/route?target=&privileged=` →
   `{target, privileged, hops:[{hop, address, rtt_ms, country, asn, asn_org}]}`.
   `privileged` ist optional (Default `false`) — der unprivilegierte Pfad funktioniert
   ohne Root (keine Sackgasse); `true` wählt die genauere Methode, läuft aber nur, wenn der
   Prozess die Rechte ohnehin hat. Fehlt `traceroute` → 503 (vorhandener Handler).

2. **Optionale Nachladung — Netz-I/O über RDAP, nur auf expliziten Abruf.**
   `EnrichRouteOrgs` (`application/diagnostics`) bekommt ein quellen-agnostisches
   `OrgLookup = Callable[[str], Awaitable[str | None]]` (IP → Org-Name | `None`). Endpunkt:
   `GET /api/diagnostics/route/orgs?ips=&ips=` → `{orgs:{ip: org}}` (nur IPs **mit** Treffer).
   Das Frontend ruft diesen Pfad **nur** auf expliziten Nutzer-Wunsch (Schalter, Default
   AUS, klar als Internet-Abfrage gekennzeichnet) und blendet die Namen in die bereits
   geladene Liste ein (Muster der lazy PTR-Namen / AUTO-MANUELL).

**Schnittführung der Nachladung: Batch über die deduplizierten, antwortenden Hop-IPs** —
nicht pro Hop einzeln und nicht über die ASN. Begründung am Code: der `RdapClient` löst
**per IP** auf (nicht je ASN; eine ASN→Org-Auflösung gibt es nicht), und mehrere Hops
teilen sich oft eine IP/ein Netz — die Dedup spart Netz-Aufrufe. Eine private/Lücken-IP hat
schlicht keinen Eintrag.

### Ehrlicher Umgang mit Lücken (kein stiller Fallback, S3)

- **Nicht-antwortender Hop** (`address=None`): bleibt als Hop in der Liste mit
  `address/rtt_ms/country/asn/asn_org = null` — kein Weglassen, kein erfundener Wert.
- **Fehlende Geo-Daten** (private IP, kein DB-Treffer): `country/asn = null` — ehrliche
  Leere.
- **`asn_org` im Hauptpfad**: immer `null` (die DB kennt es nicht) — der Org-Name kommt
  **nur** über die optionale RDAP-Nachladung, nicht im Hauptpfad geraten.
- **Gescheiterte RDAP-Auflösung**: die IP fehlt schlicht in der `{ip: org}`-Map (`null`).
  Der Adapter wirft nie (Port-Vertrag); die Nachladung blockiert **nie** die schon
  sichtbare Liste und fälscht **nie** einen Namen.

### Rechte-Naht (keine Sackgasse)

`privileged` ist eine bewusste Nutzerwahl und wird unverändert durchgereicht (keine
Selbst-Eskalation). Der **unprivilegierte** Pfad läuft auf der Ziel-VM ohne Root
(verifiziert: `traceroute` UDP-Default antwortet ohne sudo). Das Frontend nutzt den
vorhandenen `/traceroute/permission`-Status für einen dezenten Hinweis "genauere Messung mit
Rechten möglich" — die Messung läuft trotzdem.

### Composition Root (Regel 5)

Beide Nähte fallen ausschließlich in `app.py`, **nach** dem resolver-Block (beide
resolver-Adapter `geo_asn_db()`/`RdapClient` sind dort schon in Scope — keine zweite
Instanz). Das Geo-Callable projiziert dort den `GeoAsnRecord` auf ein rohes dict; das
Org-Callable zieht dort `RdapRawFacts.org` auf den rohen `str | None`. Weder die
diagnostics-Domäne noch ihr Port nennt resolver — die independence-Contracts bleiben hart
(import-linter: 8/8 KEPT verifiziert).

## Konsequenzen

- Eine neue Diagnose-Funktion macht den vorhandenen traceroute mit Land + ASN sichtbar,
  ohne neue systemnahe Infrastruktur und ohne Root-Zwang.
- Der schnelle, robuste Default-Pfad ist rein lokal; teures/fehleranfälliges Netz-I/O
  (RDAP) ist als bewusste Nutzer-Wahl strikt abgetrennt.
- `asn_org` ist im Hauptpfad ehrlich leer — das ist eine bewusste Folge der lokalen
  Datengrundlage, kein Bug; die Org-Namen sind optional nachladbar.
- Keine Karte (mangels Koordinaten) — die Liste ist die ehrliche Darstellung.

## Verifikation

- 5-Gate grün: ruff check + format, mypy strict, import-linter (8/8 KEPT), pytest
  (alle Tests, +9 neue für `BuildRouteGeo`/`EnrichRouteOrgs`).
- Live gegen `1.1.1.1` (unprivilegiert, ohne Root): plausible Hops — private erste Hops
  ehrlich `null`, deutsche Transit-ASNs aus der lokalen DB, Ziel `AU / AS13335`
  (Cloudflare); `asn_org` durchweg `null`. Die Nachladung lieferte echte RDAP-Org-Namen
  je IP.
