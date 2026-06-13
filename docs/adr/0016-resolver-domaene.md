# ADR 0016 — resolver-Domäne: „wer ist die Gegenstelle?" als Fakten mit Quelle (PTR/Forward · RDAP · TLS-Cert · Geo/ASN)

- **Status:** Akzeptiert
- **Datum:** 2026-06-12
- **Phase:** Grüne Wiese (Quer-Feature nach interfaces (0009) + traffic (0010) + process (0011) + analysis (0012/0013) + diagnostics (0014) + export (0015))
- **Bezug:** ADR 0014 (diagnostics: System-`dig`-Adapter, Tool-fehlt-Naht über eine infra-eigene Exception → 503 am Composition Root, HTTPS-Cert-Pflicht ohne `verify=False`); ADR 0010/0014 (System-Tool statt nachgebaute Lib); ADR 0007 (scanning-Adapter dürfen `modules` importieren — dieser Zaun wird hier bewusst NICHT überschritten); ADR 0002 (domain bleibt framework-frei, keine Uhr); ADR 0001 (keine stillen Fallbacks, Finding S3); pyproject.toml (`independence`-Contract über alle `domain.*`-Subpakete)

## Kontext

Die resolver-Domäne ist das **Alleinstellungsmerkmal** von CERNIS PRO: Zu einer Gegenstelle (IP, optional Port) soll möglichst viel **selbst** ermittelt und als **neutrale Fakten mit Quelle** gezeigt werden — dort, wo simple Tools (z. B. ein `netstat`/`ss`) nur die nackte IP liefern. Die Leitlinie ist hart: **kein Urteil, keine Verschmelzung, Widersprüche bleiben sichtbar.** resolver beantwortet „wer ist das Gegenüber?" als eine **Sammlung von Fakten**, jeder mit seiner Herkunft — nicht als ein verdichtetes „Vertrauenswürdig/Gefährlich".

Faktencheck der Quellen (gegen das reale System geprüft):

- **PTR/Forward** beantwortet „welcher Name gehört zu dieser IP, und bestätigt der Name die IP zurück?" (Forward-Confirmed-Reverse-DNS, Anti-Spoof).
- **RDAP** (`rdap.org` als RIR-toleranter Einstieg, Redirect zur zuständigen Registry) liefert Org/Netname/Netzbereich/Abuse-Kontakt — die Strukturen variieren je RIR stark.
- **TLS-Cert** (roher Handshake) liefert die anzeigbaren Zertifikatsfelder einer Gegenstelle.
- **Geo/ASN** beantwortet „in welchem Land liegt die IP, und zu welcher ASN gehört sie?" — aus **lokalen** Daten, ohne Drittanbieter.

Vier wiederkehrende Spannungen, die dieses ADR auflöst:

1. **Verschmelzen oder nebeneinanderstellen?** — zwei Quellen zum selben Belang (z. B. Land aus RDAP vs. Geo-DB) ergeben oft Widersprüche. Ein „Merge" würde Information vernichten.
2. **Datenhoheit und Lizenz** — die Geo/ASN-Sicht darf weder an einem Drittanbieter (ip-api o. ä.) noch an einer Attributionspflicht hängen.
3. **Wertneutralität** — anders als `security/tls.py` (Grade/Warnings) darf resolver kein Sicherheitsurteil fällen; es stellt fest, es bewertet nicht.
4. **Wo bricht ein Ausfall durch?** — ein fehlendes `dig`/eine fehlende CSV ist ein echter Konfigurationsfehler, kein stiller Leer-Fallback.

## Entscheidung

1. **Fakten-mit-Quelle statt Verschmelzung.** Grundbaustein ist `ResolverFact[T]` (`value`, `source`) — generisch (PEP 695), `value` ehrlich `None`, wenn die Quelle nichts liefert (kein erfundener Wert). Das Aggregat `RemoteEndpointFacts` ist **resolver-eigen**: jedes Feld ist ein `ResolverFact` und trägt seinen eigenen `SourceTag` (`DNS`/`RDAP`/`TLS`/`GEODB`/`DNSDB`). Zwei Quellen zum selben Belang ergeben **zwei Fakten, nicht einen Kompromiss** — der Composition Root entscheidet **nichts** weg.

2. **Vier unabhängige, einzeln abschaltbar gedachte Quell-Ports/-Adapter** (jede Quelle darf fehlen, ohne die anderen zu brechen):
   - **PTR/Forward** (`PtrResolverPort` → `DigDnsPtrResolver`): System-`dig` über stdlib (`subprocess`/`shutil`/`ipaddress`), Konsistenz mit `ss`/`dig`/`traceroute` (ADR 0010/0014). **Bewusst ein eigener, neuer Adapter** — **nicht** der `scanning`-`hostname_resolver`, der an der ADR-0007-`modules`-Ausnahme hängt; resolver bleibt sauber ohne `modules`-Import.
   - **RDAP** (`RdapClientPort` → `RdapClient`): `httpx` über `rdap.org`, `follow_redirects=True`, RIR-toleranter, rekursiver jCard-Walk (die abuse-Entity kann eine Ebene tiefer unter der Org-Entity liegen). Das gesamte Parsen lebt in reinen, gegen unvollständige dicts toleranten Helfern außerhalb der Klasse.
   - **TLS-Cert** (`TlsCertPort` → `TlsCertReader`): stdlib `ssl`/`socket`, **streng fehlertolerant** (jeder Fehlschlag → `None`, nie werfen, nie über das Timeout hinaus blockieren), **wertneutral** — bewusst **kein** Grade/Warning wie `security/tls.py`, nur die Feststellung `self_signed` über `detect_self_signed`. Die ssl-Mechanik ist von `security/tls.py` **nachgebaut, nicht importiert** (independence).
   - **Geo/ASN** (`GeoAsnDbPort` → `CsvGeoAsnDb`): rein lokaler CSV-Reader, `bisect`-Suche über vorberechnete IP-Range-Grenzen. **Synchron** (kein Netz-/Loop-I/O, Muster `VendorLookupPort`).

3. **Datenhoheit/Lizenz: Geo/ASN aus lokalen Dateien, attributionsfrei.** Kein Drittanbieter-Dienst. **Land** aus `asn-country` (CC0). Die **ASN-Nummer** aus `iptoasn-asn` (Public Domain Dedication v1.0, attributionsfrei) — **bewusst nicht** das `asn`-Verzeichnis derselben Quelle (CC BY, Attributionspflicht). `asn_org` (Klartext-Org-Name) kommt **aus RDAP**, nicht aus der DB (Entscheidung A1: attributionsfrei bleiben; der `asn_name` der CSV wird **nicht** verwendet). Die Quelle liefert Land und ASN **nicht vorkombiniert** → **zwei CSV-Familien** (asn-country + iptoasn-asn, je v4/v6), im Reader über die IP-Range gejoint. `fetch_geoasn.py` zieht alle vier CSVs **ohne stillen Fallback** (eine halbe DB ist schlimmer als ein lauter Fehler); die Lizenzlage ist je Quelle in einer `*-LICENSE.txt` dokumentiert.

4. **`country`: RDAP-Land ist unzuverlässig → Land primär aus der Geo-DB; beide bleiben sichtbar.** RDAP-Land ist RIR-abhängig oft leer, darum ist die Geo-DB die primäre Landquelle. Beide Länder bleiben als **getrennte Felder** (`country_rdap_net` vs. `country_geodb`) — keine Verschmelzung. `country_conflict` ist ein **rein berechnetes Flag** (`flag_country_conflict`, Vergleich der bekannten Landquellen, normalisiert), **kein Fact** (nichts stammt aus einer Quelle, sondern aus dem Vergleich). `country_org_address` ist derzeit `None` — es gibt keine separate Org-Adress-Quelle; das Feld bleibt für den Frontend-Katalog erhalten.

5. **`dyndns` ist abgeleitet, kein Lookup.** `derive_dyndns` prüft PTR-Name und TLS-CN gegen eine feste Suffix-Tabelle gängiger DynDNS-Anbieter — ein **Hinweis aus dem Namen**, keine Garantie. **Kein DNSDB-Adapter jetzt**; `SourceTag.DNSDB` ist reserviert für späteres passives DNS (der Tag existiert, wird hier nicht befüllt).

6. **`banner` wird bewusst nicht von resolver befüllt.** Banner-Grabbing ist Zuständigkeit der diagnostics-Domäne (ADR 0014, Block 2a). Das Feld existiert im Aggregat (Frontend-Katalog) und bleibt leer (`value: None`, `SourceTag.DNS`) — **kein Doppeln** des Banner-Grabbings.

7. **Fehler-/Leer-Semantik: fehlertolerant je Adapter, AUSSER zwei echten Konfigurationsfehlern.** Ein leerer/scheiternder Lookup ist ein **gültiger Leer-Zustand**, kein Fehler: leerer PTR → `""`, leerer RDAP → `RdapRawFacts()`, TLS-Fehlschlag → `None`, kein Geo/ASN-Treffer → Feld `None`. **Ausnahmen** (kein stiller Leer-Fallback, S3; bewusst anders als `modules.vendor`): fehlendes `dig` → infra-eigene `ResolverToolMissing`, fehlende Geo/ASN-CSV → `ResolverDataMissing`. Beide bildet der **Composition Root** über je einen globalen `exception_handler` auf **503** ab (Muster `DiagnosticsToolMissing`). Der api-Ring importiert diese Exceptions **nicht** (api → nur application); das Mapping bleibt am Composition Root.

8. **Schichtung über fünf Ringe.** Der Use-Case `ResolveEndpoint` kennt nur `domain` + `ports`, die **vier Ports per Constructor-Injection** (Protocol-Typ, nie ein konkreter Adapter); er ist die **einzige** Stelle, die die Rohfakten zusammenstellt und jedem Feld seinen korrekten `SourceTag` gibt (keine Projektion nötig — das Aggregat ist resolver-eigen). Die vier unabhängigen Quellen laufen nebenläufig (`asyncio.gather`); der synchrone Geo/ASN-Lookup wird über `asyncio.to_thread` aus dem Loop gehoben, die PTR-Kette (PTR → bei Treffer Forward-Abgleich) ist die **eine** ehrlich abhängige Sequenz. `api` ruft nur `application`. `CsvGeoAsnDb` lädt die vier CSVs **einmal beim App-Bau** (`lru_cache`, Muster `scan_history_repository`), nicht pro Request.

## Batch-PTR-Endpunkt für die Verkehrsliste (Paket 5)

Die Verkehrsliste zeigt pro Verbindung eine Gegenstellen-IP — und braucht dort **nur den reverse-DNS-Namen**, nicht die reiche Faktensicht. Würde sie pro Zeile `GET /api/resolve` rufen, liefe je Zeile die teure Mehrfach-Auflösung (RDAP über das Netz, TLS-Handshake, Geo/ASN) — für eine bloße Namensspalte unvertretbar. Darum ein **eigener, schlanker Endpunkt**:

- **`POST /api/resolve/ptr`**, Body `{"ips": [...]}` → Map `{"1.2.3.4": "name", "5.6.7.8": null}`. Bewusst **getrennt** vom reichen `GET /api/resolve`: nur der billige, lokale PTR-Lookup, **kein** RDAP/TLS/Geo. Ein leerer PTR (Port liefert `""`) wird ehrlich zu `null` projiziert; **jede** angefragte IP erscheint als Schlüssel (Vollständigkeit).
- **Wiederverwendung statt Doppelung:** derselbe `PtrResolverPort` (→ `DigDnsPtrResolver`), der schon `ResolveEndpoint` trägt — **keine** neue PTR-/DNS-Logik. Der neue Use-Case `ResolvePtrBatch` nimmt den Port per Constructor-Injection, dedupliziert die IPs intern (gleiche IP nur einmal aufgelöst) und löst die eindeutigen IPs **nebenläufig** (`asyncio.gather`) auf. Der Composition Root reicht **dieselbe** `DigDnsPtrResolver`-Instanz an beide Use-Cases.
- **TTL-Cache (3600 s):** ein prozesslokaler, dict-basierter Cache mit `time.monotonic()`-Ablauf lebt im **application-Ring**, gekapselt im Use-Case-Objekt — er ist Use-Case-**Zustand**, kein Domänen-Wissen und kein Infra-Adapter (kein bestehendes Cache-Muster im Repo, das hier zu folgen wäre). Damit der Cache über Requests greift, hält der Composition Root **eine** langlebige `ResolvePtrBatch`-Instanz. Ein Cache-Treffer überspringt den DNS-Lookup. PTR-Namen ändern sich selten; die Verkehrsliste fragt dieselben IPs in kurzer Folge wiederholt.
- **Validierungsgrenzen (sonst 422):** der Body ist ein api-eigenes pydantic-DTO — `ips` mit `min_length=1`/`max_length=256` (eine /24-Verkehrsliste passt, die Nebenläufigkeit ist gedeckelt), und ein `field_validator` prüft jeden Eintrag über stdlib `ipaddress` auf ein gültiges IP-Literal. Reine Eingabevalidierung im api-Ring, **kein** domain-Import.
- **Kein neuer Domänentyp:** `dict[str, str | None]` genügt; die `"" → None`-Projektion ist dieselbe `or None`-Zeile wie in `ResolveEndpoint` (keine künstliche Domänenfunktion). Die Tool-fehlt-Naht (`dig` fehlt → `ResolverToolMissing` → 503) gilt unverändert über denselben globalen Handler.

## Konsequenzen

**Positiv**
- **Alleinstellungsmerkmal:** zu einer nackten IP entsteht eine reiche Faktensicht (Name, Org, Netz, ASN, Land, Abuse, TLS-Cert) — selbst ermittelt, mit Quelle je Feld.
- **Datenhoheit:** Geo/ASN aus lokalen, attributionsfreien Dateien (CC0 + PDDL) — kein Drittanbieter-Dienst, keine Namensnennungs-Auflage.
- **Neutral statt urteilend:** keine Verschmelzung, kein Grade; Widersprüche (RDAP-Land vs. Geo-Land) bleiben sichtbar, `country_conflict` zeigt sie nur an. Das Einordnen bleibt dem Frontend/späteren Ringen.
- **Erweiterbar:** der reservierte `SourceTag.DNSDB` + die abschaltbar gedachten Ports machen einen späteren passiven-DNS-Adapter zu einem lokalen Anbau, kein Umbau.

**Kosten / Grenzen (nicht verlieren)**
- **Attribution:** aktuell **keine** nötig (CC0 + PDDL gewählt). Würde später doch ein ASN-Org-Name aus einer CC-BY-Quelle gewünscht, käme die **Attributionspflicht** mit hinein — das ist der Grund, warum `asn_org` heute aus RDAP kommt.
- **Frontend offen:** die Wire-Form `{value, source}` muss ans LookupPanel angebunden werden; die Standort-Begriffe (RDAP/Org/GeoDB) sind im Handbuch zu verlinken, sobald ein Handbuch existiert.
- **Geo/ASN-DB-Pflege:** der Stand altert — regelmäßiges Update über `fetch_geoasn.py` (kein Automatismus, bewusst manuell).
- **DNSDB/passives DNS** als künftiger eigener Adapter offen (gleiche Datenhoheitsfrage wie cpnetcheck — eigene vs. fremde Quelle).
- **`service_hint` und `country_org_address`** tragen derzeit den DNS- bzw. RDAP-Tag als neutralen lokalen/Quellen-Bezug (`service_hint` ist eine lokale Port→Dienst-Ableitung, `country_org_address` ist mangels separater Quelle ein `None`-Fact unter RDAP). Falls später feiner gewünscht (eigener „lokal-abgeleitet"-Tag bzw. eine echte Org-Adress-Quelle), ist das hier nachzuziehen.
- **Parser an die `dig`-/RDAP-/Cert-Ausgaben gebunden:** robust gegen leere/teilweise Antworten getestet (1502 Tests, 5 Gates grün), aber an die realen Tool-/RIR-Strukturen gekoppelt — gekapselt in den reinen Helfern, ohne echtes Netz-/Subprocess-I/O testbar (Sprach-Wechsel bleibt ein lokaler Eingriff im jeweiligen Adapter).
- **Kein neuer import-linter-Contract außer der `independence`-Zeile** — `domain.resolver` reiht sich in den bestehenden Contract ein (importiert **keine** andere `domain`-Subdomäne; die Roh-Port-Typen `RdapRawFacts`/`GeoAsnRecord` leben in `domain.resolver`, `ports.resolver` importiert sie von dort). Der Use-Case importiert nur `domain.resolver` + `ports.resolver` (beides erlaubt); kein `infrastructure`-Import im api-Ring.
