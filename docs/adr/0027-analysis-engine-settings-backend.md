# ADR 0027 — Auffälligkeits-Engine konfigurierbar: Schwelle + zwei Portlisten als Settings, breiter Service-Lookup

- **Status:** Akzeptiert
- **Datum:** 2026-06-16
- **Phase:** Grüne Wiese — Quer-Feature nach Stabilisierung des Bestands. Reine **Backend-Vorarbeit** für die spätere Einstellungs-UI: kein Frontend, keine UI. Verdrahtung ausschließlich im Composition Root (`backend/app.py`), Service-Mapping als reine Daten in der `analysis`-Domäne.
- **Bezug:** ADR 0023 (per-Settings deaktivierbare Regeln — identisches defensives Settings-Lese-Muster und Provider-Ketten-Prinzip im Composition Root); ADR 0024 (`host_many_high_ports`-Schwelle als Regel-Parameter); ADR 0025 (`host_backdoor_port`-Backdoor-Portmenge, die hier zum kritisch-Default wird); ADR 0002 (domain framework-frei); Konzept §5/§7.

## Kontext

Die Auffälligkeits-Engine ist heute starr: die `host_many_high_ports`-Schwelle (`threshold=10`, ADR 0024) und die Bewertungs-Portmengen stehen als Literale in `domain/analysis/rules.py`. Die spätere Einstellungs-UI (eigener Schnitt) soll dem Nutzer erlauben, diese Werte zu ändern — und beim Eintippen eines Ports sofort den Service-Namen zu zeigen.

Drei Anforderungen, alle **rein backend-seitig** vorzubereiten:

1. Ein breites, kuratiertes **Port→Service-Mapping** plus Lookup-Endpunkt, damit die UI zu einem eingegebenen Port den gängigen Service-Namen zeigen kann.
2. Die **`host_many_high_ports`-Schwelle** aus dem Code in ein Setting lösen.
3. Die zwei **Bewertungs-Portlisten** (auffällig / kritisch) als Settings konfigurierbar machen, mit Built-in-Defaults als Fallback.

Konzept §7 hält außerdem fest, dass die bestehende `host_remote_access_port`-Regel (vier reine Fernzugriffs-Ports 22/3389/5800/5900) **„zu grob"** ist. Sie wird im Zuge dieser Konfigurierbarkeit zur datengetriebenen auffällig-Regel umgebaut.

Die rote Linie bleibt (ADR 0012/0022): `analysis` urteilt nie. Ein Service-Name wie eine Portliste ist eine wertneutrale Einordnung, kein moralisches Urteil.

## Entscheidung

1. **SERVICE-MAPPING ALS REINE DATEN IN DER DOMÄNE.** Neue Datei `domain/analysis/services.py`: ein statisches `dict[int, str]` (~90 kuratierte IANA-Well-Known- + gängige Registered-/Heimnetz-/Selfhoster-Ports) plus `service_for_port(port: int | None) -> str | None`. Framework-frei (ADR 0002), **kein** `/etc/services`-Parse — das wäre plattform- und frozen-build-unsicher; die Tabelle ist bewusst statisch in den Code kuratiert, damit sie im gebündelten Build identisch verfügbar ist. Ein nicht gelisteter Port → `None` (gültiger Leer-Zustand, kein Fehler). `None` → `None`.

2. **LOOKUP-ENDPUNKT, DOMAIN-FREI VERDRAHTET.** `GET /api/analysis/service?port=N` → `{"port": N, "service": "mysql"}` bzw. `{"port": N, "service": null}` für Unbekannte. Der `api`-Ring darf `domain` nicht importieren (import-linter: api → nur application); deshalb kommt der Lookup wie jeder andere Runner als Composition-Root-verdrahtetes Callable (`ServiceLookupRunner`) per FastAPI-Dependency herein — der Composition Root reicht den reinen domain-`service_for_port` heraus. Port-Range **1–65535** wird per FastAPI-`Query(ge=1, le=65535)`-Constraint erzwungen; außerhalb → HTTP 422, **kein** stiller Fallback (S3). Der Endpunkt ist ein **Lookup, kein Setting**.

3. **SCHWELLE + ZWEI PORTLISTEN ALS SETTINGS-KEYS.**
   - `analysis_port_count_threshold` (Integer, Default 10) → `threshold` der Regel `host_many_high_ports`.
   - `analysis_suspicious_ports` (JSON-Array von Integern) → `ports` der Regel `host_remote_access_port`.
   - `analysis_critical_ports` (JSON-Array von Integern) → `ports` der Regel `host_backdoor_port`.

4. **`host_remote_access_port` DATENGETRIEBEN UMGEBAUT — RÜCKWÄRTSKOMPATIBEL.** Die Regel bekommt eine breitere, kuratierte 16er-Default-Portmenge (21, 23, 139, 445, 2049, 3306, 3389, 5432, 5800, 5900, 5984, 6379, 8080, 8443, 9200, 27017). **SSH 22 ist bewusst NICHT dabei** — zu alltäglich, sonst nur Lärm. Titel/`detail_template` lauten jetzt „auffälliger Port" statt nur „Fernzugriff". **`id` UNVERÄNDERT** (`host_remote_access_port`), ebenso `kind` (`host_remote_port`) und `severity` (`notable`): der Deaktivierungs-Filter (ADR 0023) und die spätere Acknowledge-Historie referenzieren die `id`, die darf nicht brechen. Die connection-seitige Schwester-Regel `remote_access_port` (Verbindung ZU einem Fernzugriffs-Port, aus traffic) bleibt **unangetastet** mit ihren vier Ports.

5. **INJEKTION IM COMPOSITION ROOT, KEINE DOMÄNEN- ODER ENGINE-ÄNDERUNG.** Ein neuer Wrapper-Provider `_ConfiguredRuleProvider` lebt — wie `_CompositeRuleProvider`/`_FilteredRuleProvider` (ADR 0023) — im Composition Root und erfüllt strukturell `ports.analysis.RuleProvider` (`get_rules() -> tuple[Rule, ...]`). Er liest die drei Settings defensiv, erzeugt per `dataclasses.replace` eine Kopie der betroffenen Default-Regel mit überschriebenem Parameter und reicht alle anderen Regeln unverändert durch. Die **Built-in-Regeln im Code bleiben unangetastet**; die Engine und die Domäne werden **nicht** verändert. Provider-Kette: `Composite (Defaults + User) → Configured (Override) → Filtered (deaktivierte raus)`.

6. **DEFENSIVES LESEN, S3-KONFORM.** Gleiches Muster wie `_load_custom_targets` + `_FilteredRuleProvider._disabled_rule_ids` (ADR 0023): fehlender Key / falscher Typ → Built-in-Default (kein Log, frische DB ist normal); kaputtes JSON (`CorruptSettingError`) → **geloggte Warnung** + Built-in-Default. Eine kaputte Komfort-Einstellung darf den Scan **nicht** fällen. Ein **leeres Array** ist ein **gültiger** Wert (= „diese Regel trifft nichts"), **kein** Rückfall auf den Default. Bei der Integer-Schwelle und den Port-Einträgen wird `bool` (Subtyp von `int`) bewusst ausgeschlossen, damit `True`/`False` nicht versehentlich als Schwelle/Port zählen.

## Abgrenzung

Dies ist **reine Backend-Vorarbeit** — kein Frontend, keine UI, kein Schreibpfad für die neuen Settings über die API (die UI dockt später lesend/schreibend über die bestehenden Settings-Endpunkte an). Es wird nichts vorgebaut, was die UI nicht braucht. Das Service-Mapping ist bewusst **knapp und kuratiert**, keine vollständige IANA-Registry.

## Konsequenzen

**Positiv**
- **UI kann später rein andocken:** der Service-Lookup ist da, die drei Settings-Keys sind definiert und werden defensiv gelesen — die UI muss nur die bestehenden Settings-Endpunkte schreiben/lesen.
- **Built-in-Regeln im Code unangetastet:** die Konfigurierbarkeit lebt vollständig im Composition Root (Provider-Wrapper + `dataclasses.replace`); `domain/analysis/rules.py` ändert sich nur in den Built-in-Defaults von `host_remote_access_port` (datengetriebener Umbau, stabile `id`).
- **Keine Domänen-/Engine-Kopplung:** keine neue `kind`, kein neuer Dispatch-Zweig; die Engine sieht weiterhin nur `Rule`-Datenobjekte.
- **Fail-safe:** kaputte/falsch getippte Settings führen zum Built-in-Default mit geloggter Warnung, nie zum Scan-Abbruch (S3).
- **Rückwärtskompatibilität:** stabile Regel-`id` schützt Deaktivierungs-Filter und spätere Acknowledge-Historie.

**Offen / später**
- **Schreibpfad/UI** für die drei Settings — eigener Schnitt (Einstellungs-UI).
- **Pflege des Service-Mappings** (weitere Ports) ist eine reine Datenänderung in `services.py`, kein Architektur-Eingriff.
