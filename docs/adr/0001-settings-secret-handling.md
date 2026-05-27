# ADR 0001 — Secret-Handling der settings-Domäne

- **Status:** Akzeptiert
- **Datum:** 2026-05-27
- **Phase:** Phase 1, Schritt 6 (settings als Referenz-Migration)
- **Bezug:** Findings S1/S3 (`vision_features_202605.md` §1.2), `phase0_ist_analyse.md` §6, Characterization-Tests Schritt 5

> Erstes ADR des Rewrites. Etabliert zugleich das Format (Nygard: Kontext → Entscheidung → Konsequenzen), an dem sich alle weiteren ADRs orientieren.

## Kontext

Die settings-Funktion in v1 (`modules/storage.py`, `modules/crypto.py`, Endpunkte in `main.py`) gibt Secrets preis und enthält stille Fallbacks. Drei konkrete, S3-nahe Befunde — die letzten beiden sind erst durch die Characterization-Tests in Schritt 5 belegt:

1. **Stiller Crypto-Fallback** (`crypto.py`): `encrypt()` gibt bei jeder Exception den **Klartext** zurück; `decrypt()` akzeptiert Klartext als „legacy"; zusätzlich `b64:`-Obfuskation als Schein-Sicherheit. Folge: Bei jedem Crypto-Fehler werden Secrets unbemerkt im Klartext gespeichert (`phase0` §6: „schlimmer als notiert").
2. **`get_all_settings`-Crash** (`storage.py`): `GET /api/settings` nutzt `get_all_settings()`, das `json.loads` über **jeden** Wert ohne `try/except` ausführt. Ein einziger Nicht-JSON-Wert lässt den gesamten Endpunkt mit `JSONDecodeError` scheitern — inkonsistent zum toleranten `get_setting` (Characterization Schritt 5).
3. **Stiller Roh-Fallback** (`storage.py` `get_setting`): Nicht-JSON-Werte werden ohne Signal als Rohstring zurückgegeben — genau die „stillen Fallbacks", die CLAUDE.md verbietet. Ein Legacy-Klartext-Secret liefe unbemerkt durch (Characterization Schritt 5).

Zusätzlich liefert `GET /api/settings` **alle** Settings inklusive Secret-Keys (`shodan_api_key`, `smtp_config`, `fritz_password`) — im Klartext bzw. verschlüsselt (Finding S1/S3).

**Frontend-Realität** (Schritt-0-Analyse, im Code verifiziert): Das Frontend liest aus `GET /api/settings` beim Secret nur die **Existenz** (`if (d.shodan_api_key) …`), nie den Wert. Secrets aus der Antwort zu redigieren bricht das Frontend also nicht.

## Entscheidung

1. **Typisiertes Settings-Modell** statt freiem KV-Blob. Die Domäne modelliert Settings als typisierte Werte (reine dataclasses, siehe ADR 0002). Secret-Keys werden explizit klassifiziert, nicht implizit erkannt.
2. **Eigener `SecretStore`-Port**, getrennt vom `SettingsRepository`-Port. Secrets laufen über einen eigenen Vertrag mit Keystore-/Crypto-Adapter; normale Settings über das Repository. Trennung von Daten und Geheimnissen ist explizit und maschinell sichtbar.
3. **Redaction in `GET`**: `GET /api/settings` liefert für Secret-Keys nur einen **maskierten Platzhalter** (truthy, wenn gesetzt; leer/abwesend, wenn nicht) — niemals Klartext. Kompatibel mit der Präsenzprüfung des Frontends. Setzen erfolgt über dedizierte `PUT`-Pfade.
4. **Keine stillen Fallbacks**: Crypto- und Deserialisierungs-Fehler sind **Fehler** (explizite Exception), kein leiser Rückfall auf Plaintext/Rohwert. Der `b64:`-Schein und der Plaintext-Fallback aus `crypto.py` werden **nicht** nachgebaut. Robustes, einheitliches Deserialisieren beseitigt den `get_all_settings`-Crash und den Roh-Fallback.

## Konsequenzen

**Positiv**
- S1/S3 adressiert: keine Klartext-Secrets im API-Response, keine stillen Fallbacks.
- Robustes Deserialisieren: der `get_all_settings`-Crash kann nicht mehr auftreten.
- Klare Trennung Setting vs. Secret — als Port-Vertrag, nicht als Konvention.
- Referenzmuster (zwei Ports, zwei Adapter) für alle weiteren Domänen-Migrationen.

**API-Vertragsänderung**
- `GET /api/settings` liefert für Secret-Keys maskierte Werte statt Klartext. **Frontend-kompatibel** (prüft nur Präsenz). Bewusste, dokumentierte Vertragsänderung im Sinne von „API-Verträge dürfen brechen".

**Kosten / Migration**
- Zwei Ports + zwei Adapter statt eines Moduls — Mehraufwand, gerechtfertigt durch den Referenz-Charakter.
- Strangler: Alter Endpunkt sowie `storage.py`/`crypto.py` bleiben in Schritt 6 **parallel** bestehen, weil andere Module (fritz, monitor, smtp …) `get_setting`/`set_setting` direkt nutzen. Löschung erst, wenn diese Konsumenten migriert sind.
