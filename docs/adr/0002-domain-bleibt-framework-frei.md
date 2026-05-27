# ADR 0002 — Die Domain bleibt framework-frei (stdlib-only)

- **Status:** Akzeptiert
- **Datum:** 2026-05-27
- **Phase:** Phase 1, Schritt 6 (vor der domain-Implementierung)
- **Bezug:** CLAUDE.md Importregel 1 (`domain/` → nur `domain/` + stdlib); `vision_features_202605.md` §5.2 (Sprachwechsel hinter Ports), §6.2 (`analysis` als reiner Domänen-Kern)

## Kontext

Wir bauen pragmatisch-hexagonal (drei Ringe). Vor der Implementierung der ersten echten Domäne (`settings`) stellte sich die Frage: Darf `domain/` Frameworks nutzen — konkret **Pydantic** für Validierungs-/Wertobjekte?

- **Strenge Lehre:** Die Domäne hat keine Framework-Abhängigkeit, also reine `dataclass` + stdlib.
- **Pragmatische Lehre:** Pydantic ist „nahe genug" an stdlib, Validierung ist Domänenlogik — also erlaubt, nur ohne HTTP-spezifische Serializer.

Die dokumentierte Regel 1 (`domain/` nur `domain/` + stdlib) spricht für die strenge Variante; die pragmatische würde sie aufweichen. `import-linter` erzwang bisher nur die Ring-Trennung, nicht „nur stdlib".

## Entscheidung

**Die Domain bleibt framework-frei: stdlib + `dataclasses`, keine Abhängigkeit von `pydantic`, `fastapi` oder `structlog`.** Validierung erfolgt als Domänenlogik über `@dataclass` + `__post_init__` mit explizitem `raise ValueError`.

Schicht-Mapping:
- **domain** = dataclasses (+ stdlib), Validierung in `__post_init__`
- **ports** = `typing.Protocol` (stdlib)
- **application** = arbeitet auf domain-dataclasses
- **api** = Pydantic (Request/Response-DTOs)
- **infrastructure** = Pydantic erlaubt (z. B. `pydantic-settings` für Config)

Begründung (vier Punkte):
1. **Geschriebene Regel.** Regel 1 sagt explizit „nur stdlib". Pydantic ist Framework — die pragmatische Variante bräche die dokumentierte Architektur.
2. **Eigenes Prinzip.** „Regeln, die gelten sollen, müssen maschinell erzwungen sein." Die Grenze „Pydantic ja, aber keine HTTP-Serializer" ist nicht maschinell prüfbar (Ermessensfrage), eine harte Linie schon.
3. **Sprachwechsel-Asset.** Die Domain ist laut Vision §5.2/§6.2 die portierbare Schicht. Eine Bindung an Pydantic-v2 (Major-Sprünge bereits erlebt) verbaut das. Framework-frei = portierbar.
4. **Sauberer Schnitt ohne Verlust.** `dataclass` + `__post_init__` leistet Validierung transparenter als Pydantics implizite Typ-Koersion.

**Zu `structlog` im Verbot:** Die Domain **loggt nicht**. Sie ist seiteneffektfreie Logik, die Daten zurückgibt oder Domänenfehler wirft; *was* protokolliert wird, entscheiden application/infrastructure. Eine loggende Domain hätte einen verborgenen Seiteneffekt (schadet Testbarkeit) und eine Python-spezifische Bindung — genau das, was Punkt 3 vermeiden will. Daher ist `structlog` ebenso verboten wie `pydantic`/`fastapi`.

**Maschinelle Durchsetzung:** Ein `import-linter`-Contract verbietet `domain` den Import von `pydantic`, `fastapi`, `structlog`. Damit ist „domain bleibt rein" für die realistischen Versuchungen geprüft, nicht nur gut gemeint.

## Konsequenzen

**Positiv**
- Regel 1 maschinell abgesichert; Domain framework-frei und portierbar (Vision §5.2).
- Validierung explizit und transparent (`__post_init__`), kein verstecktes Koersions-Verhalten.
- Konsistenz vor Pragmatismus — keine Ermessensgrenze, die unter Druck verwischt.

**Kosten**
- Keine Pydantic-Bequemlichkeit in der Domäne; `api/` braucht eigene DTOs und ein Mapping domain ↔ DTO.
- Der Contract deckt die heute genutzten Frameworks ab, nicht „jedes denkbare Drittpaket" — bei neuen Frameworks ist die Liste zu ergänzen.
