# ADR 0003 — `allow_indirect_imports` am api-Contract

- **Status:** Akzeptiert
- **Datum:** 2026-05-28
- **Phase:** Phase 1, Schritt 6f (API-Router + Verdrahtung der settings-Domäne)
- **Bezug:** CLAUDE.md Importregel 4 (`api/` → ruft nur `application/`); `pyproject.toml` `[tool.importlinter]`; ADR 0002 (Schicht-Mapping)

## Kontext

Der `import-linter`-Contract „api ruft nur application (nicht domain/ports/infrastructure direkt)" ist vom Typ `forbidden` und verbietet `api` den Import von `domain`, `ports`, `infrastructure`.

In Schritt 6f importiert `api/settings.py` erstmals aus `application/` (die drei Use-Cases). `application/` kennt — wie es die Schichtung vorsieht — `domain/` und `ports/`. Damit entsteht die **indirekte** Kette `api → application → domain` bzw. `api → application → ports`.

`forbidden`-Contracts prüfen standardmäßig **auch indirekte** Ketten. Folge: Die völlig normale, gewollte Schichtungs-Durchreichung (api ruft application, application kennt domain/ports) wurde als Vertragsverletzung gemeldet:

```
api is not allowed to import domain:
-   api.settings -> application.settings
    application.settings -> application.settings.use_cases
    application.settings.use_cases -> domain.settings
```

Ohne Gegenmaßnahme wäre saubere Schichtung als Verstoß markiert worden — der Contract-Name sagt aber ausdrücklich „nicht … **direkt**".

## Entscheidung

**`allow_indirect_imports = true` wird NUR am api-Contract gesetzt.** Die Option entschärft ausschließlich indirekte Pfade dieses einen Contracts; alle anderen Contracts bleiben unverändert (prüfen weiter direkt **und** indirekt).

Damit prüft der api-Contract nur noch **direkte** Importe von `domain`/`ports`/`infrastructure` aus `api` — genau das, was Regel 4 meint. Die indirekte Durchreichung über `application` ist erlaubt, weil sie die vorgesehene Schichtung ist.

## Konsequenzen / Sicherheitsnachweis

Das `infrastructure`-Verbot für `api` bleibt **lückenlos** — bewiesen durch drei temporäre Verletzungen (jeweils `uv run lint-imports`, danach zurückgebaut):

1. **Direkt `api → infrastructure`** (Test-Import in `api/settings.py`): **BROKEN.** Der api-Contract greift trotz `allow_indirect_imports` — direkte Importe werden weiterhin gefangen.
2. **`application → infrastructure`** (Test-Import in `application/settings/use_cases.py`): **BROKEN** über den eigenen Contract „application kennt nicht infrastructure/api" — dieser hat die Option **nicht**.
3. **Indirekt `api → application → infrastructure`** (Kombination aus 2, da `api` bereits `application` importiert): **BROKEN an der Mittelkante** (Fall 2). Der api-Contract bleibt hier `KEPT`, aber die gefährliche Kante `application → infrastructure` wird unabhängig gefangen.

**Fazit:** `allow_indirect_imports` entschärft nur die gewollte Durchreichung `api → application → domain/ports`. Jede `infrastructure`-Leak-Kette bleibt gefangen — direkt am api-Contract, indirekt an der `application → infrastructure`-Kante. Eine indirekte `api → infrastructure`-Durchreichung ist strukturell unmöglich, weil die einzige Brücke (`application → infrastructure`) ihrerseits verboten ist.

**Positiv**
- Saubere Schichtung wird nicht mehr fälschlich als Verstoß gemeldet.
- Regel 4 wird maschinell in ihrer eigentlichen Bedeutung („kein **direkter** Zugriff") geprüft.

**Kosten / Grenzen**
- Die Option gilt pauschal für alle indirekten Pfade des api-Contracts. Das ist hier unkritisch, weil der einzige denkbare gefährliche Pfad (`api → … → infrastructure`) bereits durch einen anderen, options-freien Contract abgedeckt ist. Bei künftigen Schichten ist diese Annahme erneut zu prüfen.
