# ADR 0011 — process-Domäne: Prozess-Sicht aus /proc (Stufe 1)

- **Status:** Akzeptiert
- **Datum:** 2026-06-10
- **Phase:** Grüne Wiese (dritte neue Domäne nach interfaces + traffic), Schritte P.1–P.4
- **Bezug:** `vision_features_202605.md` §6 (Prozess-Sicht aus `/proc`); ADR 0009 (interfaces als Fünf-Ringe-Muster); ADR 0010 (traffic: Rechte-Port-Vorbild, rootless-Naht, Adapter-Schablone); ADR 0002 (domain bleibt framework-frei); CLAUDE.md (keine stillen Fallbacks, Finding S3)

## Kontext

Die Prozess-Sicht ist die **Datenquelle, auf der die kommende analysis-Domäne aufsetzt** (die interpretierende Schicht über scanning/traffic/process). Eigenständiger Nutzwert schon hier: die Brücke **„welcher Prozess / Owner / Eltern-Kette steckt hinter dem Netzwerk-Verkehr"** — die Ergänzung zu traffic, das fremde Sockets nur als `pid=None` kennt.

Faktencheck der `/proc`-Quelle (gegen das reale System geprüft, 349 Prozesse):

- `psutil.process_iter` sieht **ALLE** Prozesse rootless (`pid`/`name`), aber die Detailfelder fremder Prozesse (`owner`/`status`/`create_time`/`cmdline`) werfen je nach `/proc`-Mount `AccessDenied`. Die **eigenen** Prozesse sind voll lesbar.
- Kernel-Threads hängen an `kthreadd` (pid 2) und haben ein **leeres** `cmdline` (kein Userspace-Programm).

Bewusst **kleiner Schnitt**: kein Permissions-Modell wie bei traffic (kein CAP-Pfad — die `/proc`-Sicht hängt an **echtem Root / euid 0**, nicht an einer Netz-Capability), kein Pflicht-Poller (reine Lese-Sicht, kein lebender State).

## Entscheidung

1. **Vollwertige process-Domäne über alle fünf Ringe** nach dem interfaces/traffic-Muster. `domain/process.py`: frozen `ProcessInfo` + `ProcessNode`, Alias `ProcessKind` (`Literal["kernel", "userland"]`), reine Funktionen `classify_kind` + `build_process_tree` — kein I/O, keine Uhr (`create_time` als Feld).

2. **`classify_kind`-Heuristik:** Kernel-Thread = leeres `cmdline` **UND** (`pid == 2` **ODER** `ppid == 2`). Beide Bedingungen nötig — ein leeres `cmdline` allein kann auch „nicht lesbar" heißen.

3. **`build_process_tree` baut einen deterministischen Wald** (nach `pid` sortiert), zyklen- und selbstreferenz-sicher (besuchte `pid` werden nicht erneut eingehängt — kein `RecursionError`). Verwaiste Prozesse (`ppid` zeigt ins Leere) werden ehrlich zu Wurzeln, nicht verworfen.

4. **EIN Daten-Port** `ProcessProvider` (`async list_processes`) + **eigener Rechte-Port** `ProcessPermissionPort` (synchron, Muster traffic). Beide `Protocol`, kein `@runtime_checkable`.

5. **Rootless-Naht wie traffic, aber feldweise:** der Adapter (`PsutilProcessAdapter`) liest jedes Detailfeld defensiv (`_safe` gegen `psutil.Error`) und setzt bei `AccessDenied`/`NoSuchProcess`/`ZombieProcess` ehrlich `None` bzw. leer — der Prozess bleibt in der Liste, nichts wird erfunden oder weggeworfen. `name` ist nie `None` (Fallback `""`).

6. **Rechte-Port:** volle Sicht = `geteuid() == 0` (Root sieht alle `/proc`-Felder). Sonst ein handlungsorientierter Hinweis (eigene Prozesse bleiben sichtbar), kein stiller Fallback (S3). Plattform-Riegel (`is_available`) auf Linux.

7. **`ListProcesses` bietet BEIDE Sichten als zwei Methoden** (Karl-Entscheidung): `flat()` (flache Liste) und `tree()` (Wald). `GET /api/processes?view=flat|tree` mit **PFLICHT-Parameter** `view` — bewusste Nutzerwahl, FastAPI lehnt fehlend/ungültig mit 422 ab (Vision „Wahlfreiheit wo sie Kontrolle gibt").

8. **`kind` (das `classify_kind`-Ergebnis) ist in P.3 BEWUSST NICHT in der Wire-Form** — der api-Ring darf `domain` nicht importieren, eine künstliche Anreicherung wäre über den Schnitt hinaus. `classify_kind` ist gebaut und getestet; die Wire-Nutzung folgt, wenn das Frontend (oder analysis) sie braucht.

9. **`independence`-Contract um `interfaces`, `traffic`, `process` erweitert** (dieser Schnitt, P.4): die drei grüne-Wiese-Domänen fehlten im Contract — ein versehentlicher Querimport (z. B. `domain.process` → `domain.traffic`) wurde bisher nicht gefangen. Jetzt maschinell erzwungen (CI-enforced Domänen-Isolation über ALLE domain-Subpackages).

## Konsequenzen

**Positiv**
- Die Datenquelle für analysis steht; die Domänenlogik (Klassifikation, Baum) ist testbar an **einer** Stelle, die fünf Ringe sind sauber (8/8 import-Contracts kept, 1046 Tests).
- **Ehrliche rootless-Darstellung:** fremde Prozesse bleiben sichtbar (Felder `None`, wo nicht lesbar), kein erfundener Wert, kein Wegwerfen — derselbe Anspruch wie die None-Gruppe bei traffic.
- **Wahlfreiheit flach/Baum** als bewusste Nutzerentscheidung statt verstecktem Default.
- Die Domänen-Isolation ist jetzt **lückenlos maschinell abgesichert** (Lücke bei P.2 gefunden, hier geschlossen).

**Kosten / Grenzen**
- **psutil-Abhängigkeit** (schon vorhanden); die rootless-Lücke ist **mount-abhängig** (ohne `hidepid` sind auf manchen Systemen mehr Felder lesbar als auf anderen) — der Adapter ist korrekt, die Sichtbarkeit hängt am System.
- **`kind` noch nicht im Wire** (bewusst zurückgestellt, eigener späterer Schritt).
- **Kein Live-Update der Prozessliste** (reine Pull-Sicht pro Request, kein Poller — bewusst, im Gegensatz zu traffics Durchsatz-Poller).
