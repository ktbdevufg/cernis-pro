# ADR 0009 — interfaces-Domäne: Klassifikation und Primary-Auswahl ins Backend

- **Status:** Akzeptiert
- **Datum:** 2026-06-05
- **Phase:** Grüne Wiese (erste neue Domäne nach ADR 0004), Schritte I.1–I.4
- **Bezug:** löst den `/api/interfaces`-Übergangs-Endpunkt (ADR 0004 P.1) ab; `vision_features_202605.md` §3.4 (Sprache statt Symbole, einordnen); CLAUDE.md (pragmatisch hexagonale Architektur, „keine stillen Fallbacks", Finding S3); ADR 0006 (Migrationsreihenfolge — interfaces als erste der neuen Domänen)

## Kontext

Mit ADR 0004 (P.1) wurde `/api/interfaces` bewusst als **Übergangs-Krücke** angelegt: ein modules-freier, Linux-only Adapter (`infrastructure/interfaces.py`), der dem Frontend die Interface-Liste liefert, OHNE eigene Domäne, ohne Port, ohne Use-Case. Das war für den Einstiegspunkt-Wechsel (`main:app` → `app:app`) richtig — die Krücke sollte aber, sobald die neuen Domänen drankommen, durch eine vollwertige interfaces-Domäne ersetzt werden.

Diese Krücke trug drei Mängel, die der Rewrite strukturell beseitigt:

- **Geschäftslogik im Darstellungs-Layer.** Die fachliche Frage „welches ist das primäre Interface?" lag im Frontend: `App.jsx` riet „erstes mit `ipv4 && gateway`, sonst `interfaces[0]`". Das ist genau der Befund-Typ (A1/A3 der Ist-Analyse), den der Rewrite aus der Darstellung herausziehen soll.
- **Stille Annahme statt ehrlichem Status.** `is_up` war im Übergangs-Adapter **hardcodet `True`** — ein toter Pfad, der dem Vorzeige-Anspruch „keine stillen Annahmen" (Finding S3) widerspricht.
- **Klassifikation im Adapter vermischt mit I/O.** Die Typ-Heuristik (`hw_type`/`hw_icon`) hing im systemnahen Adapter zwischen `/sys`-Reads — nicht testbar, nicht an einer Stelle.

interfaces ist zudem die kleinste, am besten geeignete erste grüne-Wiese-Domäne: self-contained, ohne Quer-Abhängigkeiten zu noch nicht migrierten Domänen, mit einem bereits laufenden Endpunkt als Referenz für die Wire-Form.

## Entscheidung

1. **Vollwertige interfaces-Domäne über alle fünf Ringe** (`domain`/`ports`/`application`/`infrastructure`/`api`). Das etabliert das Muster **„Übergangs-Krücke → echte Domäne"** als Schablone für die folgenden grüne-Wiese-Domänen (traffic/process/analysis).

2. **Fachliche Einordnung entsteht im Backend**, als reine, getestete Domänenfunktionen (`domain/interfaces.py`):
   - `classify_type` — Namens-Heuristik (`wl`→wifi, `eth`/`en`→ethernet, `lo`→loopback usw.), Loopback als präzises Muster (`lo` exakt oder `lo`+Ziffern, nicht startswith — sonst Fehlmatch auf `london0`).
   - `classify_status` — `up`/`down`/`no_ip` aus `is_up` + `has_ipv4`.
   - `select_primary` — deterministische Default-Route-Auswahl (Schablone `select_rules_to_fire` aus alerting): erster Kandidat in Eingangsreihenfolge, gibt den Namen zurück; `mark_primary` setzt die Flags konsistent.

   Das Frontend liest danach `is_primary`, statt selbst zu raten.

3. **Echter Interface-Status** aus `/sys/class/net/{name}/operstate` (`parse_operstate`: alles außer explizitem `down` gilt als up — der `unknown`→`True`-Fallback ist dokumentiert und regressionsfrei gegenüber der Krücke) statt hardcodetem `True`.

4. **Ableitbare Anzeige-Felder** (`subnet_cidr`/`broadcast`/`network`) entstehen im **api-Serialisierer** (stdlib `ipaddress`), NICHT in Domäne oder Adapter. Schichttrennung: der Adapter **misst** (rohe Felder + `network_cidr`/`host_count`, die die Domäne führt), die Domäne **klassifiziert** (type/status/is_primary), die api **formatiert** (abgeleitete Anzeige + Wire-Form). Discovery-I/O bleibt Loop-frei (`run_in_executor`, Schablone `arp_table`-Adapter).

5. **Darstellungs-Artefakte** (Icons, `hw_icon`) gehören NICHT in die Domäne (Vision §3.4: Sprache statt Symbole). Das Frontend liest sie nachweislich nicht — sie entfallen ersatzlos.

## Konsequenzen

**Positiv**
- Die Geschäftslogik (Typ/Status/Primary) ist testbar und liegt an **einer** Stelle (Domäne), statt im Frontend dupliziert. Mutationsproben (I.1) belegen, dass der Primary-Tie-Break und die Status-Ableitung beim Kaputtmachen rot werden.
- **Ehrlicher Status** statt totem `True`: ein `down`-Interface wird als `down` erkannt.
- Discovery ist Loop-frei (`run_in_executor`) — der systemnahe `ip`-/`/sys`-Aufruf blockiert den Event-Loop nicht.
- Das Muster „Krücke → Domäne über fünf Ringe" steht als Schablone für die kommenden Domänen; die import-linter-Contracts (8/8 kept) sind unberührt.
- Das Frontend hört auf, fachliche Auswahl zu duplizieren — es liest nur noch `is_primary`.

**Kosten / Verhaltensänderung**
- `select_primary` ist **strenger** als das alte Frontend-Raten: es schließt zusätzlich `!is_up` und Loopback aus. Ein Interface mit `ipv4 + gateway`, aber `operstate=down`, wird jetzt **nicht** mehr als Primary gewählt (vorher schon, weil das Raten nur `ipv4 && gateway` prüfte und `is_up` ohnehin hardcodet `True` war). Das ist **gewollt** — ein down-Interface taugt nicht als Scan-Quelle —, aber eine bewusste Verhaltensänderung gegenüber der Krücke.
- Die Wire-Form bleibt **rückwärtskompatibel**: alle bisher gelesenen Felder bleiben, die neuen (`is_primary`/`type`/`status`) sind additiv. `hw_type`/`hw_icon` entfallen, werden aber vom Frontend nicht gelesen.
- Das `unknown`→`True`-Verhalten von `parse_operstate` ist ein bewusster konservativer Fallback (viele virtuelle Interfaces melden dauerhaft `unknown`); es ist dokumentiert und getestet, kein stiller Fallback im Sinne von Finding S3.
