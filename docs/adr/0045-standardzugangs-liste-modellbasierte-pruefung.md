# 45. Standardzugangs-Liste und modellbasierte Pruefung

Datum: 2026-07-05

## Status

Akzeptiert. Baut auf ADR 0044 auf: Die dort beschlossene Einhegung der
Standardzugangs-Pruefung als scharfe Opt-in-Sonderfunktion (Sitzungs-Arm-Flag,
Netz-Guard, strikte TLS-Pruefung, Rate-Limit) bleibt unveraendert bestehen.
Diese ADR ersetzt jedoch den in 0044 noch vorausgesetzten *blinden* Pruef-
Ansatz (freie Host-Eingabe, generische admin/admin-Liste gegen geratene Ports)
durch einen *modellbasierten*.

Anlass war ein Live-Test: Der blinde admin/admin-Scan gegen eine FritzBox
produzierte einen Fehltreffer (er meldete sich in Wahrheit an einem
Docker-Bridge-Gateway auf Port 80 an, nicht am Router), und die Recherche
ergab, dass die FritzBox gar keinen universellen admin/admin-Default hat. Der
blinde Ansatz liefert also unzuverlaessige Ergebnisse und kann obendrein
Lockouts durch Credentials ausloesen, die das Zielgeraet nie besass.

## Kontext

Der blinde Ansatz probiert eine generische Zugangsdaten-Liste gegen geratene
Ports, ohne jeden Geraetebezug. Eine Recherche gegen Herstellerquellen
bestaetigte, dass das nicht nur unpraezise, sondern teils schaedlich ist:

- Netgear nutzt ueblicherweise admin/password, nicht admin/admin.
- Asus erzwingt beim ersten Zugriff einen Passwort-Wechsel, ein Werks-Default
  existiert praktisch nicht.
- FritzBox, Eero und Nest haben keinen universellen Standardzugang.
- Moderne Geraete arbeiten zunehmend mit geraeteindividuellen
  Label-Passwoertern (auf dem Geraeteaufkleber), gegen die eine generische
  Liste grundsaetzlich nichts ausrichtet.

Ein blinder Scan gegen solche Geraete probiert also Zugangsdaten, die es dort
nie gab - das kostet Zeit, taeuscht Sicherheit vor oder liefert Fehltreffer
und kann im schlechtesten Fall einen Lockout ausloesen.

Damit die Pruefung verlaesslich wird, braucht es dreierlei: einen echten
Geraetebezug (welcher Hersteller, welches Modell?), eine ehrliche
Verlaesslichkeitseinordnung der einzelnen Kandidaten und die Moeglichkeit,
positiv "kein Default bekannt" von "keine Infos" zu unterscheiden. Nur so
kann das Ergebnis fuer secure-by-default-Geraete eine echte Entwarnung geben,
statt still nichts zu finden.

## Entscheidung

1. **Kuratierte, pflegbare Standardzugangs-Liste.** Eine in SQLite
   persistierte und vom Nutzer pflegbare Liste ordnet Hersteller/Modell den
   bekannten Werks-Zugangsdaten zu (Domaenen-Typen, Seed aus
   Herstellerquellen, eigenes Repository). Jeder Kandidat traegt eine
   Konfidenz - `gesichert` (durch Herstellerquelle belegt), `auch_moeglich`,
   `vermutet` oder `benutzer` (selbst angelegt). Jeder Eintrag traegt einen
   Zustand - `hat_defaults` oder `keine_bekannten_defaults`; der dritte Fall
   "unbekannt" ergibt sich implizit aus dem Fehlen eines Eintrags.

2. **Modellbasierter Workflow.** Statt freier Host-Eingabe: Geraetewahl aus
   dem Scan, Hersteller-Bestimmung ueber die OUI (den herstellerspezifischen
   Teil der MAC-Adresse), Modell optional und bei Bedarf nachfragbar. Daraus
   eine Pruefplan-Ermittlung mit drei Faellen - Entwarnung
   (`keine_bekannten_defaults`), Kandidaten-Auswahl (`hat_defaults`) oder
   "keine Infos". Die anschliessende Pruefung laeuft gezielt: nur gegen die
   vom Nutzer gewaehlten Kandidaten und nur gegen tatsaechlich offene Ports.
   Eine Historie haelt vergangene Pruefungen fest.

3. **Verwaltungs-Menuepunkt in den Einstellungen.** Ein eigener Punkt
   "Standardzugaenge-Liste" mit CRUD (einsehen, bearbeiten, hinzufuegen,
   loeschen), aktiv/inaktiv-Toggle je Eintrag und einem "Auf Standard
   zuruecksetzen", das die mitgelieferten Eintraege wiederherstellt, selbst
   angelegte aber behaelt.

Die Absicherung aus ADR 0044 (Opt-in pro Sitzung, Netz-Guard, strikte
TLS-Pruefung mit gekennzeichnetem Selbstsigniert-Fallback, Rate-Limit) bleibt
unveraendert und gilt fuer den gezielten Pruef-Pfad genauso.

## Konsequenzen

- Verlaesslichere Ergebnisse: weniger Fehltreffer und geringeres
  Lockout-Risiko, weil nur noch geraete-passende Kandidaten gegen echte
  offene Ports geprueft werden.
- Ehrliche Entwarnung: Fuer secure-by-default-Geraete gibt es ein positives
  "hier ist nichts zu pruefen" statt eines stillen Nicht-Fundes.
- Nutzer-Pflegbarkeit: Die Liste ist einsehbar, erweiterbar und
  zuruecksetzbar; eigene Funde bleiben ueber ein Reset hinweg erhalten.
- Restaufwand bleibt die Listenpflege - die Liste ist naturgemaess nie
  vollstaendig und lebt von mitgelieferten Aktualisierungen und
  Nutzer-Ergaenzungen.
- Der bestehende alte Endpunkt/Use-Case (`check_host`) bleibt
  rueckwaertskompatibel erhalten, wird vom UI aber nicht mehr als
  Primaerpfad genutzt.
- Die Breite ueber weitere Geraeteklassen (IoT, Kameras, NAS) ist bewusst ein
  v3.0-Ausblick und hier nicht umgesetzt.
