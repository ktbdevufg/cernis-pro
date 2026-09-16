# 44. Standardzugangs-Pruefung als scharfe Opt-in-Sonderfunktion

Datum: 2026-07-04

## Status

Akzeptiert. Loest den Audit-Befund F-03 (aktiv-intrusive
default-creds-Logins) als Produktentscheidung statt durch Entfernen und
adressiert dabei F-09 (deaktivierte TLS-Verifikation) mit. Knuepft an die
Produkt-These an (muendiger Anwender, zeigen und einordnen statt urteilen;
CERNIS aendert nichts, prueft nur).

## Kontext

Der v2-Sicherheitsaudit (docs/SECURITY_AUDIT_2026-07-03.md) fuehrte den
bestehenden default-creds-Endpunkt als F-03 (High): aktive HTTP/FTP-Login-
Versuche mit Standard-Zugangsdaten sind intrusiv. Sie koennen in den
Protokollen des Zielgeraets auftauchen und im Extremfall eine voruebergehende
Sperre (Lockout) ausloesen. Der Endpunkt war unauthentisiert (nach F-01
immerhin origin-geschuetzt) und ohne Frontend-Anbindung nur ueber die rohe
API erreichbar - eine intrusive Faehigkeit ohne sichtbare Einhegung.

Ein zweiter Befund haengt daran: F-09 stellte fest, dass die HTTPS-Pruefung
die Zertifikatsvalidierung pauschal abgeschaltet hatte, um selbstsignierte
Geraete-Seiten ueberhaupt erreichen zu koennen - eine stille Abschwaechung,
die echte TLS-Fehler unsichtbar machte.

Zwei Wege standen offen: die Funktion entfernen - oder sie behalten und
absichern. Die Produkt-These spricht fuer Behalten: CERNIS richtet sich an
den muendigen Anwender und gibt ihm maximale sinnvolle Wahlfreiheit; das
Programm aendert nichts, es prueft nur. Standardpasswoerter stehen ohnehin
frei im Netz, und ein Nutzer koennte dieselbe Pruefung mit einfachen
Bordmitteln selbst durchfuehren. Der intrusive Charakter darf dabei aber
nicht verschwiegen oder unbegrenzt bleiben, sondern muss klar eingehegt und
transparent gemacht werden.

## Entscheidung

Die Funktion bleibt, wird aber zu einer scharfen Opt-in-Sonderfunktion
umgebaut:

1. **Sitzungsweites Arm-Flag am `app.state`.** Startwert aus, nicht
   persistent. Der Endpunkt antwortet 403, solange nicht freigeschaltet. Die
   Freischaltung erfolgt bewusst in den Einstellungen ueber einen
   bestaetigten Warndialog, der ausdruecklich darauf hinweist, dass die
   Freischaltung nur fuer die laufende Sitzung gilt und beim naechsten Start
   wieder aufgehoben ist. Kein dauerhafter Scharf-Zustand.

2. **Ziel-Begrenzung auf private/lokale IPs** (RFC1918, Loopback,
   Link-Local). Realisiert ueber `is_private_target` in
   `infrastructure/security/net_scope.py`, per Dependency injiziert, damit die
   `api`->`infrastructure`-Grenze gewahrt bleibt. Ein nicht-privates Ziel
   fuehrt zu 403. Das schliesst den Missbrauch der Funktion als
   Credential-Stuffing-Proxy gegen Internet-Ziele aus.

3. **F-09 geheilt: strikte TLS-Pruefung zuerst.** Der erste Versuch laeuft
   mit voller Zertifikatsvalidierung. Nur bei einem Zertifikatsfehler folgt
   genau EIN ungeprueter Fallback, dessen Treffer als "selbstsigniertes
   Zertifikat" markiert wird. Im Heimnetz sind selbstsignierte Geraete-Seiten
   ueblich; die ehrliche Kennzeichnung ist der bewusste Ersatz fuer die
   fruehere stille Abschwaechung.

4. **Rate-Limit von 1 s** zwischen den einzelnen Anmeldeversuchen, um das
   Zielgeraet zu schonen und Lockout-Risiken zu senken.

5. **Frontend.** Die Untersuchen-Kachel bleibt bis zur Freischaltung
   gesperrt. Die Pruef-Ansicht ordnet das Ergebnis neutral ein: ein Treffer
   heisst "Geraet nutzt einen Standardzugang", ein Nicht-Treffer heisst "mit
   den geprueften Standard-Zugangsdaten kein Zugang moeglich" und wird
   ausdruecklich NICHT als "sicher" ausgewiesen.

## Konsequenzen

- F-03 ist als bewusste, dokumentierte Produktentscheidung abgeschlossen -
  die Funktion wurde nicht entfernt, sondern eingehegt.
- F-09 ist behoben: die TLS-Verifikation ist wieder strikt, der einzige
  Fallback ist explizit gekennzeichnet statt still.
- Der intrusive Charakter ist durch Default-Aus, Sitzungsbindung,
  Netz-Begrenzung und Rate-Limit eingehegt.
- Restrisiko: Der Nutzer kann die Funktion bewusst gegen eigene Geraete
  einsetzen und dort theoretisch einen Lockout ausloesen. Das ist durch den
  Warndialog und den Handbuch-Eintrag transparent gemacht und entspricht der
  Wahlfreiheit des muendigen Anwenders.
- DF5 in der Domaenen-Referenz ist damit aufgeloest.
- Kein persistenter Zustand und kein neuer Port/Use-Case fuer das Arm-Flag:
  bewusst ein reines Laufzeit-Flag am `api`-Rand.
