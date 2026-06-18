# 0033 - Persistierter effektiver Start fuer die Wiederaufnahme aktiver Logging-Aufgaben

## Status

Akzeptiert

## Kontext

Eine Logging-Aufgabe hat zwei Betriebsarten (ADR 0032, Konzept Paragraph 4):

- GEPLANT: festes Fenster zwischen planned_start und planned_end. Beide Grenzen sind
  absolute Zeitpunkte und liegen bereits in der Definition vor.
- SOFORT: startet beim Druecken des Start-Knopfes und laeuft hoechstens max_duration_s
  Sekunden ab diesem Moment, als Sicherheit gegen versehentlichen Dauerlauf.

Das Konzept (Paragraph 6) verlangt, dass CERNIS nach einem Neustart eine noch gueltige
aktive Aufgabe automatisch im Hintergrund wieder aufnimmt. Fuer eine geplante Aufgabe
ist das pruefbar, weil ihr Fenster absolut definiert ist. Fuer eine Sofort-Aufgabe
fehlte dieser Bezugspunkt: B-I speichert den tatsaechlichen Start-Zeitpunkt bewusst
nicht (kein verfruehter Schema-Umbau). Ohne ihn kann nach einem Neustart nicht
entschieden werden, ob die Maximaldauer einer aktiven Sofort-Aufgabe noch laeuft oder
bereits abgelaufen ist.

Es standen zwei Wege offen: den effektiven Start dauerhaft festhalten, oder
Sofort-Aufgaben nach einem Neustart grundsaetzlich nicht wieder aufnehmen.

## Entscheidung

Der effektive Start wird persistiert. Die Tabelle `monitoring_log_tasks` erhaelt ein
zusaetzliches, anfangs leeres Feld `effective_start` (absoluter Zeitstempel):

- Es wird beim ERSTEN Uebergang nach ACTIVE gesetzt (Start-Knopf) auf den
  tatsaechlichen Zeitpunkt.
- Es bleibt ueber Pausen hinweg UNVERAENDERT stehen: ein Fortsetzen aus Pause setzt es
  NICHT neu. Die Maximaldauer einer Sofort-Aufgabe ist eine reine Wanduhr-Grenze ab dem
  ersten Start - Pausenzeit zaehlt mit. Das ist die bewusste fachliche Festlegung
  (siehe Begruendung): die Maximaldauer ist eine Sicherheitsgrenze gegen Dauerlauf,
  kein Versprechen ueber die gesammelte Datenmenge.
- Es wird erst beim endgueltigen Beenden (Uebergang nach FINISHED) wieder geleert, nicht
  beim Pausieren.
- Die zeitfreie Domaenen-Funktion is_window_active erhaelt diesen Wert kuenftig als
  Bezugszeitpunkt fuer das Maximaldauer-Fenster der Sofort-Aufgaben; die Domaene bleibt
  uhrfrei, der Wert kommt von aussen herein.

Die bestehende Tabelle aus B-I wird ueber einen idempotenten Schema-Guard ergaenzt
(CREATE TABLE unveraendert, danach PRAGMA-Pruefung und bei Bedarf ALTER TABLE ADD
COLUMN), nach demselben Muster, mit dem rtt_history seinerzeit die alive-Spalte
nachgeruestet hat. Bestandszeilen erhalten den Leerwert.

## Begruendung

Der tatsaechliche Start eines laufenden Vorgangs ist ein Fakt, kein ableitbarer Wert.
Ihn nicht zu speichern wuerde erzwingen, ihn nach einem Neustart zu raten oder die
Aufgabe fallenzulassen. Sofort-Aufgaben vom Neustart-Schutz auszunehmen wuerde die
Konzept-Zusage der automatischen Wiederaufnahme brechen, und zwar unterschiedlich je
nach Betriebsart - fuer den Nutzer ein unvorhersehbares Verhalten und das Gegenteil
einer verlaesslichen Ansicht.

Die Wanduhr-Semantik (Pausenzeit zaehlt mit, das Feld wird ueber Pausen nicht neu
gesetzt) ist bewusst gewaehlt: Die Maximaldauer ist im Konzept eine Sicherheitsgrenze
gegen versehentlichen Dauerlauf. Wuerde das Feld beim Fortsetzen neu gesetzt oder die
Pausenzeit herausgerechnet, koennte ein Sofort-Task durch wiederholtes
Pausieren und Fortsetzen unbegrenzt weiterlaufen - die Sicherheitsgrenze waere
ausgehebelt. Eine harte Wanduhr ab dem ersten Start ist fuer den Nutzer vorhersehbar
und nicht umgehbar.

Ein einzelnes optionales Feld traegt genau diesen einen real benoetigten Fakt. Das ist
kein Vorbau: die Funktion (Neustart-Wiederaufnahme) ist konkret gefordert, und ohne das
Feld nicht korrekt umsetzbar.

## Konsequenzen

- Beide Betriebsarten verhalten sich nach einem Neustart konsistent: eine noch gueltige
  aktive Aufgabe wird unabhaengig von ihrer Betriebsart wieder aufgenommen.
- Die Maximaldauer einer Sofort-Aufgabe laeuft als Wanduhr ab dem ersten Start; Pausen
  verlaengern das Fenster nicht.
- Das Setzen und Leeren des Feldes sowie die Neustart-Wiederaufnahme und der periodische
  Aufraeum-Lauf gehoeren in den Loop-/Lifespan-Anbindungs-Schritt (B-II); diese
  Entscheidung legt nur das Datenmodell und das Verhalten fest.
- Der Schema-Guard macht die Ergaenzung auf einer bereits bestehenden Datenbank
  gefahrlos wiederholbar.
