# CERNIS PRO 2.0 — Wunsch- und Ideen-Liste (Backlog)

Sammelstelle fuer Feature-Wuensche und Beobachtungen aus dem Betrieb, die NICHT
sofort umgesetzt werden, aber nicht verloren gehen duerfen. Kein Zeitdruck, keine
feste Reihenfolge. Karl entscheidet, was wann angegangen wird.

---

## Aus dem v1-Betrieb beobachtet

### Live-Ueberwachung Interfaces + Gateway mit akustischem Signal
- v1 ueberwacht Interfaces und Gateway-Connections LIVE und meldet eine
  Zustandsaenderung SOFORT -- inklusive akustischem Signal.
- In v2 noch NICHT nachgebaut.
- Eigenes Feature, gehoert NICHT zur Auffaelligkeits-Engine.
- Verortung vermutlich nahe monitoring/interfaces-Domaene (Backend) + Frontend-
  Signalisierung (akustisch + visuell).
- Zeitpunkt offen.


---

## Strategisch / Produktrichtung

### CERNIS als Hintergrunddienst (Service-Installation)
- Mit jedem neuen zeitbasierten Feature (Port-History/"neuer Port", Auffaelligkeits-
  Bewertung ueber Zeit, spaeter Acknowledge-Audit) waechst der Nutzen eines DAUERHAFT
  laufenden Dienstes statt nur GUI-on-demand.
- Eine GUI-only-App sieht nur, was waehrend ihrer Laufzeit passiert. Als Service
  (systemd-Unit Linux, launchd/Login-Item macOS, Windows-Dienst) wuerde CERNIS
  durchgehend scannen/beobachten und beim Oeffnen die volle Historie zeigen.
- Beruehrt: Auto-Start, Rechte (root-pflichtige Features als Dienst sauber loesen,
  vgl. CAP_NET_RAW-Lehre), Datenhaltung/Aufbewahrung, Ressourcen, Deinstallation.
- STRATEGISCHE Produktentscheidung -- Karl entscheidet. Proaktiv aufgreifen, wenn der
  Backend-/Engine-Block stabil steht (analog cpnetcheck-Distributionsfrage, Master §7).
- Notiert 2026-06-16 auf Karls Hinweis waehrend Schnitt 5.

### Backdoor-Liste: Klassiker-Namen statt "—" in der Service-Spalte
- In der kritisch-Portliste (Einstellungen "Was ist auffaellig?") zeigt die Service-
  Spalte "—", weil die Backdoor-Ports bewusst NICHT im gaengigen Service-Mapping stehen.
- Korrektes Verhalten heute. Nuetzlicher waere der KLASSIKER-Name je Port
  (31337 -> "Back Orifice", 12345/12346 -> "NetBus", 1243/27374/6711-6713 -> "SubSeven",
  6670/6771 -> "Deep Throat", 27444/27665/31335 -> "Trinoo").
- Eigene kleine kuratierte Backdoor->Name-Tabelle (getrennt vom IANA-Service-Mapping),
  nur fuer die kritisch-Liste. Produktentscheidung, kein Mangel. Beobachtet 2026-06-16.
