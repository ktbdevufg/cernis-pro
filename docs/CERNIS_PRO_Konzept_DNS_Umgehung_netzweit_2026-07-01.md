# CERNIS PRO 2.0 -- Konzept: Netzweiter DNS-Umgehungs-Waechter (B11)

Status: FEST (Sitzung 23, 2026-07-01). Design-Weichen von Karl freigegeben; Umsetzung in
Etappen, Backend zuerst. Herkunft: Ideen_und_Ausblick B11. ADR 0042 (siehe docs/adr).

---

## 1. Problem
Der bestehende DNS-Waechter ist HOST-LOKAL (Variante A, rootless psutil-Verbindungssicht):
er sieht nur die Resolver, die DIESER Rechner anspricht. Er kann NICHT sehen, ob ein ANDERES
Geraet im Netz (TV, IoT, Handy) den Heim-DNS (Pi-hole/Router) umgeht -- genau die
sicherheitsrelevante Frage. Ausloeser: Karls Pi-hole (172.18.0.156) taucht host-lokal nicht
auf (UDP-53 fluechtig). Netzweite Sicht braucht PASSIVES MITLESEN.

## 2. Kernidee
Passiv mitlesen (bestehender cernis-sniffd, CAP_NET_RAW), DNS-relevanten Verkehr im Netz je
Quell-Geraet auswerten: welches Geraet fragt welchen Resolver? Ziel NICHT in der erwarteten
Liste -> Befund "umgeht erwarteten DNS". Zusammengefuehrt mit dem Geraete-Bestand:
"Geraet X (Name/Hersteller) nutzt fremden Resolver Y".

## 3. Ehrliche Grenzen (rote Linie, UI benennt sie)
- PLAIN-DNS (Port 53, UDP+TCP): Quell-/Ziel-IP offen -> HART erkennbar.
- DoH (443, verschluesselt): nur HEURISTISCH ueber Anbieter-Listen (s. 6). "Kein Treffer"
  heisst NICHT "kein DoH". Privater DoH-Server bleibt unerkennbar.
- SICHTBARKEIT: im geswitchten Netz sieht CERNIS fremden Unicast NICHT automatisch (auch
  nicht promiscuous). Netzweite Sicht braucht: (a) CERNIS am Gateway/Router, (b) Mirror-/
  SPAN-Port, oder (c) einfaches Netz. Sonst ehrlicher Leerzustand + Voraussetzungs-Hinweis.

## 4. ENTSCHIEDEN (Karl, Sitzung 23)
- (§4) Verhaeltnis: BEIDE Waechter behalten, ehrlich getrennt. "DNS-Waechter (dieser
  Rechner)" rootless, immer verfuegbar (Fallback). "DNS-Umgehung im Netz" mit
  Sichtbarkeits-Voraussetzung, Hauptsicht wo gegeben. Kein Verwerfen funktionierenden Codes.
- (§5) Erwartete Resolver: vom Nutzer gepflegte Liste; Default-VORSCHLAG automatisch aus
  Systemzustand (Gateway + real genutzter Resolver aus resolv.conf/resolvectl) -> in Karls
  Netz automatisch der Pi-hole .156. Jederzeit editierbar. Ueber bestehende Settings-Naht.
- (§7) Erfassung: NUTZERGESTARTETE Aufzeichnung (Muster outbound_log), KEIN Dauer-Mitlesen.
  Bewusst gestartet, sichtbar, gestoppt -- volle Nutzerkontrolle, ressourcenschonend.
- (§DoH) DoH-Erkennung = neue Blocklist-Gruppe "DoH-Anbieter" in der bestehenden
  blocklist-Domaene (ADR 0040), 1:1 analog Tracker/Bedrohung:
  * werksseitig LIZENZFREIE Listen mitgeliefert + aktiv (permissiv, GPLv3-robust; Quelle
    lizenzgeprueft vor Aufnahme -- dnscrypt-proxy/curl-Umfeld als Kandidaten).
  * Nutzer kann eigene Listen hinzufuegen (aktivieren/deaktivieren/Strenge wie gehabt).
  * zwei Treffer-Achsen: IP-basiert (immer) + Domain-basiert via SNI (schaerfer, mit
    laufendem SNI-Sniffer).
  * Absicherung beim Hinzufuegen: Nutzer waehlt die Gruppe BEWUSST (keine stille
    Einsortierung) + leichter Format-Plausibilitaetscheck ("sieht nicht wie eine
    DoH-Liste aus -- trotzdem fuehren?"); warnt + fragt, verbietet nicht.
  * Rote Linie ADR 0040: die Liste ordnet ein, nicht CERNIS.

## 5. Architektur (WIE, Claude -- Ring-Aufteilung)
- infrastructure/sniffd: DNS-Extraktion ergaenzen (Port-53-Paket -> Quell-IP, Ziel-IP, L4,
  optional Name); neues IPC-Event DNS_QUERY (Muster SNI-HIT). promisc hier AN.
- domain/dns_bypass (neu, getrennt von dns_watch): reine Logik "Ziel in erwarteter Menge?"
  + Aggregation je Quell-Geraet. Frozen, keine Uhr/I-O/Fremd-Domaene.
- application/dns_bypass: Use-Case fuehrt Sniffer-Events + Geraete-Bestand (Quell-IP->Geraet)
  + erwartete-Liste + DoH-Blocklist-Bewertung zusammen (quellen-agnostisch injiziert).
- api + Composition Root: neue Route(n); Geraete-/Blocklist-Zuordnung faellt im Composition
  Root (independence-Contract bleibt hart).
- Frontend: eigene Kachel + View; Voraussetzungs-Hinweis + ehrlicher Leerzustand prominent.
- Befunde quittierbar (append-only, Muster dns_watch_ack/cve-ack).

## 6. Host-lokaler Bericht (E1-E3, gruen, ungepusht)
Bleibt (Entscheidung I). Bekommt nur ehrliche Text-/Hilfe-Korrektur ("dieser Rechner",
"erwartet = deine Liste") und wird dann mitgepusht. Nicht verwerfen.

## 7. Offen (im Bau zu klaeren)
CERNIS-Host-Selbstzaehlung vermeiden; Andocken an bestehende NetFinding-Naht vs. eigene
Naht; Verhaeltnis zum Sicherheitsbericht; IPv6-DNS.

## Geraete-Zuordnung: gestaffelt (Option 2 Basis + Option 3 Praezision)

Der netzweite Sniff sieht Quell-IPs, keine Geraete-Identitaeten (der Bestand ist
MAC-gefuehrt, es gibt keine IP->Geraet-Methode). Entscheidung (Karl, WAS): maximale
sinnvolle Wahlfreiheit durch Staffelung statt einer einzelnen Stufe.

* BASIS (immer, ohne Voraussetzung): Quell-IP ist der ehrliche Primaerschluessel. Ein
  best-effort-Geraetename wird aus dem Bestand (last_ip / IP-History) beigestellt, WO
  vorhanden, klar als Vermutung beschriftet ("evtl. Geraet X"). Verspricht keine harte
  Identitaet. Laeuft in jedem Netz.
* PRAEZISION (zuschaltbar, spaetere Etappe): MAC-Mit-Extraktion im DNS-Sniff
  (DNS_QUERY um src_mac erweitern -> Recorder -> harte MAC->Geraet-Zuordnung). Hebt die
  Zuordnung von "evtl." auf "sicher" -- ABER nur im selben L2-Segment (fremde MACs hinter
  Switches/Routern sind unsichtbar). Ehrlich benannt: ohne MAC-Sicht IP+Vermutung, mit
  MAC-Sicht im Segment harte Identitaet.

Option 1 (nur IP) verworfen: wirft vorhandene Bestandsdaten weg. Option 3 allein
verworfen: liefe im geswitchten Heimnetz oft leer. Die Staffelung gibt robuste Basis +
optionale Praezision, jede Stufe ehrlich beschriftet.

## DoH-Bewertung: eigene Lookup-Naht, NICHT MatchContacts

MatchContacts filtert JEDEN Treffer durch strictness_allows -- und DOH kommt bei keiner
Anzeige-Strenge durch (bewusst, E3). Der netzweite Waechter fragt die DoH-Gruppe daher
DIREKT ab (entries.lookup_ips / lookup_domains + Filter auf aktive DOH-Quellen), NICHT
ueber MatchContacts. So bleibt die Aussenkontakte-Strenge unberuehrt und die DoH-Achse
eigenstaendig.
