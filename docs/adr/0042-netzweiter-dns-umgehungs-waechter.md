# 0042 — Netzweiter DNS-Umgehungs-Wächter (passives Mitlesen, eigene Domäne)

Status: akzeptiert · Datum: 2026-07-01 · Bereich: infrastructure/sniffd (DNS-Extraktion),
domain/dns_bypass, ports/dns_bypass, application/dns_bypass, blocklist-Domäne (neue Gruppe
DoH-Anbieter), api + app.py-Verdrahtung, Frontend (eigene Kachel/View), Persistenz
(Ack-Log + Aufzeichnung)

## Kontext

Der bestehende DNS-Wächter (Block 2) ist **host-lokal** (Variante A): er sieht über die
rootless psutil-Verbindungssicht nur die Resolver, die *dieser* Rechner anspricht. Er kann
**nicht** erkennen, ob ein *anderes* Gerät im Netz (Smart-TV, IoT, Mobilgerät) den Heim-DNS
(Pi-hole/Router) umgeht — obwohl genau das die sicherheitsrelevante Frage ist: ein Gerät, das
an der Filterung vorbei einen fremden Resolver oder eigenes DoH nutzt, entzieht sich Sicht und
Kontrolle.

Auslöser (Sitzung 23): Der Pi-hole des Anwenders (172.18.0.156) taucht im host-lokalen Wächter
nicht auf, weil UDP-53-Anfragen flüchtig sind und die Verbindungs-Momentaufnahme sie nicht
fängt. Erkenntnis: eine netzweite Sicht braucht **passives Mitlesen**, nicht die
Verbindungs-Momentaufnahme. Der dafür nötige Unterbau existiert bereits (`cernis-sniffd`,
CAP_NET_RAW, ADR 0041).

Die B11-Idee stand von Anfang an als Ausblick fest (Ideen_und_Ausblick), war aber bewusst noch
nicht gebaut. Die vorhandene Kachel-/Hilfe-Formulierung des host-lokalen Wächters versprach
jedoch fälschlich diese netzweite Sicht — ein Kommunikations-Bruch, der mitkorrigiert wird.

Drei Spannungen prägten den Entwurf:
1. **Sichtbarkeit:** In einem geswitchten Netz sieht CERNIS fremden Unicast-Traffic **nicht**
   automatisch (auch nicht im promiscuous mode) — der Switch leitet fremde Pakete gar nicht an
   den CERNIS-Host. Volle netzweite Sicht setzt CERNIS am Gateway, einen Mirror-/SPAN-Port
   oder ein einfaches Netz voraus.
2. **Plain-DNS vs. DoH:** Port-53-Verkehr ist offen lesbar (Quell-/Ziel-IP) und damit hart
   erkennbar; DoH ist verschlüsseltes 443 und nur heuristisch über bekannte Anbieter
   erkennbar.
3. **Verhältnis zum host-lokalen Wächter:** Die netzweite Sicht umschließt die host-lokale
   fast vollständig — außer dass letztere ohne Rechte und ohne Netz-Sichtbarkeit funktioniert.

## Entscheidung

Ein **eigener netzweiter DNS-Umgehungs-Wächter** als neue Domäne `domain/dns_bypass`
(getrennt vom host-lokalen `dns_watch`, ADR 0002: stdlib-rein, frozen Datenträger, reine
zeitfreie Funktionen). Er liest DNS-relevanten Verkehr **passiv** über den bestehenden
Sniff-Helfer mit und ordnet je Quell-Gerät ein, ob dessen Resolver-Ziel in der erwarteten
Menge liegt.

Weitere Festlegungen:

- **Beide Wächter bleiben, ehrlich getrennt (Option I):** „DNS-Wächter (dieser Rechner)"
  bleibt der rootless, immer verfügbare Fallback; „DNS-Umgehung im Netz" ist die Hauptsicht
  dort, wo die Sichtbarkeits-Voraussetzung erfüllt ist. Der bereits gebaute host-lokale
  Bericht wird **nicht verworfen**, sondern nur ehrlich umtextet (siehe Konsequenzen).

- **Passive DNS-Extraktion im Helfer:** `infrastructure/sniffd` extrahiert aus Port-53-Paketen
  Quell-IP, Ziel-IP, L4 (udp/tcp) und optional den abgefragten Namen; neues IPC-Event
  `DNS_QUERY` (Muster der SNI-`HIT`-Naht, ADR 0041). Der Helfer läuft für diesen Modus mit
  `promisc=True` (netzweiter Anspruch), im Gegensatz zum host-lokalen `promisc=False`.

- **Nutzergestartete Aufzeichnung, kein Dauer-Mitlesen (Muster outbound_log, ADR 0039):** Die
  netzweite Erfassung wird vom Anwender **bewusst gestartet**, läuft sichtbar und wird
  gestoppt — passives Mitlesen mit CAP_NET_RAW soll nicht unbemerkt im Hintergrund laufen.
  Volle Nutzerkontrolle, ressourcenschonend.

- **Erwartete Resolver = editierbare Nutzerliste mit Auto-Vorschlag:** Die erwarteten Resolver
  liegen über die bestehende Settings-Naht (kein neuer Settings-Domänen-Eingriff). Der
  **Default-Vorschlag** wird aus dem echten Systemzustand abgeleitet (Gateway + der real
  genutzte Resolver aus `resolv.conf`/`resolvectl`) — im Netz des Anwenders also automatisch
  der Pi-hole. Jederzeit editierbar. Zeigen + einordnen: Ziel außerhalb der Liste → Befund
  „umgeht erwarteten DNS", **kein** automatisches Urteil. Behebt die falsche Gateway-Annahme
  des host-lokalen Wächters.

- **DoH-Erkennung als neue Blocklist-Gruppe „DoH-Anbieter" (analog ADR 0040):** DoH wird nicht
  als Sonderweg gebaut, sondern als weitere Gruppe der bestehenden `blocklist`-Domäne, 1:1 mit
  deren Maschinerie (laden, indizieren, Treffer als dezente Badges mit Quelle). Zwei
  Treffer-Achsen: **IP-basiert** (Ziel-IP ∈ DoH-Liste, funktioniert immer) und
  **domain-basiert** (SNI-Hostname ∈ DoH-Liste, schärfer, mit laufendem SNI-Sniffer).
  Werksseitig sind **lizenzfreie** DoH-Listen mitgeliefert und aktiv (permissiv, GPLv3-robust;
  Quelle lizenzgeprüft vor Aufnahme — dnscrypt-proxy/curl-Umfeld als Kandidaten). Der Anwender
  kann eigene Listen hinzufügen.

- **Absicherung beim Hinzufügen eigener Listen:** Der Anwender wählt die Gruppe (Tracker /
  Bedrohung / DoH-Anbieter) **bewusst** — keine stille Einsortierung. Ein leichter
  Format-Plausibilitätscheck warnt, wenn eine Liste strukturell nicht zur gewählten
  DoH-Gruppe passt („sieht nicht wie eine DoH-Liste aus — trotzdem führen?"), **verbietet
  aber nicht** (mündiger Anwender entscheidet).

- **Geräte-Zuordnung im Composition Root:** Die Zuordnung Quell-IP → Gerät (aus dem
  bestehenden Bestand) und die DoH-Blocklist-Bewertung fallen **ausschließlich** im
  Composition Root; die `dns_bypass`-Domäne nennt weder `devices` noch `blocklist`
  (independence-Contract bleibt hart). Der Application-Use-Case bekommt die Quellen
  quellen-agnostisch injiziert (Muster `BuildDnsWatch`/`BuildOutboundContacts`).

- **Befunde quittierbar (append-only):** Ein Umgehungs-Befund pro (Gerät, Resolver) kann als
  bekannt quittiert werden (Muster `dns_watch_acknowledgements`/cve-Ack).

## Ehrliche Grenzen (rote Linie, von der UI benannt)

- **Sichtbarkeits-Voraussetzung:** Ohne CERNIS am Gateway, Mirror-/SPAN-Port oder einfaches
  Netz sieht der Wächter wenig bis nichts. Die UI zeigt einen **Voraussetzungs-Hinweis** und
  einen ehrlichen Leerzustand statt eines leeren Versprechens.
- **DoH nur heuristisch:** „Kein Treffer" heißt **nicht** „kein DoH". Ein privater DoH-Server
  auf 443 bleibt unerkennbar. Listen sind nie vollständig.
- **Plain-DNS hart:** Port-53-Umgehung ist verlässlich erkennbar (UDP + TCP).

## Konsequenzen

**Positiv:**
- Beantwortet endlich die eigentliche Frage („welches Gerät umgeht den Heim-DNS"), ohne dass
  CERNIS selbst urteilt — die Einordnung gehört der Liste/der erwarteten Menge, der Anwender
  wählt Listen, Resolver und Strenge.
- Nutzt durchgängig vorhandenen Unterbau (Sniff-Helfer ADR 0041, Blocklist-Maschinerie ADR
  0040, Aufzeichnungs-Muster ADR 0039) — kein Parallelbau, konsistente Bedienung.
- Der host-lokale Wächter bleibt als rootless-Fallback erhalten und wird ehrlich umtextet.

**Negativ / bewusst offen:**
- **Sichtbarkeit ist Betriebssache:** In typischen geswitchten Heimnetzen ohne Mirror-Port
  bleibt die netzweite Sicht dünn — das ist eine physikalische Grenze, keine Implementierung.
- **DoH-Heuristik unvollständig** (siehe rote Linie).
- **CERNIS-Host-Selbstzählung, Andocken an die bestehende `NetFinding`-Naht, das Verhältnis
  zum Sicherheitsbericht und IPv6-DNS** werden im Bau geklärt (Konzept §7).

## Abgrenzung

- **Ersetzt den host-lokalen Wächter nicht** (Option I, bewusst zwei getrennte Sichten).
- **Kein eigenes CERNIS-Urteil:** keine Reputations-Engine — nur Spiegelung der erwarteten
  Menge und der ausgewählten DoH-Listen.
- **Keine externe Reputations-/DoH-API:** rein lokal, hängt an der lokal-vs-server-Grundsatz-
  frage (Vision 5.x). Vorerst bewusst nicht.
