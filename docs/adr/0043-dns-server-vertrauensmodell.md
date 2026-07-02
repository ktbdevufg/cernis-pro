# 43. DNS-Server-Vertrauensmodell mit abgestufter Einordnung

Datum: 2026-07-02

## Status

Akzeptiert. Baut auf 0042 (netzweiter DNS-Umgehungs-Waechter) auf und
verfeinert dessen "erwartete Server"-Begriff. Nutzt 0040 (Blocklist-
Bewertung, DOH- und THREAT-Gruppe) und knuepft an 0038 (Rogue-DHCP) an.

## Kontext

Der netzweite DNS-Umgehungs-Waechter (0042) klassifiziert eine Anfrage als
Umgehung, wenn ihr Ziel nicht in der "erwarteten Server"-Menge liegt. Diese
Menge war bisher: konfigurierte Liste, sonst nur das Gateway. Das ist in
realen Netzen unzureichend und teils irrefuehrend:

- Ein separater lokaler Resolver (Pi-hole/AdGuard hinter dem Router) ist der
  eigentliche Standard-Nameserver, steht aber nicht im Gateway-Default -- sein
  gesamter, gewollter Verkehr wird faelschlich als Umgehung gezaehlt.
- Der real genutzte Nameserver liesse sich systemseitig ermitteln
  (resolvectl/resolv.conf), doch ihn blind als "erwartet" zu uebernehmen waere
  gefaehrlich: ein per Rogue-DHCP oder DNS-Hijacking untergeschobener Resolver
  (0038) wuerde damit automatisch legitimiert -- der Waechter machte sich blind
  gegen genau die Angriffsklasse, die er aufdecken soll.
- "Real genutzt" und "vertrauenswuerdig" sind zwei verschiedene Achsen. Ein
  oeffentlicher Resolver (8.8.8.8) als Standard ist nicht boesartig, umgeht aber
  die lokale Filter-/Logging-Infrastruktur. Ein VPN-/Firmen-Resolver ist
  kontextabhaengig legitim. Ein gelisteter Resolver kann ein False Positive
  sein.

Es braucht daher kein binaeres "erwartet/nicht erwartet", sondern eine
abgestufte, vom Nutzer kuratierte Vertrauens-Einordnung -- konsistent zur
Produkt-These (muendiger Anwender, zeigen+einordnen statt urteilen) und zum
bestehenden TrustState-Muster bei Geraeten (User-gesteuert, vom Scan nie
veraendert).

## Entscheidung

Ein DNS-Server traegt einen Vertrauens-Zustand (DnsTrustState:
TRUSTED / NEUTRAL / REJECTED, Default NEUTRAL) -- Muster TrustState bei
Geraeten: allein User-gesteuert, append-only, von Scan/Automatik nie
ueberschrieben. Persistiert je Server-IP.

Beim ersten Erkennen ordnet CERNIS jeden Server automatisch in eine
Kategorie ein (reine Ableitung aus vorhandenen Quellen, kein Urteil):

- Gateway -- die definierende Netz-Instanz (aus der Topologie). Einziger
  Fall mit Auto-Vertrauen (implizit TRUSTED): misstraut man dem Gateway,
  ist die Netzbasis ohnehin verloren.
- Lokal/privat -- RFC1918-Adresse, nicht Gateway (typisch Pi-hole/AdGuard).
  Kein Auto-Vertrauen: einmalige bewusste Bestaetigung noetig (Schutz gegen
  lokales DNS-Hijacking / Rogue-DHCP, 0038), aber ruhige Darstellung.
- Oeffentlicher Resolver -- Treffer in der DOH-Gruppe/Resolver-Tabelle
  (0040; Google/Cloudflare/Quad9 ...). Neutrale Einordnung "oeffentlicher
  Dienst", bewusste Vertrauen/Ablehnen-Wahl.
- Unbekannt -- keine der obigen (typisch VPN-Resolver, Firmen-DNS,
  unbekannte lokale Geraete). Bewusste Vertrauen/Ablehnen-Wahl.
- Auf Bedrohungsliste -- Treffer in der THREAT-Gruppe (0040, Feodo u.a.).
  Als Warnbefund dargestellt, nicht als neutrale Wahl. Vertrauen bleibt
  technisch moeglich (muendiger Nutzer; Blocklists haben False Positives), aber
  nur durch aktives Uebergehen der Warnung.

Bei jeder zu bestaetigenden Entscheidung zeigt CERNIS eine
Plausibilitaets-Einordnung aus vorhandenen Daten (Stufe 1, ohne
Extra-Scan): Bestandszugehoerigkeit und -alter (first_seen), MAC/Hersteller,
bereits bekannte offene Ports, Stabilitaet ueber die Zeit. Diese Indizien sind
Entscheidungshilfe, kein Beweis -- CERNIS ordnet Plausibilitaet ein, urteilt
nicht. Ein gezielter Live-Nachscan des Ziels ist als spaetere Stufe 2 moeglich.

Die erwartete Menge des Waechters (0042) ist kuenftig die Menge der
TRUSTED-Server (Auto-Gateway + bewusst bestaetigte). Der real genutzte
Nameserver (resolvectl, Fallback resolv.conf ohne Loopback-Stub wie
127.0.0.53) fliesst NICHT automatisch als erwartet ein, sondern nur als
erkannter Server, der zur Einordnung vorgelegt wird.

Eine Verwaltungs-Ansicht listet alle je erkannten DNS-Server (auch aktuell
inaktive, z.B. abgeschaltetes VPN -- konsistent zum Geraete-Bestand) mit
Kategorie, Vertrauens-Zustand und Vertrauen/Ablehnen-Schaltern; nachtraeglich
aenderbar.

## Konsequenzen

- Der Waechter klassifiziert in realen Netzen korrekt: der lokale Resolver ist
  nach einmaliger Bestaetigung erwartungsgemaess, nur echte Ausreisser bleiben
  Umgehung.
- CERNIS bleibt gegen Rogue-DHCP/DNS-Hijacking wachsam (0038): kein
  untergeschobener Resolver wird stillschweigend legitimiert.
- Der Nutzer traegt eine bewusste Erstentscheidung je Server -- ein Klick,
  danach Ruhe; die Plausibilitaets-Einordnung senkt die Last.
- Neuer persistierter Zustand (DNS-Server-Vertrauen) mit eigener Repository-
  Naht; neue System-Resolver-Ermittlung (infrastructure, best-effort, mit
  Timeout); neue Verwaltungs-Ansicht.
- Die "gute Resolver"-Whitelist entsteht netzspezifisch aus den Nutzer-
  Entscheidungen -- keine mitgelieferte Whitelist (was "gut" ist, ist
  netzabhaengig).

## Alternativen

- Real genutzten Resolver auto-vertrauen -- verworfen: legitimiert
  Rogue-DHCP/Hijacking automatisch, untergraebt den Waechter-Zweck.
- Alle privaten IPs auto-vertrauen -- verworfen: die haeufigsten realen
  LAN-DNS-Angriffe nutzen private IPs; Auto-Vertrauen waere dagegen blind.
- Mitgelieferte Resolver-Whitelist -- verworfen: "vertrauenswuerdig" ist
  netzabhaengig; eine statische Liste passt nicht und wiegt in falscher
  Sicherheit.
- Binaere erwartet/nicht-erwartet-Menge beibehalten -- verworfen: bildet
  weder die VPN-/Firmen-Faelle noch die "oeffentlich aber gewollt?"-Frage ab.
