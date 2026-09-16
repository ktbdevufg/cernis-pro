# 0041 — Privilege-Separation: Sniff-Helfer cernis-sniffd traegt CAP_NET_RAW

Status: akzeptiert · Datum: 2026-06-27 · Bereich: infrastructure/sniffd (Helfer-Prozess-Seite:
protocol/server/sniff_core/_scapy), infrastructure/sniffd_client (Backend-Client-Seite: base +
SNI/pcap/LLDP-Clients), backend/sniffd.py (Entry), PyInstaller-Specs (Linux/macOS/Windows),
deb-/rpm-postinst.sh, tauri.conf.json (externalBin), scripts/dev-setcap-sniffd.sh

## Kontext

Drei Funktionen brauchen einen rohen Paketmitschnitt und damit CAP_NET_RAW: SNI-Erfassung
(TLS-ClientHello), Packet-Capture (pcap) und LLDP/CDP-Topologie. Alle drei fuhren bis hierher
scapy direkt im FastAPI-Backend.

Das v1-Modell setzte die Capability per Postinstall auf die GANZE Backend-Binary
(`setcap cap_net_raw+eip /usr/bin/cernis-backend`). Das erfuellt zwar den Kernwunsch (einmalig
bei Installation, dauerhaft, der Anwender merkt nichts) -- verletzt aber die S5-Lehre
(Build-Doku): Ein vollstaendiges FastAPI-Backend mit DB, REST-Endpunkten und Netz-Downloads
liefe dann dauerhaft mit Raw-Socket-Recht. Das ist eine unnoetig grosse Angriffsflaeche fuer
ein Recht, das nur drei eng umrissene Sniff-Funktionen brauchen.

## Entscheidung

Privilege-Separation nach dem Wireshark/dumpcap-Modell (Konzept SNI/Privilegien Weg 2): Ein
dedizierter, schlanker Helfer-Prozess `cernis-sniffd` traegt als EINZIGE Komponente
CAP_NET_RAW. Das grosse Backend bleibt unprivilegiert und spricht den Helfer ueber eine
schmale IPC-Naht an. Karls Kernwunsch (Cap einmalig per Postinstall, lautlos) bleibt erfuellt
-- nur das Ziel der Capability wandert vom Backend auf den Helfer.

Bausteine:

- **Zwei Modulheimaten, klare Namensgrenze:** `infrastructure/sniffd/` ist die
  HELFER-PROZESS-Seite (Protokoll + Sniff-Kern + Server + das geteilte scapy-Setup `_scapy`);
  `infrastructure/sniffd_client/` ist die BACKEND-Seite (spawnt den Helfer + spricht die IPC).
  Der Helfer-Importgraph ist bewusst fastapi-/uvicorn-/reportlab-frei -- darum lebt `_scapy`
  in der sniffd-Heimat und NICHT mehr im capture-Paket (dessen __init__ fastapi zieht und die
  schlanke Helfer-Binary beim Start zum Absturz brachte).

- **IPC: laengen-praefixiertes NDJSON ueber AF_UNIX-Stream-Socket.** Framing: 4 Byte
  big-endian unsigned Laenge (struct ">I") + UTF-8-JSON-Body, ein Frame = eine Nachricht.
  Reine stdlib (socket/json/struct), ohne scapy/psutil/domain -- die Naht bleibt isoliert
  testbar. Befehle Backend->Helfer: START (SNI), START_PCAP, START_LLDP, EXPORT_PCAP, STOP,
  PING. Antworten/Events Helfer->Backend: HIT, PACKET, NEIGHBORS, EXPORTED, STARTED, STOPPED,
  PONG, ERROR.

- **Lebenszyklus on-demand:** Der privilegierte Helfer lebt nur waehrend einer aktiven
  Sniff-Operation. Pro Backend-Client-Instanz hoechstens ein laufender Helfer; eigenes
  mkdtemp-Socket-Verzeichnis (0700, nicht world-writable); Teardown raeumt Prozess + Socket
  + Verzeichnis ab. Der Socket-Pfad wird dem Helfer als argv uebergeben.

- **promisc=False:** Der Sniff laeuft ohne Promiscuous-Mode -- SNI/pcap brauchen nur den
  eigenen Host-Traffic, und so entfaellt zusaetzlich der VMware-/Hypervisor-Promiscuous-Dialog.

- **Spawn frozen vs. dev:** Frozen (PyInstaller) liegt die Helfer-Binary `cernis-sniffd` neben
  sys.executable (Backend-Sidecar-Verzeichnis); dev startet der venv-Python `backend/sniffd.py`.
  Die Erkennung folgt dem etablierten `serve.py._is_frozen`-Muster (sys.frozen / _MEIPASS).

- **Build/Auslieferung:** Drei eigene, schlanke PyInstaller-Specs (cernis_sniffd_linux/macos/
  windows.spec, Entry sniffd.py) erzeugen die Helfer-Binary OHNE fastapi/uvicorn/starlette/
  reportlab/pysnmp/fritzconnection/keyring -- nur scapy (+contrib lldp/cdp), psutil, structlog.
  `cernis-sniffd` wird zweiter Tauri-externalBin neben `cernis-backend`. deb-/rpm-Postinstall
  setzen CAP_NET_RAW auf `/usr/bin/cernis-sniffd` statt aufs Backend. Im Dev traegt der
  venv-Python-Interpreter die Cap (Helferskript `scripts/dev-setcap-sniffd.sh`), weil eine
  Capability nicht auf eine .py-Datei gesetzt werden kann.

- **Ehrliche Rechte-Semantik (S3-frei):** Scheitert Spawn/Connect oder fehlt das Recht,
  liefert der Helfer einen ehrlichen ERROR-Text (kein Crash, keine stille Leer-Erfassung);
  der `check_permission`-Pfad bleibt optimistisch (None), die echte Pruefung macht der reale
  Sniff-Start ueber die ERROR-Naht.

## Konsequenzen

**Positiv:**
- Nur noch eine winzige Komponente traegt CAP_NET_RAW; das grosse Backend ist unprivilegiert.
  Die S5-Lehre ist erfuellt, ohne Karls Kernwunsch (lautlose Cap bei Installation) aufzugeben.
- Der Helfer-Importgraph ist nachweislich fastapi-frei (Binary-Pruefung: keine fastapi/uvicorn-
  Strings; Start-Smoke PING->PONG, Exit 0).
- Plattform-uebertragbar: Linux setcap heute; macOS Entitlement / Windows Npcap-Dienst spaeter
  am selben Naht-Modell.

**Negativ / bewusst offen:**
- Mehr bewegliche Teile (zweiter Prozess, IPC, zweite Binary im Build) statt eines Monolithen.
- Der privilegierte Traceroute-Pfad (ICMP via `traceroute -I`, gated an `geteuid()==0`) ist
  durch das nun rootlose Backend toter Code geworden -- bewusst markiert, nicht entfernt
  (siehe Abgrenzung).

## Abgrenzung

- **Traceroute NICHT in den Helfer gezogen (Variante A + Aufraeumen):** Der privilegierte
  ICMP-Traceroute nutzte KEINEN Raw-Socket im Backend, sondern das externe `traceroute -I`-
  Binary mit `geteuid()`-Pruefung (Sorte B, nicht Sniff-Helfer-Familie). Nach Weg 2 ist das
  Backend rootlos -> `geteuid()==0` nie wahr -> der Zweig ist tot. Der rootlose UDP-Pfad bleibt
  alleiniger Normalpfad (Funktionsverlust im Heimnetz praktisch klein). Ein nativer
  ICMP-Traceroute im Helfer waere Neuentwicklung (kein erprobter Code), schwer CI-testbar ->
  bewusst zurueckgestellt als Roadmap-Posten (gekoppelt an Topologie/Route/Multi-Subnetz).
- **Kein Windows-Capability-Schritt in diesem Block:** Windows braucht Npcap (+ ggf. Admin);
  der nsis-Hook vergibt heute keine Capability -- bekannter Roadmap-Aufwand.
- **Kein Backend-Refactor der Sniff-Adapter ueber das Noetige hinaus:** Die Zuordnung
  (psutil/match_snapshot/observed) bleibt backend-seitig; nur der rohe Sniff wanderte in den
  Helfer.
