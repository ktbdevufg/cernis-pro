# CERNIS PRO 2.0.0 — Release-Notes

**Release-Datum:** 2026-07-09
**Tag:** `v2.0.0` · **Build-Commit:** `a134fd8` (rewrite/v2, CI gruen)
**Lizenz:** GPL-2.0-only
**Plattform:** Linux x86_64 (amd64) — deb, rpm, AppImage

---

## Ueberblick

CERNIS PRO 2.0.0 ist ein vollstaendiger, strukturierter Backend-Rewrite von v1.0.0. Aus einem
FastAPI-Monolithen (~1.961 Zeilen `main.py`, kein Test) wurde eine hexagonale, maschinell
architektur-gepruefte, durchgaengig getestete Anwendung. Dies ist die erste vollstaendige,
auf drei Distributionen verifizierte Freigabe.

---

## Installation

Drei Paketformate stehen zur Wahl. Die Version ist ueberall `2.0.0`; die unterschiedlichen
Dateinamen (`amd64` vs. `x86_64`, Unterstriche vs. Bindestriche) folgen den jeweiligen
Plattform-Konventionen.

**Debian / Ubuntu (deb):**
```
sudo apt install ./CernisPro_2.0.0_amd64.deb
```
Getestet auf Debian 13 (trixie) und Ubuntu 24.04 LTS. `apt` loest die Abhaengigkeiten auf
(nicht `dpkg -i` verwenden).

**Fedora und verwandte (rpm):**
```
sudo dnf install ./CernisPro-2.0.0-1.x86_64.rpm
```
Getestet auf Fedora 44 (SELinux Enforcing, firewalld aktiv — keine Anpassung noetig).

**AppImage (ohne Installation):**
```
chmod +x CernisPro_2.0.0_amd64.AppImage
./CernisPro_2.0.0_amd64.AppImage
```

### Wichtige Einschraenkung des AppImage

Das AppImage laeuft ohne Installation und ohne Root-Rechte. Deshalb kann es die Berechtigung
`cap_net_raw` nicht einrichten, die der Sniff-Helfer zum passiven Mitlesen benoetigt.
**Konsequenz: Die Funktion „Echte Domainnamen" (SNI) unter Aussenkontakte funktioniert im
AppImage nicht.** Alle anderen Funktionen — Netzwerk-Scan, Live-Monitoring, CVE-Abgleich,
Aussenkontakte auf Betreiber-Ebene, Topologie, Berichte — laufen vollstaendig. Wer SNI nutzen
moechte, installiert CERNIS PRO als deb oder rpm. Es ist dieselbe Version, nur anders verpackt.

Das AppImage benoetigt zudem eine grafische Sitzung (X11 oder Wayland); ein Start aus einer
reinen Textkonsole schlaegt fehl.

### Systemvoraussetzungen

64-Bit-Linux (x86_64/amd64) mit grafischer Oberflaeche. Getestet: Debian 13, Ubuntu 24.04,
Fedora 44; aeltere gepflegte Ausgaben (Debian 12, Ubuntu 22.04, Fedora 40) sollten ebenfalls
laufen. Die Anzeige nutzt WebKitGTK (`libwebkit2gtk-4.1`). ARM-Versionen sind noch nicht
verfuegbar.

---

## Kernpunkte gegenueber v1.0.0

**Architektur**
- Hexagonale 5-Ring-Architektur (domain ← ports ← application ← infrastructure ← api), per
  import-linter mit 8 Contracts CI-hart erzwungen.
- Ein Repository-Adapter statt verstreuter SQLite-Zugriffe; Dependency Injection im Composition Root.
- Durchgaengige Typisierung (mypy strict), keine toten Pfade, keine stillen Fallbacks.
- Vollstaendige Test-Abdeckung als CI-Gate (5-Gate-Kette, 3027 Tests).

**Funktionsumfang**
- Passives Live-Monitoring, Aussenkontakte-Aufzeichnung, netzweiter DNS-Waechter, Verhaltensprofile.
- Mehrstufige Gegenstellen-Aufloesung (resolver + SNI) — neutrale Fakten statt Urteil.
- Sechs Berichtstypen (Sicherheit, Bestand, CVE, Aussenkontakte, DNS-Waechter, Verhaltensprofil), PDF.
- CVE-Monitoring gegen den Geraete-Bestand; FritzBox-Detailauslese (TR-064).
- Standardzugangs-Pruefung als scharfe, geraete-/modellbasierte Opt-in-Sonderfunktion.
- Dynamisches Nutzungs-Ranking im Startseiten-Schnellzugriff.
- Benutzerhandbuch als reportlab-PDF (DE/EN), In-App-Hilfe.

**Sicherheit**
- Vollstaendiger v2-Sicherheits-Audit (9 Befunde dokumentiert, behoben/bewusst zurueckgestellt).
- Privilege-Separation: nur der Sniff-Helfer `cernis-sniffd` traegt CAP_NET_RAW.

**Paketierung & Build (neu in dieser Freigabe)**
- Reproduzierbarer Build in einer Debian-13-Container-Werkbank; ein Build erzeugt deb, rpm und
  AppImage aus denselben Binaries.
- Alle externen Kommandos mit erzwungener C-Locale — korrekte Messwerte unabhaengig von der
  Systemsprache.

**Lizenz**
- GPL-2.0-only. Lizenz-Audit dokumentiert Vertraeglichkeit aller ausgelieferten Abhaengigkeiten und
  den bekannten offenen Punkt (requests/Apache via fritzconnection).

---

## Bekannte offene Punkte (v2.1 / spaeter)

- AppImage ohne SNI (siehe oben) — prinzipbedingt.
- Hersteller-Normalisierung bei der Standardzugangs-Pruefung (AVM-Matching).
- requests/Apache-Lizenz-Spannung — bei erhoehten Compliance-Anforderungen juristisch zu bewerten;
  GPLv3 waere nur nach Abloesung von scapy moeglich.
- Zurueckgestellt: F-01 Etappe 2 (lokaler Shared-Token), F-08 (esbuild/vite dev-only).

---

## Ausblick

Multi-Plattform-Roadmap (naechster Schritt: ARM), GUI-Redesign-Block, v3.0-Ideen
(IoT-/Geraeteklassen-Erfassung, TR-064-Router-Adapter, KI-Konzept).
