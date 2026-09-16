# CERNIS Pro

**Aktuelle stabile Version: 2.1.2**

*[English version below](#cernis-pro-english)*

---

## Deutsch

CERNIS Pro ist ein lokaler, plattformübergreifender LAN-Scanner für Privathaushalte,
Homeoffice und kleine Büros. Die Anwendung erfasst die Geräte im eigenen Netz, ordnet sie
ein und beobachtet Veränderungen über die Zeit.

### Plattformen

Windows, macOS und Linux.

### Arbeitsweise und Netzwerkzugriffe

CERNIS Pro läuft als lokale Desktop-Anwendung; Scan und Auswertung finden auf dem eigenen
Rechner statt. Einzelne Funktionen greifen darüber hinaus auf das Netzwerk zu — teils
funktionsbedingt, teils optional und nur nach Konfiguration:

- Scan und Beobachtung des lokalen Netzes (funktionsbedingt)
- Abgleich erkannter Dienste mit öffentlichen CVE-Einträgen der NVD
- RDAP-Abfragen zur Einordnung externer Gegenstellen
- optionaler externer Erreichbarkeitscheck (nur aktiv, wenn URL und Token gesetzt sind)
- optionaler E-Mail-Versand von Benachrichtigungen über einen selbst konfigurierten
  SMTP-Server

Setzen Sie CERNIS Pro ausschließlich in Netzen ein, die Ihnen gehören oder für die Sie
ausdrücklich autorisiert sind.

### Links

- Projektwebsite: <https://cernispro.de/>
- Downloads: <https://cernispro.de/downloads/>
- Versionshinweise 2.1.2: [`docs/RELEASE_NOTES_v2.1.2.md`](docs/RELEASE_NOTES_v2.1.2.md)

### Technologie

- Backend: Python, FastAPI
- Frontend: React, Vite
- Desktop-Rahmen: Tauri v2 (Rust)
- Paketierung: PyInstaller, NSIS, deb, rpm, dmg

### Bauen und Paketieren

Das Repository enthält die verwendeten Build- und Packaging-Skripte: `build.sh`,
`build-linux.sh`, `build.ps1` und `build-in-docker.sh` samt Dockerfiles, die
PyInstaller-Spezifikationen unter `backend/`, die Paket-Skripte unter `src-tauri/` sowie
die CI-Workflows unter `.github/workflows/`.

### Lizenz

CERNIS Pro steht unter **GPL-2.0-only**.

- Lizenztext: [`LICENSE`](LICENSE)
- Texte der Fremdlizenzen: [`LICENSES/`](LICENSES/)
- Übersicht der Fremdbestandteile:
  [`docs/THIRD_PARTY_LICENSES.md`](docs/THIRD_PARTY_LICENSES.md)

Mitgelieferte Fremdbestandteile unterliegen weiterhin ihren eigenen Lizenzen. Jedem
Release liegt eine Aufstellung sämtlicher enthaltener Fremdbestandteile bei.

---

## CERNIS Pro (English)

**Current stable version: 2.1.2**

CERNIS Pro is a local, cross-platform LAN scanner for private households, home offices and
small offices. It discovers the devices on your own network, classifies them and tracks
changes over time.

### Platforms

Windows, macOS and Linux.

### How it works and network access

CERNIS Pro runs as a local desktop application; scanning and analysis happen on your own
machine. Beyond that, individual features access the network — some inherently, some
optional and only after configuration:

- scanning and monitoring the local network (inherent to the function)
- matching detected services against public CVE records from the NVD
- RDAP lookups to classify external endpoints
- optional external reachability check (active only when URL and token are configured)
- optional e-mail notifications via an SMTP server you configure yourself

Use CERNIS Pro only on networks you own or are explicitly authorised to examine.

### Links

- Project website: <https://cernispro.de/>
- Downloads: <https://cernispro.de/downloads/>
- Release notes 2.1.2: [`docs/RELEASE_NOTES_v2.1.2.md`](docs/RELEASE_NOTES_v2.1.2.md)

### Technology

- Backend: Python, FastAPI
- Frontend: React, Vite
- Desktop shell: Tauri v2 (Rust)
- Packaging: PyInstaller, NSIS, deb, rpm, dmg

### Building and packaging

The repository contains the build and packaging scripts in use: `build.sh`,
`build-linux.sh`, `build.ps1` and `build-in-docker.sh` along with the Dockerfiles, the
PyInstaller specifications under `backend/`, the packaging scripts under `src-tauri/` and
the CI workflows under `.github/workflows/`.

### License

CERNIS Pro is licensed under **GPL-2.0-only**.

- License text: [`LICENSE`](LICENSE)
- Third-party license texts: [`LICENSES/`](LICENSES/)
- Overview of third-party components:
  [`docs/THIRD_PARTY_LICENSES.md`](docs/THIRD_PARTY_LICENSES.md)

Bundled third-party components remain subject to their own licenses. Each release ships
with a manifest of all included third-party components.
