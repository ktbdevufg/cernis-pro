# Herkunft der abgelegten Lizenztexte

Dieses Verzeichnis haelt die Volltexte jener Lizenzen, die von mitgelieferten
Fremdbestandteilen benoetigt werden, aber **von keinem der Pakete selbst als Datei
mitgeliefert** werden. Die Benennung folgt der REUSE-Spezifikation: eine Datei je
SPDX-Bezeichner, Dateiname gleich Bezeichner mit der Endung `.txt`.

Die Texte sind **unveraendert** abgelegt: nicht gekuerzt, nicht neu umbrochen, nicht
uebersetzt. Die Pruefsumme unten belegt das.

Erzeugt und geprueft wird die Zuordnung von `scripts/gen_license_manifest.py`.

## Vorrang der Paketdatei

Diese Ablage ist der **zweite** Rang, nicht der erste. Bringt ein Paket eine eigene
Lizenzdatei mit, wird immer diese verwendet; die hier abgelegte Fassung greift nur,
wenn das Paket keine fuehrt. Die Aufstellung vermerkt zu jedem Bestandteil, aus
welcher Quelle sein Text stammt (`paketdatei`, `spdx_ablage`, `werk_lizenz` oder
`nicht_belegt`).

## GPL-2.0-only ist bewusst NICHT hier abgelegt

Fuer `GPL-2.0-only` liegt in diesem Verzeichnis **absichtlich keine Datei**. Die
SPDX-Fassung dieses Bezeichners ist gemessen unvollstaendig; ihr fehlen gegenueber
den beiden im Projekt vorliegenden GPLv2-Volltexten:

1. der **gesamte Schlussabsatz** („This General Public License does not permit
   incorporating your program into proprietary programs. …"), und
2. die **wiederholte Ueberschrift** `GNU GENERAL PUBLIC LICENSE` vor dem Abschnitt
   „TERMS AND CONDITIONS".

Fuer `GPL-2.0-only` gilt daher ausschliesslich die **Wurzel-`LICENSE`** des Projekts.
Das Werkzeug verweist dort auf sie und greift nie auf eine SPDX-Fassung zurueck.
Der Befund stammt aus dem Textvergleich der Messung S71-L3, Block N.4 (Wortebene:
98,12 % Uebereinstimmung, 12 Abweichungsstellen, davon zwei inhaltliche).

## Die abgelegten Texte

Alle sechs Texte stammen aus der SPDX-Lizenzliste, je Bezeichner aus dem
Einzeldokument `https://spdx.org/licenses/<Bezeichner>.json`, Feld `licenseText`.

| Merkmal | Wert |
|---|---|
| Bezugsquelle | `https://spdx.org/licenses/<Bezeichner>.json` |
| Gegenprobe der Fassung | `https://spdx.org/licenses/licenses.json` (HTTP 200, 332 451 Bytes) |
| **Fassung der SPDX-Lizenzliste** | **3.28.0** |
| **`releaseDate` der Liste** | **2026-02-20T00:00:00Z** |
| Zahl der gefuehrten Lizenzen | 727 |
| **Abrufdatum** | **2026-08-02** |
| Abrufweg | `curl` gegen die genannten Adressen, HTTP 200 fuer jeden der sechs Abrufe |

| Bezeichner | Name laut SPDX | Bytes | SHA-256 |
|---|---|---:|---|
| `MIT` | MIT License | 1 078 | `b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5` |
| `Apache-2.0` | Apache License 2.0 | 10 280 | `074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff` |
| `BSD-3-Clause` | BSD 3-Clause "New" or "Revised" License | 1 460 | `5a93d5831e1297ab10fe643e1a631e83be392896da14ee2951285a79012df69d` |
| `CC0-1.0` | Creative Commons Zero v1.0 Universal | 7 048 | `a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499` |
| `MPL-2.0` | Mozilla Public License 2.0 | 16 727 | `66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172` |
| `PDDL-1.0` | Open Data Commons Public Domain Dedication & License 1.0 | 15 485 | `561ca6d9bba2a5b8658466833b15035f64d067fc327d226250f5123aa96e82af` |

Kein Eintrag ist bei SPDX als veraltet gefuehrt (`isDeprecatedLicenseId: false` fuer
alle sechs).

## Wozu die einzelnen Texte gebraucht werden

| Bezeichner | Anlass |
|---|---|
| `MIT` | 25 Bestandteile fuehren MIT als Bezeichner, bringen aber keine eigene Lizenzdatei mit (ganz ueberwiegend Rust-Crates, dazu `html-parse-stringify` und die beiden `@tauri-apps`-Plugins, deren `LICENSE.spdx` ein Metadatensatz ohne Wortlaut ist). |
| `Apache-2.0` | 13 Bestandteile ohne eigene Datei. |
| `BSD-3-Clause` | 1 Bestandteil ohne eigene Datei. |
| `MPL-2.0` | `certifi` und die Crate `selectors`. Die Datei `certifi-*.dist-info/licenses/LICENSE` ist 989 Zeichen lang und enthaelt nur einen MPL-Kopfblock, nicht den Volltext (16 727 Zeichen). |
| `CC0-1.0` | Die Geo-Zuordnung und die DoH-Werksliste. Die beiliegende `asn-country-LICENSE.txt` benennt die Lizenz, fuehrt aber keinen Wortlaut. |
| `PDDL-1.0` | Die ASN-Zuordnung. Die beiliegende `iptoasn-asn-LICENSE.txt` benennt die Lizenz ebenfalls nur. |

**Zum MIT-Text ausdruecklich:** Die SPDX-Fassung fuehrt an der Stelle des
Urhebervermerks die Platzhalter `Copyright (c) <year> <copyright holders>`. Diese
Platzhalter sind **kein Urhebervermerk**. Das Werkzeug uebernimmt sie nie als solchen;
wo kein echter Vermerk aus der Paketquelle vorliegt, bleibt das Feld leer und die
Quelle `nicht_belegt`.

## Unter welcher Lizenz die SPDX-Daten selbst stehen

**Soweit belegbar — und nur teilweise belegbar.** Gemessene Fundstellen:

1. Das Repo `spdx/license-list-data`, aus dem die JSON-Dateien erzeugt werden, fuehrt
   **selbst keine `LICENSE`-Datei** (Abruf der Rohdatei: HTTP 404; GitHub-API
   `/license`: HTTP 404, `license: None`). Sein `README.md` verweist im Abschnitt
   „Licensing Information" fuer die Lizenzangabe auf die jeweiligen Quell-Repos.
2. Das Quell-Repo `spdx/license-list-XML` meldet ueber die GitHub-API
   `NOASSERTION ('Other')`. Die dort referenzierte Datei ist ein Shell-Skript, keine
   Lizenzangabe — eine Fehlerkennung der GitHub-Lizenzerkennung.
3. Die SPDX-Lizenzliste beschreibt sich selbst als „an integral part of the SPDX
   Specification". Die Spezifikation (`spdx/spdx-spec`, `LICENSE`) steht unter
   **Community Specification License 1.0 (`Community-Spec-1.0`)**, Altbestaende unter
   **Creative Commons Attribution 3.0 Unported (`CC-BY-3.0`)**.
4. `accessingLicenses.md` nennt `CC-BY-3.0` ausdruecklich fuer das
   **Tech-Report-Dokument**, nicht fuer die Lizenzdaten.
5. Der Fussbereich von `spdx.org/licenses/` fuehrt „© 2018 SPDX Workgroup a Linux
   Foundation Project. All Rights Reserved."

**Ergebnis:** Eine Lizenzdatei, die sich ausdruecklich auf die JSON-Datendateien
bezieht, existiert nicht. Die Angabe ist damit **teilweise nicht ermittelbar** und
wird hier als solche gefuehrt, statt sie zu vereinheitlichen. Die Fundstellen stammen
aus der Messung S71-L3, Block N.2.
