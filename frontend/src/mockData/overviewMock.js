// PLATZHALTER — bei Anbindung an echte API entfernen (siehe Auftrag).
//
// Einzige Datenquelle der Überblick-Ansicht. Die View kennt nur diese Struktur,
// nicht ihre Herkunft. Bei echter Anbindung wird der Import in OverviewView.jsx
// auf den API-Datenfluss umgestellt und diese Datei gelöscht.
//
// Texte sind hier NICHT enthalten — nur Schlüssel und Zahlen. Die View löst
// Titel/Untertitel über i18n auf. So bleibt der Mock sprachneutral.

// Lage-Befunde ("Auffälliges zuerst"). Jeder Eintrag verweist per i18nKey auf
// die Texte in de.json/en.json (overview.findings.<key>.title/.subtitle).
export const auffaelligkeiten = [
  { id: "neues-geraet", i18nKey: "newDevice", icon: "smartphone", severity: "med" },
  { id: "ausgehende-verbindung", i18nKey: "outboundConnection", icon: "globe", severity: "med" },
];

// Verdichtete Kennzahlen (Karten-Grid). Reihenfolge ist die Anzeigereihenfolge.
export const kennzahlen = [
  { id: "apps-mit-verkehr", i18nKey: "appsWithTraffic", value: 12 },
  { id: "aktive-verbindungen", i18nKey: "activeConnections", value: 48 },
  { id: "geraete-im-netz", i18nKey: "devicesOnNetwork", value: 7 },
];

// Komplettes Mock-Lagebild für Zustand B ("Daten vorhanden").
export const overviewMock = {
  auffaelligkeiten,
  kennzahlen,
};

export default overviewMock;
