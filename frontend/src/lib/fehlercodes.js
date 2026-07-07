// Zentrale Fehlercode-Tabelle (CERNIS PRO 2.0)
//
// Jeder nutzerrelevante Fehler traegt einen stabilen Code E-xxx, der dem Nutzer
// zusammen mit der Meldung angezeigt wird (z.B. "Speichern fehlgeschlagen (E-501)").
// Diese Tabelle ist die EINZIGE Quelle der Codes im Frontend — ein neuer Fehler =
// ein neuer Eintrag hier plus der passende Kurztext in i18n (Zweig fehlercodes.*).
//
// Die Codes sind statische Konstanten (kein DB-/Backend-Zugriff): Start- und
// Backend-Fehler E-1xx muessen ohne laufendes Backend anzeigbar bleiben. Die
// E-1xx selbst leben im nativen Splash (splash.html/Rust) — sie sind hier nur der
// Vollstaendigkeit halber gelistet, damit das Handbuch und die Tabelle sie kennen.
//
// Schema (Klassen):
//   E-1xx Start und Backend        (im Splash, hier nur referenziert)
//   E-2xx Laufzeit-Verbindung
//   E-3xx Rechte
//   E-4xx Externe Dienste
//   E-5xx Aktionen und Daten

// Alle bekannten Codes als benannte Konstanten. Der Wert ist der sichtbare Code.
// Zugriff im Code ueber CODES.E_201 usw. — der Bindestrich im sichtbaren Code
// wird im Bezeichner zum Unterstrich (JS-Bezeichner duerfen kein "-" enthalten).
export const CODES = Object.freeze({
  // E-1xx Start und Backend (nativer Splash, hier nur referenziert)
  E_101: "E-101",
  E_102: "E-102",
  E_103: "E-103",
  E_104: "E-104",
  // E-2xx Laufzeit-Verbindung
  E_201: "E-201",
  E_202: "E-202",
  E_203: "E-203",
  E_204: "E-204",
  E_205: "E-205",
  // E-3xx Rechte
  E_301: "E-301",
  // E-4xx Externe Dienste
  E_401: "E-401",
  E_402: "E-402",
  E_403: "E-403",
  E_404: "E-404",
  // E-5xx Aktionen und Daten
  E_501: "E-501",
  E_502: "E-502",
  E_503: "E-503",
  E_504: "E-504",
  E_505: "E-505",
  E_506: "E-506",
});

// Liste aller Codes in fester Reihenfolge (fuer Handbuch/Tabellen-Ausgabe).
export const ALLE_CODES = Object.freeze(Object.values(CODES));

// Der i18n-Key zu einem Code liegt unter dem Zweig fehlercodes.<code>, also z.B.
// "fehlercodes.E-201". Diese Funktion baut ihn — so muss der Zweig-Praefix nicht
// an jeder Aufrufstelle wiederholt werden.
export function i18nKeyFuerCode(code) {
  return `fehlercodes.${code}`;
}

// Haengt einen Fehlercode einheitlich an eine Meldung: "meldung (E-xxx)".
// EINE Stelle fuer das Anzeigeformat, damit alle Fehler gleich aussehen. Ein
// bereits vorhandener Satzpunkt am Ende bleibt erhalten ("Speichern
// fehlgeschlagen. (E-501)"). Fehlt entweder Meldung oder Code, wird der jeweils
// vorhandene Teil unveraendert zurueckgegeben (kein "undefined" im Text).
export function mitCode(meldung, code) {
  const text = meldung == null ? "" : String(meldung);
  if (!code) {
    return text;
  }
  if (!text) {
    return `(${code})`;
  }
  return `${text} (${code})`;
}

export default { CODES, ALLE_CODES, i18nKeyFuerCode, mitCode };
