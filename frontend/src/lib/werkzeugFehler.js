// Anzeige eines 503 "Werkzeug/Daten fehlen" (CERNIS PRO 2.0)
//
// DER BEFUND (61): Zwei Ansichten zeigten bei einem 503 einen FESTEN Satz, der
// ein bestimmtes Programm benannte — RouteView behauptete stets „traceroute“,
// obwohl derselbe Statuscode auch aus dem Resolver kommt (dort fehlt „dig“:
// ResolverToolMissing, oder eine Geo/ASN-CSV: ResolverDataMissing). LookupPanel
// wertete den Fehler gar nicht aus und verwarf beide 503er.
//
// Das Backend liefert den echten Grund im Wortlaut mit (FastAPI {"detail": ...});
// seit S84-A7 trägt ApiError.detail ihn auch auf dem GET-Weg (api/client.js).
// Diese Funktion entscheidet daraus, WAS angezeigt wird:
//
//   * detail vorhanden  -> genau dieser Text, UNVERÄNDERT. Er kommt von der
//     Stelle, die den Fehlschlag wirklich kennt — er wird nicht gedeutet,
//     gekürzt oder ergänzt.
//   * detail fehlt      -> der neutrale Rückfallschlüssel. Er behauptet KEIN
//     bestimmtes Programm, weil an dieser Stelle keines bekannt ist.
//
// Rein (Ursache rein, Anzeige raus), ohne i18n-Bindung: die Funktion gibt einen
// SCHLÜSSEL oder einen fertigen TEXT zurück, das Auflösen macht die Ansicht.
// Genau darum lässt sie sich direkt und ohne DOM prüfen (siehe
// backend/tests/test_werkzeug_fehler_texte_naht.py).

// Der gemeinsame Rückfalltext, wenn das Backend keinen Grund mitliefert.
// Bewusst NICHT nach Ansicht getrennt: derselbe Sachverhalt, derselbe Satz.
export const WERKZEUG_RUECKFALL_SCHLUESSEL = "werkzeug.nichtVerfuegbar";

// Entscheidet, wie ein gescheiterter Aufruf angezeigt wird.
//
// `status` ist der HTTP-Status (oder null bei Netzfehler), `detail` der
// Begründungstext des Backends (oder null). Zurück kommt:
//   { textKey }  — ein i18n-Schlüssel, den die Ansicht auflöst, ODER
//   { text }     — ein fertiger Text vom Backend, der NICHT übersetzt wird.
// Immer genau eines von beiden; das jeweils andere Feld ist null.
//
// `fehlerSchluessel` ist der ansichts-eigene Schlüssel für „irgendein anderer
// Fehler“ (RouteView: die Route ließ sich nicht messen; LookupPanel: die
// Auflösung war nicht erreichbar). Er bleibt ansichtsspezifisch, weil er die
// jeweilige Handlung benennt — nur der 503-Fall ist gemeinsam.
export function waehleWerkzeugFehlerAnzeige(status, detail, fehlerSchluessel) {
  if (status !== 503) {
    // Kein Werkzeug-/Daten-Fall: unverändert der ansichts-eigene Fehlertext.
    return { textKey: fehlerSchluessel, text: null };
  }
  const grund = typeof detail === "string" && detail.trim() !== "" ? detail : null;
  if (grund !== null) {
    // Der echte Grund des Backends, im Wortlaut.
    return { textKey: null, text: grund };
  }
  // Kein Grund mitgeliefert: neutraler Satz, der kein Programm behauptet.
  return { textKey: WERKZEUG_RUECKFALL_SCHLUESSEL, text: null };
}

export default { waehleWerkzeugFehlerAnzeige, WERKZEUG_RUECKFALL_SCHLUESSEL };
