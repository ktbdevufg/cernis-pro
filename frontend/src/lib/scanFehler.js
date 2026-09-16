// Anzeige eines Scan-Fehlers aus dem WS-Strom (CERNIS PRO 2.0)
//
// DER FALL (S88-P2): Ein zu großes Netz wird abgewiesen — die Domäne prüft die
// SUMME der angegebenen Adressen gegen MAX_SCAN_ADRESSEN (4.096) und wirft
// NetzZuGrossError. Der Anwender soll dazu einen erklärenden Text in SEINER
// Sprache sehen, samt der Zahl, die er tatsächlich angegeben hat.
//
// Die Domäne ist sprachfrei (ADR 0002) und trägt keinen Anzeigetext. Sie liefert
// darum ein MASCHINENLESBARES Signal, das Frontend wählt daran den i18n-Schlüssel
// und übersetzt selbst — das Muster, das der Bestand führt (DnsTrustPanel.jsx:46ff:
// „ApiError.status auswerten, kein detail-Parsing"). Über die WS-Naht gibt es
// keinen HTTP-Status, darum trägt das error-Frame das Signal in eigenen Feldern:
//
//   frame.grund  — "netzZuGross" (der maschinenlesbare Wert)
//   frame.anzahl — die gemessene Gesamtzahl als ZAHL
//
// frame.message ist daneben weiterhin vorhanden, ist aber ENGLISCHER
// ENTWICKLERTEXT aus der Domäne und NICHT der Anwendertext. Er dient allein der
// Verträglichkeit für Verbraucher, die `grund` nicht kennen.
//
// Rein (Ursache rein, Anzeige raus), ohne i18n-Bindung: die Funktion gibt einen
// SCHLÜSSEL samt Werten ODER einen fertigen Text zurück, das Auflösen macht die
// Ansicht. Genau darum lässt sie sich direkt und ohne DOM prüfen — Muster
// werkzeugFehler.js.

// Der i18n-Schlüssel des Abweisungstextes für ein zu großes Netz.
export const NETZ_ZU_GROSS_SCHLUESSEL = "beobachten.scan.netzZuGross";

// Der maschinenlesbare Wert, den das Backend im error-Frame sendet.
export const GRUND_NETZ_ZU_GROSS = "netzZuGross";

// Entscheidet, wie ein Fehler aus dem Scan-Strom angezeigt wird.
//
// `nachricht` ist der Text des Backends (oder ein lokaler Transport-Text),
// `frame` das ROHE error-Frame oder null (Transportfehler ohne Frame).
// Zurück kommt:
//   { textKey, werte } — ein i18n-Schlüssel samt Interpolationswerten, ODER
//   { text }           — ein fertiger Text, der NICHT übersetzt wird.
// Immer genau eines von beiden; die jeweils anderen Felder sind null.
//
// `formatiereZahl` formatiert die Adressanzahl sprachabhängig (Tausendertrennung).
// Als Parameter statt fest verdrahtet, damit die Funktion rein bleibt und ohne
// i18n-Kontext prüfbar ist; die Ansicht reicht `(n) => n.toLocaleString(sprache)`
// herein (Muster LoggingPanel.jsx:81ff).
export function waehleScanFehlerAnzeige(nachricht, frame, formatiereZahl) {
  const anzahl = frame?.anzahl;
  if (frame?.grund === GRUND_NETZ_ZU_GROSS && Number.isFinite(anzahl)) {
    // Der übersetzte Abweisungstext mit der GEMESSENEN Gesamtzahl.
    return {
      textKey: NETZ_ZU_GROSS_SCHLUESSEL,
      werte: { anzahl: formatiereZahl(anzahl) },
      text: null,
    };
  }
  // Jeder andere Fehler: unverändert der bisherige Weg — der Text des Backends.
  // KEIN Rückfall auf einen erfundenen Grund: wer `grund` nicht sendet (oder eine
  // unbrauchbare `anzahl`), bekommt genau das bisherige Verhalten.
  return { textKey: null, werte: null, text: nachricht ?? null };
}

export default {
  waehleScanFehlerAnzeige,
  NETZ_ZU_GROSS_SCHLUESSEL,
  GRUND_NETZ_ZU_GROSS,
};
