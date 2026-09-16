// Akustischer Signalton-Helfer (CERNIS PRO 2.0)
//
// Reiner, testbarer Web-Audio-Helfer ohne React/i18n-Bezug. Erzeugt einen
// kurzen, dezenten Beep über die Web Audio API. Bewusst vollständig
// fehlertolerant: ein nicht verfügbarer AudioContext oder ein Fehler beim
// Aufbau der Tonkette darf NIE eine Exception bis in die UI durchreichen
// (Hausregel "keine stillen Fallbacks" gilt für Backend-Verhalten; ein rein
// dekorativer Ton bleibt jedoch beste-möglich und stört die App nicht).

// Modulweiter AudioContext, lazy beim ersten Aufruf erzeugt. Vor der ersten
// Nutzerinteraktion legt die Browser-Autoplay-Policy keinen brauchbaren Context
// an — deshalb NICHT auf Modulebene erzeugen, sondern erst im Aufruf.
let audioContext = null;

// Liefert den (lazy erzeugten) AudioContext oder null, falls die Web Audio API
// nicht verfügbar ist. Fängt jeden Fehler ab und gibt dann null zurück.
function holeAudioContext() {
  try {
    if (audioContext === null) {
      const Ctor = window.AudioContext || window.webkitAudioContext;
      if (!Ctor) {
        return null;
      }
      audioContext = new Ctor();
    }
    return audioContext;
  } catch {
    return null;
  }
}

// Spielt einen kurzen, dezenten Beep (~120 ms, ~660 Hz) mit weicher
// Gain-Hüllkurve gegen Klick-Artefakte. Wirft NIE: jeder Fehler (kein Context,
// suspendierter Context, Aufbaufehler) wird verschluckt — der Ton ist Beiwerk.
export function spieleSignalton() {
  try {
    const ctx = holeAudioContext();
    if (!ctx) {
      return;
    }

    // Ein durch die Autoplay-Policy suspendierter Context muss zunächst wieder
    // aufgenommen werden; das Resultat-Promise wird bewusst ignoriert.
    if (ctx.state === "suspended" && typeof ctx.resume === "function") {
      ctx.resume().catch(() => {});
    }

    const jetzt = ctx.currentTime;
    const dauer = 0.12; // ~120 ms
    const spitzePegel = 0.08; // dezent, kein erschreckender Pegel

    const oszillator = ctx.createOscillator();
    oszillator.type = "sine";
    oszillator.frequency.setValueAtTime(660, jetzt);

    // Weiche Hüllkurve: schnell hoch (gegen Anfangsklick), sanft aus.
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, jetzt);
    gain.gain.exponentialRampToValueAtTime(spitzePegel, jetzt + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, jetzt + dauer);

    oszillator.connect(gain);
    gain.connect(ctx.destination);

    oszillator.start(jetzt);
    oszillator.stop(jetzt + dauer);
  } catch {
    // Bewusst geschluckt: ein fehlschlagender Signalton darf die UI nie stören.
  }
}

export default { spieleSignalton };
