// Restzeit-/Status-Logik fuer Logging-Aufgaben (CERNIS PRO 2.0)
//
// Reine, clientseitige Helfer OHNE Backend: aus einem Logging-Task (camelCase, aus
// api/monitoring.mappeLoggingTask) die Rest-Information ableiten. Alle noetigen
// Felder stehen im Task. Gemeinsam genutzt von LoggingPanel (Karten-Restzeit +
// Fortschritt) und dem Kopfzeilen-Pill (naechstes Ende). Kein React-Import: pur,
// damit testbar und uebergreifend nutzbar.
//
// Zeitbasis (ADR 0033, Wanduhr): das Backend liefert Unix-ts in SEKUNDEN
// (time.time()); jetzt() liefert ebenfalls Sekunden (Date.now()/1000). Die
// Pausenzeit zaehlt bei IMMEDIATE mit -- Bezug ist der effektive Start, nicht die
// aktive Laufzeit.

// Zustands-Vokabular des Backends (TaskState-StrEnum-Werte). Hier als Konstanten
// gespiegelt, damit Aufrufer nicht auf rohe Strings angewiesen sind.
export const ZUSTAND = {
  CREATED: "created",
  ACTIVE: "active",
  PAUSED: "paused",
  FINISHED: "finished",
};

// Aktueller Unix-ts in SEKUNDEN (Backend-Zeitbasis). Als Parameter injizierbar
// (Tests/Stabilitaet), Default ist die Wanduhr.
export function jetztSekunden() {
  return Date.now() / 1000;
}

// Leitet das Ende eines Tasks als absoluten Unix-ts ab ODER null, wenn kein Ende
// bestimmbar ist (Felder fehlen modus-abhaengig). KEIN erfundener Wert.
//   SCHEDULED: Ende = plannedEnd.
//   IMMEDIATE: Ende = effectiveStart + maxDurationS (Wanduhr ab effektivem Start).
//     Ohne effectiveStart (Task noch nicht gestartet) ist kein Ende bestimmbar.
export function endeTs(task) {
  if (task.operationMode === "scheduled") {
    return task.plannedEnd ?? null;
  }
  if (task.operationMode === "immediate") {
    if (task.effectiveStart === null || task.maxDurationS === null) {
      return null;
    }
    return task.effectiveStart + task.maxDurationS;
  }
  return null;
}

// Leitet den Start eines Tasks als absoluten Unix-ts ab ODER null.
//   SCHEDULED: Start = plannedStart.
//   IMMEDIATE: Start = effectiveStart (null, solange nicht gestartet).
export function startTs(task) {
  if (task.operationMode === "scheduled") {
    return task.plannedStart ?? null;
  }
  if (task.operationMode === "immediate") {
    return task.effectiveStart ?? null;
  }
  return null;
}

// Restzeit in SEKUNDEN bis zum Ende (>= 0) ODER null, wenn kein Ende bestimmbar
// ist. Negative Werte werden auf 0 geklemmt (abgelaufen, aber nicht "negative
// Restzeit"). jetzt als Parameter injizierbar.
export function restSekunden(task, jetzt = jetztSekunden()) {
  const ende = endeTs(task);
  if (ende === null) {
    return null;
  }
  const rest = ende - jetzt;
  return rest > 0 ? rest : 0;
}

// Fortschritt eines Tasks als Anteil 0..1 ODER null, wenn Start/Ende nicht
// bestimmbar sind (z. B. IMMEDIATE vor dem Start). Geklemmt auf [0,1].
export function fortschrittAnteil(task, jetzt = jetztSekunden()) {
  const start = startTs(task);
  const ende = endeTs(task);
  if (start === null || ende === null || ende <= start) {
    return null;
  }
  const anteil = (jetzt - start) / (ende - start);
  if (anteil < 0) {
    return 0;
  }
  if (anteil > 1) {
    return 1;
  }
  return anteil;
}

// Formatiert eine Dauer in Sekunden menschlich, ueber i18n. Liefert die groebste
// zwei aufeinanderfolgenden Einheiten (Tg+Std, Std+Min, Min+Sek) -- z. B.
// "noch 6 Tg 3 Std" / "noch 4 Std 12 Min". Erwartet die t-Funktion (react-i18next)
// und einen i18n-Praefix (z. B. "beobachten.logging.rest"). Die Keys:
//   {praefix}.tage / .stunden / .minuten / .sekunden  -> "{{value}} Tg" usw.
//   {praefix}.zwei  -> "noch {{erste}} {{zweite}}"   (zwei Einheiten)
//   {praefix}.eine  -> "noch {{erste}}"              (eine Einheit, Rest 0)
//   {praefix}.jetzt -> "jetzt"                       (Rest 0)
export function formatiereRestzeit(sekunden, t, praefix) {
  if (sekunden === null || sekunden === undefined) {
    return null;
  }
  const gesamt = Math.max(0, Math.floor(sekunden));
  if (gesamt === 0) {
    return t(`${praefix}.jetzt`);
  }

  const tage = Math.floor(gesamt / 86400);
  const stunden = Math.floor((gesamt % 86400) / 3600);
  const minuten = Math.floor((gesamt % 3600) / 60);
  const sek = gesamt % 60;

  // Die beiden groebsten nicht-leeren Einheiten waehlen (von Tagen abwaerts).
  const einheiten = [
    [tage, "tage"],
    [stunden, "stunden"],
    [minuten, "minuten"],
    [sek, "sekunden"],
  ];
  const ersterIndex = einheiten.findIndex(([wert]) => wert > 0);
  if (ersterIndex === -1) {
    return t(`${praefix}.jetzt`);
  }

  const [erstWert, erstSchluessel] = einheiten[ersterIndex];
  const erste = t(`${praefix}.${erstSchluessel}`, { value: erstWert });

  // Zweite Einheit (die naechste, falls vorhanden und > 0).
  const zweiteEinheit = einheiten[ersterIndex + 1];
  if (zweiteEinheit && zweiteEinheit[0] > 0) {
    const zweite = t(`${praefix}.${zweiteEinheit[1]}`, { value: zweiteEinheit[0] });
    return t(`${praefix}.zwei`, { erste, zweite });
  }
  return t(`${praefix}.eine`, { erste });
}
