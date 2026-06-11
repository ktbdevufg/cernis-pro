"""Domaenenmodell der settings-Domaene: Wertobjekt und Secret-Policy.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber
Persistenz (der KV-Speicher ist Infrastruktur) oder HTTP. Der eigentliche Kern
ist die Secret-Klassifikation und die Redaction-Policy (ADR 0001).
"""

from dataclasses import dataclass

# JSON-serialisierbarer Wert: was im KV-Store eines Settings landen kann.
# Bewusst breit gehalten -- die Typisierung einzelner Keys ist nicht Aufgabe
# dieser Referenz-Domaene (settings ist ein generischer Key-Value-Store).
type SettingValue = (
    None | bool | int | float | str | list["SettingValue"] | dict[str, "SettingValue"]
)


@dataclass(frozen=True)
class Setting:
    """Ein einzelnes Setting: Schluessel + Wert."""

    key: str
    value: SettingValue

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("Setting-Key darf nicht leer sein")


# Keys, deren GESAMTER Wert geheim ist (ADR 0001). smtp_config ist bewusst nicht
# dabei: dort ist nur das verschachtelte Passwort geheim -- das gehoert in die
# kuenftige alerting-Domaene mit eigenem, bereits redigierendem Endpunkt.
# cpnetcheck_token (ADR 0014 Block 2b): der Bearer-Token fuer den externen
# cpnetcheck-Dienst -- als ganzer Wert geheim. Allein durch diesen Eintrag wird er
# automatisch redigiert (GetSettings/redact) und ausschliesslich ueber UpdateSecret
# setzbar; UpdateSetting lehnt ihn via is_secret() ab. Die zugehoerige NICHT-geheime
# URL (cpnetcheck_url) ist KEIN Secret und liegt darum nicht hier.
SECRET_KEYS: frozenset[str] = frozenset({"shodan_api_key", "fritz_password", "cpnetcheck_token"})

# Platzhalter, der einen redigierten Secret-Wert nach aussen ersetzt.
# "[REDACTED]" weil: (1) truthy -> erfuellt die Praesenzpruefung des Frontends
# (`if (d.shodan_api_key) ...`); (2) signalisiert explizit "bewusst entfernt"
# statt einen echten maskierten Wert vorzutaeuschen; (3) ASCII -> keine
# Encoding-Fallen ueber Build-Plattformen.
REDACTED = "[REDACTED]"


def is_secret(key: str) -> bool:
    """Ob der Wert dieses Keys vollstaendig geheim ist."""
    return key in SECRET_KEYS


def _redact_value(key: str, value: SettingValue) -> SettingValue:
    # Nur GESETZTE Secrets maskieren; leere/None-Secrets bleiben falsy, damit
    # das Frontend "nicht gesetzt" anzeigen kann.
    if is_secret(key) and value:
        return REDACTED
    return value


def redact(settings: dict[str, SettingValue]) -> dict[str, SettingValue]:
    """Maskiert gesetzte Secret-Werte fuer die Ausgabe nach aussen (ADR 0001).

    Nicht-Secrets bleiben unveraendert. Niemals wird ein Secret im Klartext
    geliefert -- das ist die Redaction-Policy aus ADR 0001 als reine Funktion.
    """
    return {key: _redact_value(key, value) for key, value in settings.items()}
