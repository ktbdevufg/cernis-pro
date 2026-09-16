"""Tests fuer ``escape_applescript_literal`` -- Escaping fuer AppleScript-Literale."""

from infrastructure.osascript_escape import escape_applescript_literal


def test_escapes_double_quote() -> None:
    """Ein ``"`` wird zu ``\\"`` -- das Ergebnis enthaelt kein unescaptes ``"``."""
    result = escape_applescript_literal('foo"bar')
    assert result == 'foo\\"bar'
    # Kein unescaptes " mehr im Ergebnis: jedes " ist von einem \\ vorangestellt.
    assert '\\"' in result
    assert result.count('"') == result.count('\\"')


def test_escapes_backslash() -> None:
    """Ein ``\\`` wird verdoppelt (``\\`` -> ``\\\\``)."""
    assert escape_applescript_literal("foo\\bar") == "foo\\\\bar"


def test_backslash_before_quote_order() -> None:
    """Backslash zuerst, dann Quote: ``\\"`` -> Backslash verdoppelt, dann Quote escaped."""
    assert escape_applescript_literal('\\"') == '\\\\\\"'


def test_plain_value_unchanged() -> None:
    """Ein normaler Wert ohne ``"``/``\\`` bleibt unveraendert."""
    assert escape_applescript_literal("Netzwerk ist offline") == "Netzwerk ist offline"
