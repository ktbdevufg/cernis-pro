"""Tests fuer ``desktop_notifier.notify_macos`` (A.8) -- AppleScript-Injection geheilt.

Alles ueber Mocks, KEIN echtes ``osascript`` (die CI ist Linux). Kern: ein ``"`` in
``message``/``title``/``subtitle`` (Werte stammen aus Geraetenamen -- AUS DEM NETZWERK)
wird korrekt escaped und bricht NICHT aus dem AppleScript-Double-Quoted-Literal aus.
"""

import subprocess
from typing import Any

import pytest

from infrastructure.alerting import desktop_notifier


def _capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], **kwargs: Any) -> None:
        seen["args"] = args
        seen["kwargs"] = kwargs

    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def test_calls_osascript_as_arg_list_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    desktop_notifier.notify_macos("Title", "Message")
    assert seen["args"][0] == "osascript"
    assert seen["args"][1] == "-e"
    # kein shell=True -> keine zusaetzliche Shell-Injection.
    assert seen["kwargs"].get("shell") in (None, False)
    assert seen["kwargs"]["timeout"] == 3


def test_double_quote_in_message_is_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    # Ein Geraetename mit " -- der Altcode-Injection-Vektor.
    desktop_notifier.notify_macos("Title", 'Bob\'s "Router"')
    script = seen["args"][2]
    # Das " im Wert erscheint escaped (\"), nicht roh -> kein Ausbruch aus dem Literal.
    assert '\\"Router\\"' in script
    # Der message-Teil steht in seinem Literal; das schliessende Literal + " with title"
    # folgt UNBESCHAEDIGT -- ein Ausbruch haette diese Struktur zerrissen.
    assert '" with title "' in script


def test_double_quote_in_title_is_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    desktop_notifier.notify_macos('Ev"il', "Message")
    script = seen["args"][2]
    assert 'Ev\\"il' in script


def test_double_quote_in_subtitle_is_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    desktop_notifier.notify_macos("Title", "Message", subtitle='sub"title')
    script = seen["args"][2]
    assert 'subtitle "sub\\"title"' in script


def test_backslash_is_escaped_first(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    desktop_notifier.notify_macos("Title", "a\\b")
    script = seen["args"][2]
    # Backslash verdoppelt (\\), damit ein spaeter eingefuegter Escape-Backslash sauber ist.
    assert "a\\\\b" in script


def test_no_subtitle_omits_subtitle_clause(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture(monkeypatch)
    desktop_notifier.notify_macos("Title", "Message")
    script = seen["args"][2]
    assert "subtitle" not in script
    assert 'sound name "Basso"' in script


def test_missing_osascript_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Auf Linux fehlt osascript -> FileNotFoundError. Die Funktion schluckt NICHTS;
    # der Aufrufer (AlertNotifierAdapter.macos) faengt das und loggt.
    def boom(args: list[str], **kwargs: Any) -> None:
        raise FileNotFoundError("osascript")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(FileNotFoundError):
        desktop_notifier.notify_macos("Title", "Message")
