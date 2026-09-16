"""Tests fuer den Monitor-Targets-Schreibpfad (M.9-Nachzuegler) gegen ein Fake-Repo.

Reine application-Schicht: KEINE echte Settings-DB. Ein aufzeichnender Fake-
``SettingsRepository`` belegt, dass ``AddMonitorTarget`` an die
``monitor_custom_targets``-Liste appended und ``DeleteMonitorTarget`` nach ``id``
filtert -- jeweils ueber ``get`` + ``set(Setting)``. Der Spy auf den GESCHRIEBENEN
Wert ist der eigentliche Vertrag.
"""

from typing import Any, cast

from application.monitoring import AddMonitorTarget, DeleteMonitorTarget
from domain.monitoring import CUSTOM_TARGETS_KEY
from domain.settings import Setting, SettingValue


class _FakeSettingsRepo:
    """Aufzeichnender ``SettingsRepository``-Fake (erfuellt das Protocol strukturell)."""

    def __init__(self, initial: list[dict[str, Any]] | None = None) -> None:
        self._store: dict[str, SettingValue] = {}
        if initial is not None:
            self._store[CUSTOM_TARGETS_KEY] = cast(SettingValue, initial)

    def get_all(self) -> dict[str, SettingValue]:
        return dict(self._store)

    def get(self, key: str) -> Setting | None:
        if key not in self._store:
            return None
        return Setting(key=key, value=self._store[key])

    def set(self, setting: Setting) -> None:
        self._store[setting.key] = setting.value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear_all(self) -> None:
        """Leert den kompletten Settings-Store (No-op-Vertrag fuer den Fake)."""
        self._store.clear()

    def written(self) -> list[dict[str, Any]]:
        """Der zuletzt geschriebene Custom-Targets-Wert als typisierte Liste (Spy-Ziel)."""
        value = self._store.get(CUSTOM_TARGETS_KEY)
        assert isinstance(value, list)
        return cast(list[dict[str, Any]], value)


def test_add_appended_an_leere_liste() -> None:
    """Auf einen nicht gesetzten Key haengt Add das erste Target an (Altcode-Feldform)."""
    repo = _FakeSettingsRepo()
    add = AddMonitorTarget(repo)

    add(target_id="t1", label="Server", host="10.0.0.5")

    assert repo.written() == [
        {"id": "t1", "label": "Server", "host": "10.0.0.5", "interface": "", "enabled": True}
    ]


def test_add_appended_an_bestehende_liste() -> None:
    """Add erhaelt die bestehenden Eintraege und haengt nur an (kein Ueberschreiben)."""
    existing = [{"id": "t0", "label": "Alt", "host": "1.1.1.1", "interface": "", "enabled": True}]
    repo = _FakeSettingsRepo(initial=existing)
    add = AddMonitorTarget(repo)

    add(target_id="t1", label="Neu", host="2.2.2.2", interface="eth0", enabled=False)

    written = repo.written()
    assert isinstance(written, list)
    assert len(written) == 2
    assert written[0]["id"] == "t0"
    assert written[1] == {
        "id": "t1",
        "label": "Neu",
        "host": "2.2.2.2",
        "interface": "eth0",
        "enabled": False,
    }


def test_delete_filtert_nach_id() -> None:
    """Delete entfernt genau das Target mit passender id, die anderen bleiben."""
    existing = [
        {"id": "t1", "label": "A", "host": "1.1.1.1", "interface": "", "enabled": True},
        {"id": "t2", "label": "B", "host": "2.2.2.2", "interface": "", "enabled": True},
    ]
    repo = _FakeSettingsRepo(initial=existing)
    delete = DeleteMonitorTarget(repo)

    delete("t1")

    written = repo.written()
    assert isinstance(written, list)
    assert [entry["id"] for entry in written] == ["t2"]


def test_delete_unbekannte_id_ist_idempotent() -> None:
    """Eine unbekannte id filtert nichts heraus (kein Fehler) -- die Liste bleibt."""
    existing = [{"id": "t1", "label": "A", "host": "1.1.1.1", "interface": "", "enabled": True}]
    repo = _FakeSettingsRepo(initial=existing)
    delete = DeleteMonitorTarget(repo)

    delete("does-not-exist")

    assert repo.written() == existing
