"""Tests des SNI-Sniffer-Adapters OHNE echten Subprozess/scapy/Root.

ETAPPE 2 (Privilege-Separation): Der Adapter faehrt scapy nicht mehr selbst, sondern
spricht den Helfer ueber die ``SniffHelperChannel``-Naht an. Wir injizieren einen
Fake-Channel (kontrolliert STARTED/ERROR, speist Hits ein) und pruefen:

* den Zuordnungs-Pfad (``observed()``) ueber direkt gesetzte rohe Hits + synthetische
  Socket-Snapshots -- der ``match_snapshot``-Pfad ist UNVERAENDERT;
* den Hit-Poller (zieht ``channel.poll_hits()`` -> ``_raw_hits`` -> ``observed()``);
* die Lifecycle-Naht (start ok -> is_running True; start ERROR -> SniError);
* die neue (B)-Semantik von ``check_permission`` (optimistisch ``None``, KEINE
  Backend-Raw-Socket-Probe mehr).

KEIN echter scapy/Raw-Socket, KEIN echter Subprozess in diesem Modul.
"""

import os
import time

import pytest

from infrastructure.sni.errors import SniError, SniPermissionError
from infrastructure.sni.sni_sniffer import ScapySniSniffer, _RawHit, _resolve_app_name
from infrastructure.sniffd_client.base import sniffd_platform_supported


class _FakeChannel:
    """In-Memory-``SniffHelperChannel``: kontrolliert START-Antwort + speist Hits ein.

    ``start_error`` ``None`` -> ``start()`` meldet Erfolg und ``is_running()`` wird
    True; ein Text -> ``start()`` gibt ihn zurueck (der Adapter macht eine SniError
    daraus). ``feed`` legt rohe Hit-dicts ab, die der naechste ``poll_hits()`` (genau
    EINMAL) herausgibt -- so wie der echte Channel die seit dem letzten Aufruf
    eingegangenen Hits leert.
    """

    def __init__(self, *, start_error: str | None = None) -> None:
        self._start_error = start_error
        self._running = False
        self._pending: list[dict[str, object]] = []
        self.start_calls: list[str | None] = []
        self.stop_calls = 0

    def start(self, interface: str | None) -> str | None:
        self.start_calls.append(interface)
        if self._start_error is not None:
            return self._start_error
        self._running = True
        return None

    def poll_hits(self) -> list[dict[str, object]]:
        hits = self._pending
        self._pending = []
        return hits

    def stop(self) -> None:
        self.stop_calls += 1
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def feed(self, **hit: object) -> None:
        self._pending.append(hit)


# ── observed(): Zuordnungs-Pfad (UNVERAENDERT) ────────────────────────────────


def test_observed_assigns_nearest_snapshot_and_resolves_name() -> None:
    sniffer = ScapySniSniffer(channel_factory=_FakeChannel)
    # 1 roher Hit bei ts=100.0 auf 93.184.216.34:443.
    sniffer._raw_hits.append(_RawHit("example.com", "93.184.216.34", 443, 100.0))
    # Zwei Snapshots: der bei 100.05 (50 ms) ist naeher und kennt den Endpunkt mit
    # UNSERER PID -> Treffer + Name unseres Prozesses + Delta 50 ms.
    my_pid = os.getpid()
    sniffer._snapshots.append((100.5, {("93.184.216.34", 443): 99999999}))
    sniffer._snapshots.append((100.05, {("93.184.216.34", 443): my_pid}))

    observed = sniffer.observed()
    assert len(observed) == 1
    obs = observed[0]
    assert obs.hostname == "example.com"
    assert obs.remote_ip == "93.184.216.34"
    assert obs.remote_port == 443
    assert obs.pid == my_pid
    assert obs.app_name == _resolve_app_name(my_pid)  # echter Prozessname (nicht None)
    assert obs.delta_ms == 50


def test_observed_unmatched_hit_has_none_fields() -> None:
    sniffer = ScapySniSniffer(channel_factory=_FakeChannel)
    sniffer._raw_hits.append(_RawHit("nomatch.io", "9.9.9.9", 443, 100.0))
    sniffer._snapshots.append((100.0, {("1.2.3.4", 443): 1234}))

    obs = sniffer.observed()[0]
    assert obs.app_name is None
    assert obs.pid is None
    assert obs.delta_ms is None


def test_observed_empty_when_no_hits() -> None:
    assert ScapySniSniffer(channel_factory=_FakeChannel).observed() == []


# ── Hit-Poller: rohe Helfer-Hits -> _raw_hits -> observed() ───────────────────


def test_hit_poller_pulls_channel_hits_into_observed() -> None:
    """Der Hit-Poller zieht ``channel.poll_hits()`` und fuellt ``observed()`` -- end-to-end
    OHNE echten Subprozess. Belegt: ein vom (Fake-)Helfer eingespeister Hit taucht nach
    dem Start in ``observed()`` auf, zugeordnet ueber den unveraenderten match-Pfad."""
    fake = _FakeChannel()
    sniffer = ScapySniSniffer(channel_factory=lambda: fake)
    fake.feed(hostname="example.com", remote_ip="93.184.216.34", remote_port=443, monotonic_ts=1.0)
    sniffer.start(None)
    try:
        # Auf den Hit-Poller (0.25 s-Intervall) warten, bis der Hit umgefuellt ist.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not sniffer.observed():
            time.sleep(0.02)
        observed = sniffer.observed()
        assert len(observed) == 1
        assert observed[0].hostname == "example.com"
        assert observed[0].remote_ip == "93.184.216.34"
    finally:
        sniffer.stop()
    assert fake.stop_calls == 1


def test_malformed_channel_hit_is_skipped() -> None:
    """Ein kaputtes Hit-dict (fehlendes Feld) wird still uebersprungen -- kein Crash,
    der Poller laeuft weiter (defensiv, S3-frei)."""
    sniffer = ScapySniSniffer(channel_factory=_FakeChannel)
    assert sniffer._raw_hit_from_dict({"hostname": "x", "remote_ip": "1.2.3.4"}) is None
    ok = sniffer._raw_hit_from_dict(
        {"hostname": "x.io", "remote_ip": "1.2.3.4", "remote_port": 443, "monotonic_ts": 1.0}
    )
    assert ok is not None
    assert ok.hostname == "x.io"


# ── Lifecycle-Naht ueber den Fake-Channel ─────────────────────────────────────


def test_start_ok_sets_running_and_forwards_interface() -> None:
    fake = _FakeChannel()
    sniffer = ScapySniSniffer(channel_factory=lambda: fake)
    sniffer.start("ens33")
    try:
        assert sniffer.is_running() is True
        assert fake.start_calls == ["ens33"]
    finally:
        sniffer.stop()
    assert sniffer.is_running() is False


def test_start_error_raises_sni_error() -> None:
    """ETAPPE-2-Naht: liefert der Helfer-Channel einen Fehlertext (z. B. fehlendes
    CAP_NET_RAW), wirft ``start()`` ``SniError`` -- KEINE stille Leer-Erfassung. Die
    ECHTE Rechtepruefung passiert so beim Start ueber die ERROR-Naht des Helfers (statt
    ueber eine Backend-Raw-Socket-Probe, die rechtelos faelschlich fehlschlagen wuerde)."""
    fake = _FakeChannel(start_error="Permission denied -- SNI capture requires CAP_NET_RAW.")
    sniffer = ScapySniSniffer(channel_factory=lambda: fake)
    with pytest.raises(SniError, match="CAP_NET_RAW"):
        sniffer.start(None)
    assert sniffer.is_running() is False


@pytest.mark.parametrize(
    "text",
    [
        "Permission denied -- SNI capture requires root or CAP_NET_RAW.",
        "raw socket not accessible -- requires CAP_NET_RAW",
    ],
)
def test_start_permission_error_raises_subclass(text: str) -> None:
    """Enthaelt der Helfer-Fehlertext den stabilen Substring ``CAP_NET_RAW``, ist es ein
    RECHTE-Fehler -> ``SniPermissionError`` (Subklasse von ``SniError``). Der Composition
    Root mappt die Subklasse auf 403 (nicht 503), damit der Frontend-Rechte-Hinweis
    greift. Beide Helfer-Varianten des Permission-Falls werden geprueft."""
    fake = _FakeChannel(start_error=text)
    sniffer = ScapySniSniffer(channel_factory=lambda: fake)
    with pytest.raises(SniPermissionError, match="CAP_NET_RAW"):
        sniffer.start(None)
    assert sniffer.is_running() is False


def test_start_non_permission_error_stays_base_class() -> None:
    """Ein Start-Fehler OHNE ``CAP_NET_RAW`` (z. B. kaputter Spawn/Geraet weg) ist KEIN
    Rechte-Fehler -> weiter ``SniError`` und gerade NICHT die ``SniPermissionError``-
    Subklasse (sonst wuerde der globale Handler ihn faelschlich auf 403 statt 503
    mappen)."""
    fake = _FakeChannel(start_error="helper spawn failed -- device gone")
    sniffer = ScapySniSniffer(channel_factory=lambda: fake)
    with pytest.raises(SniError) as excinfo:
        sniffer.start(None)
    assert not isinstance(excinfo.value, SniPermissionError)
    assert sniffer.is_running() is False


def test_resolve_app_name_none_pid_returns_none() -> None:
    assert _resolve_app_name(None) is None


def test_resolve_app_name_unknown_pid_returns_none() -> None:
    # Eine sehr hohe PID existiert (mit hoher Wahrscheinlichkeit) nicht -> None,
    # defensiv ueber psutil.Error (kein Crash).
    assert _resolve_app_name(2**31 - 1) is None


def test_is_running_false_without_sniff() -> None:
    assert ScapySniSniffer(channel_factory=_FakeChannel).is_running() is False


def test_stop_idempotent_without_sniff() -> None:
    # Kein laufender Sniff -> stop() ist ein No-op (kein Crash).
    ScapySniSniffer(channel_factory=_FakeChannel).stop()


# ── check_permission / is_available (neue (B)-Semantik) ───────────────────────


def test_check_permission_is_optimistic_none() -> None:
    """ETAPPE-2-(B)-Semantik: ``check_permission`` macht KEINE Backend-Raw-Socket-Probe
    mehr (das Backend hat kuenftig kein CAP_NET_RAW -- eine Probe wuerde faelschlich
    "keine Rechte" melden). Auf tragender Plattform ist sie optimistisch ``None``; der
    echte Rechte-Fehler kommt beim ``start()`` ueber die ERROR-Naht des Helfers.
    Ersetzt den alten Test der AF_PACKET-Probe-Semantik.

    Die Plattform-Weiche entscheidet, was "tragend" heisst: Linux/macOS immer, Windows
    genau dann, wenn Npcap erkannt wird (die IPC-Naht traegt dort seit W2 ueber eine
    benannte Pipe). Fehlt Npcap, hat der Marker ``NPCAP_MISSING`` Vorrang -> nicht
    ``None``, damit das Frontend die Funktion ehrlich ausgraut. Der Erwartungswert
    kommt darum aus ``sniffd_platform_supported()`` selbst und nicht aus einer
    Annahme ueber die Plattform."""
    plattform_traegt, _ = sniffd_platform_supported()
    result = ScapySniSniffer(channel_factory=_FakeChannel).check_permission()
    if plattform_traegt:
        assert result is None
    else:
        assert result == "NPCAP_MISSING"


def test_is_available_reflects_helper_entry_in_dev() -> None:
    """In der dev-Umgebung auf tragender Plattform existiert ``backend/sniffd.py``
    -> ``is_available()`` True. Reiner Pfad-Verfuegbarkeits-Check (scapy lebt jetzt im
    Helfer, ohne Spawn nicht pruefbar).

    Traegt die Plattform nicht (Windows ohne erkanntes Npcap), meldet die Pruefung
    ehrlich False, obwohl die Helfer-Binary existiert -- plattform-abhaengig. Der
    Erwartungswert kommt aus ``sniffd_platform_supported()`` selbst."""
    expected, _ = sniffd_platform_supported()
    assert ScapySniSniffer(channel_factory=_FakeChannel).is_available() is expected
