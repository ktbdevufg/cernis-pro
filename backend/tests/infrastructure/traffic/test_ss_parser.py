"""Tests der reinen ``parse_ss_output``-Funktion gegen ECHTES ``ss -tin``-Format.

Die Fixtures sind reale ``ss -tin``-Ausgaben (Zwei-Zeilen-Struktur: Socket-Zeile ohne
fuehrenden Whitespace + Detailzeile mit fuehrendem Whitespace und ``key:value``-Tokens).
Geprueft: normaler Socket, Socket ohne ``bytes_received``, Socket ganz ohne
Byte-Tokens (SYN-SENT), IPv6 in ``[...]``, mehrere Sockets, Muell/leer. ZEITFREI --
``parse_ss_output`` setzt keinen Zeitstempel (das macht der Adapter).
"""

from infrastructure.traffic_linux import parse_ss_output

# Header wie ``ss -tin`` ihn ausgibt (wird uebersprungen).
_HEADER = "State Recv-Q Send-Q         Local Address:Port           Peer Address:Port Process"


def test_parse_normal_socket() -> None:
    text = (
        _HEADER + "\n"
        "ESTAB 0      0               172.18.1.156:22             172.18.1.152:50018\n"
        "\t cubic wscale:6,10 rto:201 bytes_sent:11320827 bytes_retrans:100 "
        "bytes_acked:11320727 bytes_received:1437254 segs_out:89551\n"
    )
    result = parse_ss_output(text)
    assert result == [("tcp:172.18.1.156:22:172.18.1.152:50018", 11320827, 1437254)]


def test_parse_socket_without_bytes_received() -> None:
    # Realer Fall: frischer Socket mit bytes_sent aber OHNE bytes_received -> recv=0,
    # NICHT uebersprungen (damit er ueber beide Messpunkte in match_samples paart).
    text = (
        "ESTAB 0      517             172.18.1.156:38738          140.82.121.5:443\n"
        "\t cubic wscale:10,10 rto:214 bytes_sent:517 bytes_acked:1 segs_out:3\n"
    )
    result = parse_ss_output(text)
    assert result == [("tcp:172.18.1.156:38738:140.82.121.5:443", 517, 0)]


def test_parse_socket_without_any_bytes() -> None:
    # SYN-SENT: Socket-Zeile + Detailzeile ganz ohne Byte-Tokens -> (key, 0, 0).
    text = (
        "SYN-SENT 0  1               172.18.1.156:53648          140.82.121.5:443\n"
        "\t cubic rto:1000 mss:524 cwnd:10 segs_out:1 app_limited unacked:1\n"
    )
    result = parse_ss_output(text)
    assert result == [("tcp:172.18.1.156:53648:140.82.121.5:443", 0, 0)]


def test_parse_ipv6_address() -> None:
    # IPv6 in [...] -> key korrekt mit Klammern gebildet.
    text = (
        "ESTAB 0      0      [::ffff:172.18.1.156]:3389  [::ffff:172.18.1.152]:49946\n"
        "\t cubic bytes_sent:7891874 bytes_acked:7888016 bytes_received:8210318\n"
    )
    result = parse_ss_output(text)
    assert result == [
        ("tcp:[::ffff:172.18.1.156]:3389:[::ffff:172.18.1.152]:49946", 7891874, 8210318)
    ]


def test_parse_multiple_sockets_in_order() -> None:
    text = (
        _HEADER + "\n"
        "ESTAB 0      0               10.0.0.1:22             10.0.0.2:5001\n"
        "\t cubic bytes_sent:100 bytes_received:200\n"
        "ESTAB 0      0               10.0.0.1:443            10.0.0.3:5002\n"
        "\t cubic bytes_sent:300 bytes_received:400\n"
    )
    result = parse_ss_output(text)
    assert result == [
        ("tcp:10.0.0.1:22:10.0.0.2:5001", 100, 200),
        ("tcp:10.0.0.1:443:10.0.0.3:5002", 300, 400),
    ]


def test_parse_empty_input() -> None:
    assert parse_ss_output("") == []
    assert parse_ss_output("\n\n") == []


def test_parse_header_only() -> None:
    # Nur die Header-Zeile, keine Sockets -> [].
    assert parse_ss_output(_HEADER + "\n") == []


def test_parse_garbage_does_not_raise() -> None:
    # Muell-Input: keine Adressspalten / unparsebar -> [], nie werfen.
    assert parse_ss_output("voelliger muell ohne struktur\nnoch mehr muell\n") == []


def test_parse_detail_line_without_socket_line_ignored() -> None:
    # Detailzeile ohne vorangehende Socket-Zeile (defensiv) -> ignoriert.
    text = "\t cubic bytes_sent:999 bytes_received:888\n"
    assert parse_ss_output(text) == []


def test_parse_key_form_is_tcp_local_remote() -> None:
    text = (
        "ESTAB 0      0               1.2.3.4:80              5.6.7.8:12345\n"
        "\t cubic bytes_sent:1 bytes_received:2\n"
    )
    key, _, _ = parse_ss_output(text)[0]
    assert key == "tcp:1.2.3.4:80:5.6.7.8:12345"
