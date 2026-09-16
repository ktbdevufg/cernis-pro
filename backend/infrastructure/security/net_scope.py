"""Reine Ziel-Bereichs-Pruefung fuer die default-creds-Sonderfunktion (stdlib-only).

Liegt im infrastructure-Ring, importiert AUSSCHLIESSLICH stdlib (``ipaddress``) -- kein
domain-/ports-Bezug. Der api-Ring importiert diese Funktion NICHT direkt (import-linter:
api -> nur application); die Verdrahtung laeuft ueber den dependency-Marker
``provide_target_scope_guard`` (api/security.py), den der Composition Root ``app.py`` auf
``is_private_target`` legt (Regel 5: ports<->infra nur dort).
"""

import ipaddress


def is_private_target(host: str) -> bool:
    """``True`` nur fuer eine IP-Literal im eigenen, privaten Netz (v4 und v6).

    Konservativ: nur ein echtes IP-Literal, das ``is_private`` ODER ``is_loopback`` ODER
    ``is_link_local`` ist, gilt als zulaessig. Ein Hostname (nicht parsebar als IP) ->
    ``False`` -- KEINE DNS-Aufloesung, damit kein Ziel ausserhalb des eigenen Netzes
    durchrutscht.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local
