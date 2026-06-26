"""Privilege-Separation-Sniff-Helfer -- traegt als EINZIGE Komponente CAP_NET_RAW.

Wird vom Backend on-demand gestartet. Schlanker Standalone-Prozess: KEIN uvicorn,
kein FastAPI -- nur der AF_UNIX-Helfer-Server (``infrastructure.sniffd.server``).
Der Socket-Pfad kommt aus ``sys.argv[1]`` (Default ``/tmp/cernis-sniffd.sock``).
"""

import sys

from infrastructure.sniffd.server import serve

_DEFAULT_SOCKET_PATH = "/tmp/cernis-sniffd.sock"


def main() -> None:
    socket_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_SOCKET_PATH
    serve(socket_path)


if __name__ == "__main__":
    main()
