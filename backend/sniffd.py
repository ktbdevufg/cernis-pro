"""Privilege-Separation-Sniff-Helfer -- traegt als EINZIGE Komponente CAP_NET_RAW.

Wird vom Backend on-demand gestartet. Schlanker Standalone-Prozess: KEIN uvicorn,
kein FastAPI -- nur der Helfer-Server (``infrastructure.sniffd.server``). Die
Adresse der lauschenden Stelle kommt aus ``sys.argv[1]``: auf Linux/macOS ein
AF_UNIX-Socket-Pfad, auf Windows der Name einer benannten Pipe.
"""

import sys

from infrastructure.sniffd.server import serve

# Kein plattformfremder Vorgabewert mehr: der fruehere Default
# ``/tmp/cernis-sniffd.sock`` ist auf Windows kein gueltiger Pipe-Name -- ein
# Start ohne Argument waere dort in einen unverstaendlichen Fehler tief in der
# Transportnaht gelaufen. Die Backendseite uebergibt die Adresse IMMER
# (``sniffd_client/base.py._spawn_command``); ein fehlendes Argument ist damit
# ein Aufrufsfehler und wird als solcher benannt statt still geraten
# (S3: keine stillen Fallbacks).
_USAGE = "Aufruf: sniffd <adresse>  (Socket-Pfad bzw. Pipe-Name der lauschenden Stelle)"


def main() -> None:
    if len(sys.argv) < 2 or not sys.argv[1]:
        print(_USAGE, file=sys.stderr)
        raise SystemExit(2)
    serve(sys.argv[1])


if __name__ == "__main__":
    main()
