"""Infrastructure-Adapter der scanning-Domaene.

Das EINZIGE Paket der neuen Ringe, das ``modules/`` importieren darf (ADR 0007,
eng eingezaeunt via ``import-linter``-``ignore_imports``): Die systemnahe
Scan-Schicht (Ping/Portscan/mDNS/SSDP/IPv6/Fritz, Vendor/Resolver) wird hier
hinter den ``ports/scanning``-Vertraegen gekapselt, statt sie zu reimplementieren
-- Wegwerf-Arbeit vor dem in Vision 5.2 vorgesehenen moeglichen Sprachwechsel
waere zu vermeiden.
"""
