#!/bin/bash
# Set CAP_NET_RAW on sniff helper for packet capture (scapy)
# S5-Lehre: Cap sitzt auf dem Sniff-Helfer cernis-sniffd, NICHT auf dem Backend.
setcap cap_net_raw+eip /usr/bin/cernis-sniffd 2>/dev/null || true
