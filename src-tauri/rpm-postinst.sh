#!/bin/bash
# Set CAP_NET_RAW on backend binary for packet capture (scapy)
setcap cap_net_raw+eip /usr/bin/cernis-backend 2>/dev/null || true
