#!/bin/bash
# Kill any running cernis-backend processes before installing new version
killall -9 cernis-backend 2>/dev/null || true
sleep 1
