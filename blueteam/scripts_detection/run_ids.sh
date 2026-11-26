#!/bin/bash
stdbuf -oL -eL tcpdump -l -n -Z root -i any udp port 53 2>/dev/null | python3 -u /root/detection/detect_engine.py
