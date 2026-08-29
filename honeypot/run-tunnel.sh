#!/bin/bash
# Keeps a Pinggy TCP tunnel alive pointing at the honeypot on
# localhost:2222. Free-tier Pinggy sessions cap out at ~60 minutes,
# so this loops and reconnects automatically when a session ends.
# Note: the public address (host:port Pinggy assigns) changes on
# every reconnect on the free tier -- watch the output each time.

LOCAL_PORT=2222

while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') Starting Pinggy tunnel..."
    ssh -p 443 \
        -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -R0:localhost:${LOCAL_PORT} tcp@free.pinggy.io
    echo "$(date '+%Y-%m-%d %H:%M:%S') Tunnel dropped, reconnecting in 5s..."
    sleep 5
done
