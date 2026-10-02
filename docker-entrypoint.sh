#!/bin/sh
set -e
mkdir -p "$DATA_DIR"
chown -R chat:chat "$DATA_DIR"
chmod 700 "$DATA_DIR"
exec setpriv --reuid=chat --regid=chat --clear-groups \
  ./chat_server -p "${PORT:-10000}" -b 0.0.0.0 -d "$DATA_DIR" -w ./public --secure --trust-proxy
