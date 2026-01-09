#!/bin/sh
set -eu

# Ensure mounted volumes are writable before dropping privileges.
chown -R dawnuser:dawnuser /app/data /app/logs

exec su-exec dawnuser "$@"
