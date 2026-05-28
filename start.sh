#!/bin/sh
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:?Must set ADMIN_PASSWORD}"
export SESSION_SECRET="${SESSION_SECRET:?Must set SESSION_SECRET}"
export PORT="${PORT:-3000}"
exec node server.js
