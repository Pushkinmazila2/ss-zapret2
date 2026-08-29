#!/usr/bin/env sh

set -euo pipefail

missing=""
for var in SS_PORT SS_PASSWORD SS_ENCRYPT_METHOD SS_TIMEOUT SOCKS_PORT; do
  eval "value=\${$var:-}"
  [ -n "$value" ] || missing="$missing $var"
done

if [ -n "$missing" ]; then
  echo "[entrypoint] ERROR: required environment variables are not set:$missing" >&2
  exit 1
fi

sync_defaults() {
  src_dir=$1
  dst_dir=$2
  label=$3

  [ -d "$src_dir" ] && [ -d "$dst_dir" ] || return 0

  for src in "$src_dir"/*; do
    [ -e "$src" ] || continue
    name="$(basename "$src")"
    dst="$dst_dir/$name"
    [ -e "$dst" ] && continue
    echo "[entrypoint] Copying $label: $name"
    cp -a "$src" "$dst"
  done
}

sync_defaults "/opt/zapret2/lua.dist" "/opt/zapret2/lua" "lua script"
sync_defaults "/opt/zapret2/init.d/custom.d.examples.linux.dist" "/opt/zapret2/init.d/custom.d.examples.linux" "custom.d script"
sync_defaults "/opt/zapret2/files/fake.dist" "/opt/zapret2/files/fake" "fake file"

/opt/zapret2/init.d/sysv/zapret2 start

# ── веб-панель управления стратегиями ──────────────────────────────────────
PANEL_PORT="${PANEL_PORT:-1888}"
echo "[entrypoint] Starting web panel on :${PANEL_PORT}, socks_port=${SOCKS_PORT}"
python3 /opt/zapret2/panel/server.py \
  --config      /opt/zapret2/config \
  --strategies  /opt/zapret2/strategies \
  --port        "${PANEL_PORT}" \
  --ss-port     "${SS_PORT}" \
  --socks-port  "${SOCKS_PORT}" \
  --restart-cmd "/opt/zapret2/init.d/sysv/zapret2 restart-daemons" \
  2>&1 | awk '{print "[PANEL] " $0; fflush()}' &
PANEL_PID=$!
echo "[entrypoint] Panel PID=${PANEL_PID}"

cleanup() {
  /opt/zapret2/init.d/sysv/zapret2 stop || true
  [ -n "${SS_SERVER_PID:-}" ] && kill "${SS_SERVER_PID}" 2>/dev/null || true
  [ -n "${SS_LOCAL_PID:-}" ] && kill "${SS_LOCAL_PID}" 2>/dev/null || true
  [ -n "${PANEL_PID:-}" ]    && kill "${PANEL_PID}"    2>/dev/null || true
}

trap cleanup EXIT TERM INT

SS_VERBOSE_FLAG=""
if [ "${SS_VERBOSE:-0}" = "1" ]; then
  SS_VERBOSE_FLAG="-v"
fi

SS_LOG=/run/zapret-pool/ss-server.log
mkdir -p /run/zapret-pool
: > "$SS_LOG"   # очищаем при старте

ss-server ${SS_VERBOSE_FLAG} -s 0.0.0.0 -p "${SS_PORT}" -k "${SS_PASSWORD}" -m "${SS_ENCRYPT_METHOD}" -t "${SS_TIMEOUT}" -u \
  2>&1 | tee -a "$SS_LOG" | awk '{print "[SS-SERVER] " $0; fflush()}' &
SS_SERVER_PID=$!

ss-local ${SS_VERBOSE_FLAG} -b 0.0.0.0 -s 127.0.0.1 -p "${SS_PORT}" -l "${SOCKS_PORT}" -k "${SS_PASSWORD}" -m "${SS_ENCRYPT_METHOD}" -t "${SS_TIMEOUT}" -u &
SS_LOCAL_PID=$!

wait