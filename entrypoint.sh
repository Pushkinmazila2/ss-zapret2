#!/usr/bin/env sh
set -e

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

/opt/zapret2/init.d/sysv/zapret2 start

cleanup() {
  /opt/zapret2/init.d/sysv/zapret2 stop || true
  pkill -P $$ ss-server 2>/dev/null || true
  pkill -P $$ ss-local 2>/dev/null || true
  pkill -P $$ sed 2>/dev/null || true
}

trap cleanup TERM INT

if [ "${SS_VERBOSE:-1}" = "0" ]; then
  exec >/dev/null 2>&1
fi

# Создаем named pipes
mkfifo /tmp/ss-server.pipe /tmp/ss-local.pipe

# Запускаем ss-server с перенаправлением в pipe
ss-server -v -s 0.0.0.0 -p "${SS_PORT}" -k "${SS_PASSWORD}" -m "${SS_ENCRYPT_METHOD}" -t "${SS_TIMEOUT}" -u 2>&1 >/tmp/ss-server.pipe &

# Запускаем ss-local с перенаправлением в pipe
ss-local -b 0.0.0.0 -s 127.0.0.1 -p "${SS_PORT}" -l "${SOCKS_PORT}" -k "${SS_PASSWORD}" -m "${SS_ENCRYPT_METHOD}" -t "${SS_TIMEOUT}" -v -u 2>&1 >/tmp/ss-local.pipe &

# Читаем из pipes и добавляем префиксы
sed 's/^/[SS-SERVER] /' </tmp/ss-server.pipe &
sed 's/^/[SS-LOCAL] /' </tmp/ss-local.pipe &

# Ждем завершения любого процесса
wait -n

# Если один процесс упал, убиваем остальные
cleanup
