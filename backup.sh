#!/usr/bin/env bash
# Бэкап данных (profiles/: аккаунты, пользователи, подписки, расписания, сессии).
# Кладёт архив в ~/yoy-backups (вне репозитория, чтобы git его не трогал),
# хранит последние 14 копий. Безопасно запускать по cron.
set -e
umask 077
REPO="$(dirname "$(readlink -f "$0")")"
DEST="$HOME/yoy-backups"
mkdir -p "$DEST"
chmod 700 "$DEST"

if [ ! -d "$REPO/profiles" ]; then
  echo "$(date '+%F %T') нет папки profiles — пропуск"
  exit 0
fi

STAMP=$(date '+%Y%m%d-%H%M')
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/profiles"
cp -a "$REPO/profiles/." "$STAGE/profiles/"

# Копирование SQLite-файла вместе с живым WAL может дать повреждённый архив.
# sqlite3.backup делает согласованный снимок, пока приложение продолжает работу.
AUDIT_DB="$REPO/profiles/payment_audit.sqlite3"
STAGED_AUDIT_DB="$STAGE/profiles/payment_audit.sqlite3"
if [ -f "$AUDIT_DB" ]; then
  rm -f "$STAGED_AUDIT_DB" "$STAGED_AUDIT_DB-wal" "$STAGED_AUDIT_DB-shm"
  python3 - "$AUDIT_DB" "$STAGED_AUDIT_DB" <<'PY'
import sqlite3
import sys

source_path, target_path = sys.argv[1:]
source = sqlite3.connect(source_path)
target = sqlite3.connect(target_path)
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
  chmod 600 "$STAGED_AUDIT_DB"
fi

tar -czf "$DEST/yoy-$STAMP.tar.gz" -C "$STAGE" profiles
chmod 600 "$DEST/yoy-$STAMP.tar.gz"

# оставить последние 14 архивов
ls -1t "$DEST"/yoy-*.tar.gz 2>/dev/null | tail -n +15 | xargs -r rm -f

echo "$(date '+%F %T') бэкап готов: $DEST/yoy-$STAMP.tar.gz"
