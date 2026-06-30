#!/usr/bin/env bash
# Бэкап данных (profiles/: аккаунты, пользователи, подписки, расписания, сессии).
# Кладёт архив в ~/yoy-backups (вне репозитория, чтобы git его не трогал),
# хранит последние 14 копий. Безопасно запускать по cron.
set -e
REPO="$(dirname "$(readlink -f "$0")")"
DEST="$HOME/yoy-backups"
mkdir -p "$DEST"

if [ ! -d "$REPO/profiles" ]; then
  echo "$(date '+%F %T') нет папки profiles — пропуск"
  exit 0
fi

STAMP=$(date '+%Y%m%d-%H%M')
tar -czf "$DEST/yoy-$STAMP.tar.gz" -C "$REPO" profiles

# оставить последние 14 архивов
ls -1t "$DEST"/yoy-*.tar.gz 2>/dev/null | tail -n +15 | xargs -r rm -f

echo "$(date '+%F %T') бэкап готов: $DEST/yoy-$STAMP.tar.gz"
