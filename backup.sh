#!/usr/bin/env bash
# Бэкап данных. Маленькие критичные данные (аккаунты, расписания, сессии,
# факты оплат) храним в 14 копиях. Уже зашифрованные полные чаты складываем
# отдельно в один latest-снимок: повторять до 2 ГБ четырнадцать раз нельзя.
# Если PAYMENT_ARCHIVE_KEY задан в .env, сам .env сюда намеренно не входит:
# его резервную копию нужно хранить отдельно.
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

# Сначала снимаем тяжёлый архив, а уже потом SQLite. Тогда при событии прямо
# во время бэкапа компактный факт попадёт в более новый SQLite-снимок, даже
# если соответствующий полный чат не успел попасть в tar.
CHAT_ARCHIVES="$REPO/profiles/payment_chat_archives"
CHAT_LATEST="$DEST/payment-chat-archives-latest.tar"
CHAT_TMP="$DEST/.payment-chat-archives-$STAMP.tar.tmp"
STAGE=""
cleanup() {
  rm -f -- "$CHAT_TMP"
  if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
    rm -rf -- "$STAGE"
  fi
}
trap cleanup EXIT
if [ -d "$CHAT_ARCHIVES" ]; then
  NEED_KB=$(du -sk "$CHAT_ARCHIVES" | awk '{print $1}')
  FREE_KB=$(df -Pk "$DEST" | awk 'NR==2 {print $4}')
  RESERVE_KB=262144
  if [ "$FREE_KB" -ge $((NEED_KB + RESERVE_KB)) ]; then
    if tar -cf "$CHAT_TMP" -C "$REPO/profiles" payment_chat_archives; then
      chmod 600 "$CHAT_TMP"
      mv -f "$CHAT_TMP" "$CHAT_LATEST"
    else
      rm -f "$CHAT_TMP"
      echo "$(date '+%F %T') полный архив чатов изменился во время копирования — сохранена предыдущая latest-копия"
    fi
  else
    echo "$(date '+%F %T') мало места для latest-копии полных чатов — критичный бэкап фактов всё равно будет сделан"
  fi
fi

STAGE=$(mktemp -d)
mkdir -p "$STAGE/profiles"
# Не затаскиваем тяжёлый архив в staging и в каждую из 14 ежедневных копий.
tar -cf - --exclude='profiles/payment_chat_archives' -C "$REPO" profiles \
  | tar -xf - -C "$STAGE"

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
