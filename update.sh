#!/usr/bin/env bash
# Авто-обновление: тянет последнюю версию с GitHub и пересобирает контейнеры,
# только если в репозитории появились изменения. Безопасно запускать по cron.
# .env и папка profiles/ (аккаунты, пользователи) не трогаются.
set -e
cd "$(dirname "$(readlink -f "$0")")"

git fetch --quiet origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
  exit 0   # уже актуально — ничего не делаем
fi

echo "$(date '+%Y-%m-%d %H:%M') обновление ${LOCAL:0:7} -> ${REMOTE:0:7}"
git reset --hard origin/main
docker compose up -d --build
echo "$(date '+%Y-%m-%d %H:%M') готово"
