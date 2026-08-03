#!/usr/bin/env python3
"""
Telegram планировщик постов — веб-панель.

Идея:
  • несколько профилей (Telegram-аккаунтов), каждый со своей сессией;
  • первый экран — выбор профиля; если профилей нет, добавляем через GUI-вход
    (api_id/api_hash → телефон → код → 2FA);
  • внутри профиля нет списка чатов — есть поиск чатов (как в Telegram),
    можно выбрать сразу несколько (лс / группы / каналы);
  • пишем сообщение и задаём расписание отправки по всем выбранным чатам.

Логика таймера:
  • заданы конкретные даты      → отправка один раз в каждую из этих дат;
  • заданы только дни недели    → повтор каждую неделю в эти дни;
  • ничего не задано            → повтор каждый день.

Запуск:
    python web.py
    # затем открой http://127.0.0.1:8000
"""

import asyncio
import base64
import hashlib
import hmac
import io
import json
import math
import os
import random
import re
import secrets
import tempfile
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, urlencode

from payment_audit import analyze_payment_signal
from payment_chat_archive import PaymentChatArchive, PaymentChatArchiveError
from payment_audit_store import PaymentAuditStore, mask_sensitive_text, normalize_chat_context
from receipt_ocr import (
    OcrLimits,
    RemoteReceiptOcr,
    ReceiptOcrError,
)

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from telethon import TelegramClient, utils, events
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.functions.messages import (
    ImportChatInviteRequest,
    GetDialogFiltersRequest,
    UpdateDialogFilterRequest,
    ExportChatInviteRequest,
)
from telethon.tl.types import User, Chat, Channel
from telethon.errors import (
    ApiIdInvalidError,
    FloodWaitError,
    PeerFloodError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    SessionPasswordNeededError,
)

# --- Пути ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")
PROFILES_JSON = os.path.join(PROFILES_DIR, "profiles.json")
SCHEDULES_JSON = os.path.join(PROFILES_DIR, "schedules.json")
PACKS_JSON = os.path.join(PROFILES_DIR, "packs.json")
USERS_JSON = os.path.join(PROFILES_DIR, "users.json")
SENDS_JSON = os.path.join(PROFILES_DIR, "sends.json")
SENDS_KEEP = int(os.environ.get("SENDS_KEEP", "1000"))  # сколько последних запусков хранить (окно для админ-статистики)
QUEUE_JSON = os.path.join(PROFILES_DIR, "queue.json")  # активные рассылки (докатка при рестарте)
NOTIFS_JSON = os.path.join(PROFILES_DIR, "notifications.json")  # уведомления владельцу о ЧП
CLONES_DIR = os.path.join(PROFILES_DIR, "clones")  # снимки настроек аккаунта для клонирования
NOTIFS_KEEP = int(os.environ.get("NOTIFS_KEEP", "100"))
RESPONSES_JSON = os.path.join(PROFILES_DIR, "responses.json")  # счётчик входящих в личку (отклик на рассылки)
RESP_KEEP_DAYS = int(os.environ.get("RESP_KEEP_DAYS", "30"))
PAYMENT_AUDIT_DB = os.path.join(PROFILES_DIR, "payment_audit.sqlite3")
PAYMENT_CHAT_ARCHIVE_DIR = os.path.join(PROFILES_DIR, "payment_chat_archives")
PAYMENT_CHAT_ARCHIVE_KEY_FILE = os.path.join(PROFILES_DIR, "payment_archive.key")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(PROFILES_DIR, exist_ok=True)

# Ключ для подписи cookie-сессий. Берём из env SECRET_KEY либо генерируем и
# сохраняем в profiles/secret.key (тогда сессии переживают перезапуск сервера).
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    _key_path = os.path.join(PROFILES_DIR, "secret.key")
    if os.path.exists(_key_path):
        with open(_key_path, "r", encoding="utf-8") as f:
            SECRET_KEY = f.read().strip()
    else:
        SECRET_KEY = secrets.token_hex(32)
        with open(_key_path, "w", encoding="utf-8") as f:
            f.write(SECRET_KEY)
        try:
            os.chmod(_key_path, 0o600)
        except OSError:
            pass

# secure-флаг для cookie. По умолчанию включён (мы за HTTPS через Caddy).
# Для локального запуска по http можно выставить COOKIE_SECURE=0.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") != "0"

# --- Прозрачная проверка оплат в рабочих Telegram-аккаунтах ---
PAYMENT_AUDIT_VERSION = "2026-08-01-v2"
# Минимальные факты и решения нужны для недельной/годовой сверки дольше, чем
# тяжёлый архив полной переписки. Старое имя env оставлено как fallback.
PAYMENT_AUDIT_RETENTION_DAYS = int(os.environ.get(
    "PAYMENT_FACT_RETENTION_DAYS",
    os.environ.get("PAYMENT_AUDIT_RETENTION_DAYS", "0"),
))
PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS = int(os.environ.get(
    # 0 = хранить до ручной кнопки «Оставить только оплаты».
    "PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS", "0"
))
PAYMENT_CHAT_ARCHIVE_MAX_MESSAGES = int(os.environ.get(
    # Хватает, чтобы поднять переписку вокруг оплаты, и это ~4 запроса к Telegram
    # на чат вместо полусотни: рабочие аккаунты не любят всплесков запросов.
    "PAYMENT_CHAT_ARCHIVE_MAX_MESSAGES", "400"
))
# Разнос выкачки историй во времени (сек). Первый чат сохраняется сразу, очередь
# следующих растягивается — так с аккаунта не уходит залп запросов подряд.
PAYMENT_CHAT_ARCHIVE_GAP_MIN = float(os.environ.get("PAYMENT_CHAT_ARCHIVE_GAP_MIN", "1.5"))
PAYMENT_CHAT_ARCHIVE_GAP_MAX = float(os.environ.get("PAYMENT_CHAT_ARCHIVE_GAP_MAX", "4"))
PAYMENT_CHAT_ARCHIVE_MAX_TEXT_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_MAX_TEXT_BYTES", str(10 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_ITEMS = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_ITEMS", "50"
))
PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES", str(10 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_MAX_TOTAL_MEDIA_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_MAX_TOTAL_MEDIA_BYTES", str(50 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_OWNER_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_OWNER_BYTES", str(512 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_GLOBAL_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_GLOBAL_BYTES", str(2 * 1024 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_MIN_FREE_BYTES = int(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_MIN_FREE_BYTES", str(512 * 1024 * 1024)
))
PAYMENT_CHAT_ARCHIVE_TIMEOUT = float(os.environ.get(
    "PAYMENT_CHAT_ARCHIVE_TIMEOUT", "120"
))
PAYMENT_AUDIT_OCR_MAX_BYTES = int(os.environ.get("PAYMENT_AUDIT_OCR_MAX_BYTES", str(10 * 1024 * 1024)))
PAYMENT_AUDIT_OCR_PER_HOUR = int(os.environ.get("PAYMENT_AUDIT_OCR_PER_HOUR", "30"))
PAYMENT_AUDIT_OCR_QUEUE_MAX = int(os.environ.get("PAYMENT_AUDIT_OCR_QUEUE_MAX", "20"))
PAYMENT_AUDIT_DOWNLOAD_TIMEOUT = float(os.environ.get("PAYMENT_AUDIT_DOWNLOAD_TIMEOUT", "20"))
PAYMENT_AUDIT_OCR_HEALTH_TIMEOUT = float(os.environ.get("PAYMENT_AUDIT_OCR_HEALTH_TIMEOUT", "2"))
PAYMENT_COMMISSION_RATE = 0.15
# Сколько дней «не доход» лежит в корзине, прежде чем удалиться сам.
PAYMENT_TRASH_DAYS = int(os.environ.get("PAYMENT_TRASH_DAYS", "7"))
payment_audit_store = None
_payment_audit_store_retry_at = 0.0
_payment_audit_store_lock = threading.Lock()
payment_chat_archive = None
_payment_chat_archive_lock = threading.Lock()
_payment_ocr_health_cache = (0.0, False)
receipt_ocr = RemoteReceiptOcr(
    base_url=os.environ.get("PAYMENT_AUDIT_OCR_URL", "http://ocr:8080"),
    limits=OcrLimits(
        max_media_bytes=PAYMENT_AUDIT_OCR_MAX_BYTES,
        # PDF parsing is intentionally disabled at the Telegram boundary.  A
        # single raster receipt is enough for the first safe production mode.
        max_pdf_pages=1,
    )
)


def _get_payment_audit_store():
    """Initialize the optional audit store without risking the scheduler."""
    global payment_audit_store, _payment_audit_store_retry_at
    with _payment_audit_store_lock:
        if payment_audit_store is not None:
            return payment_audit_store
        if time.monotonic() < _payment_audit_store_retry_at:
            return None
        try:
            payment_audit_store = PaymentAuditStore(
                PAYMENT_AUDIT_DB,
                SECRET_KEY,
                retention_days=PAYMENT_AUDIT_RETENTION_DAYS,
                trash_days=PAYMENT_TRASH_DAYS,
                correlation_minutes=60,
            )
        except Exception as exc:
            # Payment audit is auxiliary. A damaged/full audit DB must not stop
            # scheduled Telegram sends or the main web panel.
            print(f"[payment-audit] store unavailable {type(exc).__name__}")
            _payment_audit_store_retry_at = time.monotonic() + 300
            return None
        _payment_audit_store_retry_at = 0.0
        return payment_audit_store


async def _get_payment_audit_store_async():
    return await asyncio.to_thread(_get_payment_audit_store)


def _payment_archive_key():
    """Load a dedicated archive key; production should provide it via .env."""
    def validate(value):
        text = str(value or "").strip()
        valid = bool(re.fullmatch(r"[0-9a-fA-F]{64}", text))
        if not valid:
            try:
                valid = len(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))) == 32
            except Exception:
                valid = False
        if not valid:
            raise PaymentChatArchiveError(
                "PAYMENT_ARCHIVE_KEY must be 32 bytes (64 hex characters)"
            )
        return text

    def read_file():
        with open(PAYMENT_CHAT_ARCHIVE_KEY_FILE, "r", encoding="utf-8") as handle:
            return validate(handle.read())

    configured = (os.environ.get("PAYMENT_ARCHIVE_KEY") or "").strip()
    if configured:
        return validate(configured)
    if os.path.exists(PAYMENT_CHAT_ARCHIVE_KEY_FILE):
        return read_file()
    value = secrets.token_hex(32)
    fd, tmp_name = tempfile.mkstemp(prefix=".payment-archive-key-", dir=PROFILES_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        fd = -1
        try:
            # link() publishes without overwriting a key another process created.
            os.link(tmp_name, PAYMENT_CHAT_ARCHIVE_KEY_FILE)
        except FileExistsError:
            return read_file()
        try:
            dir_fd = os.open(PROFILES_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        return value
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _get_payment_chat_archive():
    global payment_chat_archive
    with _payment_chat_archive_lock:
        if payment_chat_archive is None:
            payment_chat_archive = PaymentChatArchive(
                PAYMENT_CHAT_ARCHIVE_DIR,
                _payment_archive_key(),
                max_messages=max(1, PAYMENT_CHAT_ARCHIVE_MAX_MESSAGES),
                max_text_bytes=max(1024, PAYMENT_CHAT_ARCHIVE_MAX_TEXT_BYTES),
                max_media_items=max(0, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_ITEMS),
                max_media_bytes=max(1024, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES),
                max_total_media_bytes=max(1024, PAYMENT_CHAT_ARCHIVE_MAX_TOTAL_MEDIA_BYTES),
                max_owner_bytes=max(0, PAYMENT_CHAT_ARCHIVE_OWNER_BYTES),
                max_global_bytes=max(0, PAYMENT_CHAT_ARCHIVE_GLOBAL_BYTES),
                min_free_bytes=max(0, PAYMENT_CHAT_ARCHIVE_MIN_FREE_BYTES),
            )
        return payment_chat_archive


async def _get_payment_chat_archive_async():
    return await asyncio.to_thread(_get_payment_chat_archive)


async def _payment_ocr_available():
    """Return sidecar readiness without delaying the panel when OCR is down."""
    global _payment_ocr_health_cache
    now = time.monotonic()
    refresh_at, available = _payment_ocr_health_cache
    if now < refresh_at:
        return available
    try:
        async with asyncio.timeout(max(0.25, PAYMENT_AUDIT_OCR_HEALTH_TIMEOUT)):
            health = await receipt_ocr.health()
        available = bool(health.ready and health.languages_available)
    except (TimeoutError, ReceiptOcrError):
        available = False
    _payment_ocr_health_cache = (now + (30 if available else 10), available)
    return available

# --- Тарифы и оплата ---
# Токен CryptoBot (Crypto Pay API). Получить: @CryptoBot → Crypto Pay → Create App.
CRYPTOBOT_TOKEN = os.environ.get("CRYPTOBOT_TOKEN", "")
CRYPTOBOT_API = os.environ.get("CRYPTOBOT_API", "https://pay.crypt.bot/api")
PANEL_DOMAIN = os.environ.get("PANEL_DOMAIN", "")

# Тарифов и лимитов НЕТ: у каждого одобренного пользователя — полный доступ ко
# всем возможностям без ограничений по числу аккаунтов. Доступ регулируется только
# сроком подписки (paid_until), который админ продлевает вручную (+7 / +30 дней).
# Оплата идёт вне сайта (перевод / наличка) и на сайте не афишируется.


def _valid_hash(value):
    """api_hash должен быть ровно 32 hex-символа."""
    hex_chars = set("0123456789abcdefABCDEF")
    return bool(value) and len(value) == 32 and all(c in hex_chars for c in value)


# ---------------------------------------------------------------------------
# Хранилище профилей и расписаний (простые JSON-файлы)
# ---------------------------------------------------------------------------
def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_profiles():
    return _read_json(PROFILES_JSON, {"profiles": []})["profiles"]


def save_profiles(profiles):
    _write_json(PROFILES_JSON, {"profiles": profiles})


def get_profile(pid):
    for p in load_profiles():
        if p["id"] == pid:
            return p
    return None


def load_schedules():
    return _read_json(SCHEDULES_JSON, {"schedules": []})["schedules"]


def save_schedules(schedules):
    _write_json(SCHEDULES_JSON, {"schedules": schedules})


def load_packs():
    return _read_json(PACKS_JSON, {"packs": []})["packs"]


def save_packs(packs):
    _write_json(PACKS_JSON, {"packs": packs})


def load_sends():
    return _read_json(SENDS_JSON, {"sends": []})["sends"]


# --- очередь активных рассылок: чтобы недоотправленное докатилось после рестарта ---
def _queue_load():
    return _read_json(QUEUE_JSON, {"jobs": []})["jobs"]


def _queue_put(entry):
    jobs = [j for j in _queue_load() if j.get("pid") != entry.get("pid")]
    jobs.append(entry)
    _write_json(QUEUE_JSON, {"jobs": jobs})


def _queue_clear(pid):
    jobs = [j for j in _queue_load() if j.get("pid") != pid]
    _write_json(QUEUE_JSON, {"jobs": jobs})


# --- уведомления владельцу о ЧП (спам-флаг, флуд, бан аккаунта) ---
def _add_notification(owner, pid, level, text):
    """Кладёт уведомление в ленту (для баннера в панели). level: 'warn'|'error'|'info'."""
    if not owner:
        return
    items = _read_json(NOTIFS_JSON, {"items": []})["items"]
    items.insert(0, {
        "id": secrets.token_hex(5), "owner": owner, "pid": pid,
        "level": level, "text": text,
        "ts": datetime.now().isoformat(timespec="seconds"), "read": False,
    })
    if len(items) > NOTIFS_KEEP:
        items = items[:NOTIFS_KEEP]
    _write_json(NOTIFS_JSON, {"items": items})


async def _notify_saved(pid, text):
    """Best-effort: шлёт уведомление в «Избранное» самого аккаунта (доходит всегда)."""
    try:
        client = await get_client(pid)
        if client and await client.is_user_authorized():
            await client.send_message("me", text)
    except Exception:
        pass  # уведомление не критично — молча пропускаем


# --- отклик на рассылки: сколько людей написали аккаунту в личку ---
# Считаем ТОЛЬКО количество входящих личных сообщений (без содержимого и без
# личности отправителя) — это простой сигнал «рассылки сработали, людям
# интересно и они пишут». Владелец панели видит цифру, не переписку.
def _load_responses():
    return _read_json(RESPONSES_JSON, {"counts": {}})


def _bump_response(pid):
    data = _load_responses()
    counts = data.setdefault("counts", {})
    per = counts.setdefault(pid, {})
    day = datetime.now().strftime("%Y-%m-%d")
    per[day] = int(per.get(day, 0)) + 1
    cutoff = (datetime.now() - timedelta(days=RESP_KEEP_DAYS)).strftime("%Y-%m-%d")
    for old in [d for d in per if d < cutoff]:
        per.pop(old, None)
    _write_json(RESPONSES_JSON, data)


def _responses_window(pid, days):
    """Сумма входящих в личку за последние `days` дней (включая сегодня)."""
    per = _load_responses().get("counts", {}).get(pid, {})
    cutoff = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    return sum(n for d, n in per.items() if d >= cutoff)


# после скольких подряд ошибок чат считается мёртвым и убирается из получателей
CHAT_FAIL_LIMIT = int(os.environ.get("CHAT_FAIL_LIMIT", "3"))


def _record_chat_result(pid, chat_id, ok):
    """Ведёт счётчик подряд-ошибок по чату. Возвращает True, если чат пора удалить (мёртвый)."""
    profiles = load_profiles()
    dead = False
    for p in profiles:
        if p["id"] != pid:
            continue
        fails = p.setdefault("chat_fails", {})
        key = str(chat_id)
        if ok:
            if key in fails:
                fails.pop(key, None)
                save_profiles(profiles)
            return False
        fails[key] = int(fails.get(key, 0)) + 1
        dead = fails[key] >= CHAT_FAIL_LIMIT
        if dead:
            fails.pop(key, None)   # сбрасываем — чат уйдёт из получателей
        save_profiles(profiles)
        return dead
    return False


def _remove_chat_from_schedules(pid, chat_id):
    """Убирает мёртвый чат из всех расписаний профиля. Возвращает True, если что-то удалили."""
    schedules = load_schedules()
    changed = False
    for rule in schedules:
        if rule.get("profile_id") != pid:
            continue
        tg = rule.get("targets") or []
        new_tg = [t for t in tg if str(t.get("id")) != str(chat_id)]
        if len(new_tg) != len(tg):
            rule["targets"] = new_tg
            changed = True
    if changed:
        save_schedules(schedules)
    return changed


def _log_send_run(record):
    """Добавляет запись о завершённой рассылке в историю (newest-first), с ограничением объёма."""
    sends = load_sends()
    sends.insert(0, record)
    if len(sends) > SENDS_KEEP:
        sends = sends[:SENDS_KEEP]
    _write_json(SENDS_JSON, {"sends": sends})


# ---------------------------------------------------------------------------
# Пользователи и аутентификация
# ---------------------------------------------------------------------------
# Модель доступа:
#   • человек регистрируется (логин + пароль) → статус "pending";
#   • войти и пользоваться можно только после одобрения админом ("approved");
#   • первый зарегистрированный пользователь автоматически становится админом;
#   • каждый видит только свои Telegram-профили и расписания (поле owner);
#   • заблокированный ("blocked") пользователь не входит, его рассылки не идут.
def load_users():
    return _read_json(USERS_JSON, {"users": []})["users"]


def save_users(users):
    _write_json(USERS_JSON, {"users": users})


def get_user(uid):
    for u in load_users():
        if u["id"] == uid:
            return u
    return None


def get_user_by_name(username):
    uname = (username or "").strip().lower()
    for u in load_users():
        if u["username"].lower() == uname:
            return u
    return None


def _hash_pw(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return salt, dk.hex()


def _verify_pw(password, salt, expected):
    _, h = _hash_pw(password, salt)
    return secrets.compare_digest(h, expected)


def _sign_token(uid):
    sig = hmac.new(SECRET_KEY.encode("utf-8"), uid.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{uid}.{sig}"


def _verify_token(token):
    if not token or "." not in token:
        return None
    uid, _, sig = token.partition(".")
    expected = hmac.new(SECRET_KEY.encode("utf-8"), uid.encode("utf-8"), hashlib.sha256).hexdigest()
    if not secrets.compare_digest(sig, expected):
        return None
    return uid


def _sub_active(user):
    if (user or {}).get("is_admin"):
        return True   # админ всегда с доступом
    pu = (user or {}).get("paid_until")
    if not pu:
        return False
    try:
        return datetime.now() < datetime.fromisoformat(pu)
    except Exception:
        return False


def _days_left(user):
    pu = (user or {}).get("paid_until")
    if not pu:
        return 0
    try:
        secs = (datetime.fromisoformat(pu) - datetime.now()).total_seconds()
        return max(0, int((secs + 86399) // 86400))  # округление вверх до дней
    except Exception:
        return 0


def _extend_subscription(uid, days):
    """Продлевает подписку: добавляет days к текущей дате (или от now, если истекла)."""
    users = load_users()
    for u in users:
        if u["id"] == uid:
            base = datetime.now()
            if u.get("paid_until"):
                try:
                    pu = datetime.fromisoformat(u["paid_until"])
                    if pu > base:
                        base = pu
                except Exception:
                    pass
            u["paid_until"] = (base + timedelta(days=int(days))).isoformat(timespec="seconds")
            break
    save_users(users)


def _user_public(u):
    return {
        "id": u["id"],
        "username": u["username"],
        "status": u.get("status"),
        "is_admin": bool(u.get("is_admin")),
        "created": u.get("created"),
        "paid_until": u.get("paid_until"),
        "sub_active": _sub_active(u),
        "days_left": _days_left(u),
        "reset_status": u.get("reset_status"),        # None | "pending" | "approved"
        "reset_requested": u.get("reset_requested"),
        "must_setup": bool(u.get("must_setup")),      # вошёл по дефолтному admin/admin — заставить сменить
    }


def _admin_reset_token():
    return (os.environ.get("ADMIN_RESET_TOKEN") or "").strip()


def _bootstrap_admin():
    """Гарантирует вход админа по ADMIN_USER/ADMIN_PASS — чтобы можно было войти даже
    с забытым паролём.

    Механизм «аварийного сброса» через git: пока ADMIN_RESET_TOKEN не меняется, а
    владелец уже задал свои логин/пароль (admin_customized) — дефолтный admin/admin
    НЕ применяется (пароль из git не открывает доступ). Если сменить ADMIN_RESET_TOKEN
    (в docker-compose/.env) — на следующем старте вход принудительно возвращается к
    ADMIN_USER/ADMIN_PASS с требованием заново задать свои данные. Данные (профили,
    расписания) при этом сохраняются — меняются только логин/пароль того же аккаунта.

    Запускается при старте приложения (не при импорте), чтобы не трогать данные во
    время локальных проверок.
    """
    au = (os.environ.get("ADMIN_USER") or "").strip()
    ap = os.environ.get("ADMIN_PASS") or ""
    if not au or not ap:
        return
    token = _admin_reset_token()
    users = load_users()
    # цель: пользователь с таким логином → иначе первый админ → иначе первый в списке
    target = next((u for u in users if u["username"].lower() == au.lower()), None)
    if target is None:
        target = next((u for u in users if u.get("is_admin")), None)
    if target is None and users:
        target = users[0]

    # Владелец уже задал свой вход под ТЕКУЩИМ токеном — ничего не трогаем.
    if target and target.get("admin_customized") and target.get("admin_token") == token:
        return
    # Дефолт уже выдан под текущим токеном и ждёт настройки — файл не переписываем.
    if (target and not target.get("admin_customized")
            and target["username"].lower() == au.lower()
            and target.get("is_admin") and target.get("status") == "approved"
            and target.get("must_setup")
            and target.get("admin_token") == token
            and _verify_pw(ap, target.get("salt", ""), target.get("pw_hash", ""))):
        return

    salt, pw_hash = _hash_pw(ap)
    if target is None:
        # пользователей ещё нет — создаём нового админа
        target = {
            "id": uuid.uuid4().hex[:8],
            "username": au,
            "salt": salt,
            "pw_hash": pw_hash,
            "status": "approved",
            "is_admin": True,
            "must_setup": True,
            "admin_token": token,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        users.append(target)
        save_users(users)
        _claim_orphan_data(target["id"])
    else:
        target["username"] = au
        target["salt"] = salt
        target["pw_hash"] = pw_hash
        target["is_admin"] = True
        target["status"] = "approved"
        target["must_setup"] = True        # после входа заставим задать свои логин/пароль
        target["admin_token"] = token
        target.pop("admin_customized", None)   # снова дефолт — требуется настройка
        target.pop("reset_status", None)
        target.pop("reset_requested", None)
        save_users(users)
    print(f"[bootstrap] аварийный админ-доступ задан из ADMIN_USER/ADMIN_PASS (токен «{token}»): логин «{au}», нужна смена")


def _current_user(request: Request):
    """Возвращает пользователя по cookie-сессии (только одобренного) или None."""
    uid = _verify_token(request.cookies.get("session"))
    if not uid:
        return None
    u = get_user(uid)
    if not u or u.get("status") != "approved":
        return None
    return u


async def require_user(request: Request):
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return u


async def require_admin(request: Request):
    u = _current_user(request)
    if not u or not u.get("is_admin"):
        raise HTTPException(status_code=403, detail="Только для администратора")
    return u


async def require_active(request: Request):
    """Доступ к действиям только при активной подписке (иначе 402 — нужна оплата)."""
    u = _current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Не авторизован")
    if not _sub_active(u):
        raise HTTPException(status_code=402, detail="Подписка неактивна — оплати доступ")
    return u


def _set_session_cookie(resp, uid):
    resp.set_cookie(
        "session",
        _sign_token(uid),
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


# ---------------------------------------------------------------------------
# Глобальное состояние
# ---------------------------------------------------------------------------
class State:
    # profile_id -> TelegramClient
    clients: dict[str, TelegramClient] = {}
    # Не даёт двум корутинам одновременно открыть одну SQLite session Telethon.
    client_locks: dict[str, asyncio.Lock] = {}
    # profile_id -> {"phone": ..., "phone_code_hash": ...}
    login: dict[str, dict] = {}
    # profile_id -> {peer_id: entity}
    entities: dict[str, dict] = {}
    # profile_id -> {"total","done","joined":[],"failed":[],"running"}
    join_jobs: dict[str, dict] = {}
    # profile_id -> {"total","done","ok","failed":[],"running","cancel","status",...}
    send_jobs: dict[str, dict] = {}
    # profile_id -> фоновая задача отправки. Запись появляется ДО первого await,
    # чтобы ручной запуск и планировщик не могли одновременно занять один аккаунт.
    send_tasks: dict[str, asyncio.Task] = {}
    # OCR запускается отдельно от обработчика Telegram, но task держим сильной
    # ссылкой и корректно отменяем при остановке контейнера.
    audit_tasks: set[asyncio.Task] = set()
    audit_ocr_tasks: dict[asyncio.Task, dict] = {}
    audit_archive_tasks: dict[str, dict] = {}
    audit_ocr_recent: dict[str, list[tuple[float, bool]]] = {}
    audit_ocr_dropped: dict[str, int] = {"queue": 0, "quota": 0, "invalid": 0}
    audit_deleted_owners: set[str] = set()
    audit_deleted_profiles: set[str] = set()
    # Serializes audit writes with destructive account operations, preventing an
    # in-flight Telegram callback from recreating evidence after it was deleted.
    audit_owner_locks: dict[str, asyncio.Lock] = {}
    audit_ocr_semaphore = None
    audit_archive_semaphore = None
    audit_archive_media_semaphore = None
    # Момент, раньше которого не начинаем следующую выкачку истории чата.
    audit_archive_next_at = 0.0
    audit_cleanup_at = 0.0
    audit_archive_resume_at = 0.0
    scheduler_task = None
    warm_task = None


state = State()


def _send_busy(pid, *, allow_retry=False):
    """True, если профиль занят или ждёт докатки сохранённой очереди."""
    task = state.send_tasks.get(pid)
    if task is not None and task.done():
        state.send_tasks.pop(pid, None)
        task = None
    job = state.send_jobs.get(pid)
    retry_pending = bool(job and job.get("retry_pending"))
    stopping = bool(job and job.get("stopping"))
    return (
        task is not None
        or bool(job and job.get("running"))
        or stopping
        or (retry_pending and not allow_retry)
    )


def _launch_tracked_send(pid, runner):
    async def tracked():
        try:
            await runner()
        finally:
            current = asyncio.current_task()
            if state.send_tasks.get(pid) is current:
                state.send_tasks.pop(pid, None)

    task = asyncio.create_task(tracked())
    state.send_tasks[pid] = task
    return task


def _start_send_task(pid, runner, *, allow_retry=False):
    """Резервирует профиль и запускает async runner в фоне; None если он занят."""
    if _send_busy(pid, allow_retry=allow_retry):
        return None
    return _launch_tracked_send(pid, runner)


def _reserve_current_send(pid):
    """Резервирует профиль за текущим HTTP-запросом для одиночной отправки."""
    if _send_busy(pid):
        return None
    task = asyncio.current_task()
    if task is None:
        return None
    state.send_tasks[pid] = task
    return task


def _handoff_current_send(pid, reservation, runner):
    """Без окна гонки передаёт резерв HTTP-запроса фоновой задаче."""
    if state.send_tasks.get(pid) is not reservation:
        return None
    return _launch_tracked_send(pid, runner)


def _release_current_send(pid, task):
    if state.send_tasks.get(pid) is task:
        state.send_tasks.pop(pid, None)


async def _discard_queued_send(pid, status):
    """Отменяет уже зарезервированную докатку и только затем удаляет её хвост."""
    job = state.send_jobs.get(pid)
    if job is not None:
        # Tombstone закрывает окно между cancel task и очисткой queue.json.
        job["stopping"] = True

    task = state.send_tasks.get(pid)
    current = asyncio.current_task()
    if task is not None and task is not current and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    if task is not None and state.send_tasks.get(pid) is task and task.done():
        state.send_tasks.pop(pid, None)

    try:
        _queue_clear(pid)
    except Exception:
        current_job = state.send_jobs.get(pid)
        if current_job is not None:
            current_job.pop("stopping", None)
        raise

    current_job = state.send_jobs.get(pid)
    if current_job is not None:
        current_job["running"] = False
        current_job["retry_pending"] = False
        current_job.pop("stopping", None)
        current_job["status"] = status
        current_job["finished"] = datetime.now().isoformat(timespec="seconds")


def _session_path(profile):
    # Сессии лежат в profiles/<id>
    return os.path.join(PROFILES_DIR, profile["id"])


def _parse_proxy(raw):
    """Разбирает строку прокси в формат python-socks для Telethon.
    Поддержка: socks5://user:pass@host:port, host:port:user:pass, host:port."""
    raw = (raw or "").strip()
    if not raw:
        return None
    ptype = "socks5"
    rest = raw
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        ptype = scheme.lower()
    user = pwd = host = port = None
    try:
        if "@" in rest:
            creds, hostport = rest.rsplit("@", 1)
            if ":" in creds:
                user, pwd = creds.split(":", 1)
            else:
                user = creds
            parts = hostport.split(":")
            host, port = parts[0], parts[1]
        else:
            parts = rest.split(":")
            host = parts[0]
            port = parts[1] if len(parts) > 1 else None
            if len(parts) >= 4:        # host:port:user:pass
                user, pwd = parts[2], parts[3]
        if not host or not port:
            return None
        ptype = {"socks5": "socks5", "socks4": "socks4", "http": "http", "https": "http"}.get(ptype, "socks5")
        return {
            "proxy_type": ptype,
            "addr": host,
            "port": int(port),
            "username": user or None,
            "password": pwd or None,
            "rdns": True,
        }
    except Exception:
        return None


def _payment_audit_applies(user):
    """Проверка оплат включена для всех одобренных рабочих аккаунтов.

    Согласие на неё пользователи дают вне панели — подписанным соглашением на
    пользование сервисом, поэтому отдельного экрана-подтверждения в сервисе нет
    и отключить проверку изнутри нельзя.
    """
    return bool(user and user.get("status") == "approved")


def _payment_media_type(event):
    if getattr(event, "photo", None) is not None:
        return "image/jpeg"
    file_obj = getattr(event, "file", None)
    mime = getattr(file_obj, "mime_type", None)
    return str(mime or "") or None


def _payment_ocr_media_allowed(event, media_type):
    """Allow only bounded JPEG/PNG receipts; skip stickers and PDFs."""
    if media_type not in {"image/jpeg", "image/png"}:
        return False
    file_obj = getattr(event, "file", None)
    size = int(getattr(file_obj, "size", 0) or 0)
    # Telegram photos may not expose ``file.size`` on every Telethon version;
    # documents must always advertise a size before we allocate their bytes.
    if size <= 0 and getattr(event, "photo", None) is None:
        return False
    return size <= 0 or size <= PAYMENT_AUDIT_OCR_MAX_BYTES


def _payment_raster_magic_allowed(data):
    return bool(
        isinstance(data, bytes)
        and (
            data.startswith(b"\xff\xd8\xff")
            or data.startswith(b"\x89PNG\r\n\x1a\n")
        )
    )


def _audit_signal_snippet(analysis):
    """Persist only matched payment phrases, never the whole chat/OCR text."""
    fragments = []
    seen = set()
    for item in analysis.get("evidence") or []:
        value = str((item or {}).get("match") or "").strip()
        if value and value.casefold() not in seen:
            fragments.append(value[:80])
            seen.add(value.casefold())
    for amount in analysis.get("amounts") or []:
        value = str((amount or {}).get("raw") or "").strip()
        if value and value.casefold() not in seen:
            fragments.append(value[:48])
            seen.add(value.casefold())
    return mask_sensitive_text(" · ".join(fragments[:8]), 240)


def _trusted_ocr_amounts(rich, signals) -> list[dict]:
    """Keep only amounts that have an explicit currency mark (₽/руб/…)."""
    trusted: list[dict] = []
    seen: set[tuple[float, str]] = set()

    def add(value, currency, raw="", explicit=True):
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        if not math.isfinite(number) or number <= 0:
            return
        currency = str(currency or "RUB")
        key = (number, currency)
        if key in seen:
            return
        seen.add(key)
        trusted.append({
            "value": number,
            "currency": currency,
            "raw": str(raw or value),
            "currency_explicit": bool(explicit),
        })

    for item in rich.get("amounts") or []:
        if item.get("currency_explicit"):
            add(item.get("value"), item.get("currency") or "RUB", item.get("raw") or "")
    for item in getattr(signals, "amounts", ()) or []:
        currency = getattr(item, "currency", None)
        if not currency:
            continue
        add(getattr(item, "value", None), currency, getattr(item, "raw", "") or "")
    return trusted


async def _payment_chat_context(client, chat_id, *, limit=5):
    """Grab a short nearby window so admin can verify without opening Telegram."""
    try:
        messages = await client.get_messages(chat_id, limit=max(1, min(8, int(limit))))
    except Exception:
        return []
    rows = []
    for msg in reversed(list(messages or [])):
        text = (getattr(msg, "raw_text", None) or getattr(msg, "message", None) or "").strip()
        if not text:
            if getattr(msg, "media", None) is not None:
                text = "[фото/файл]"
            else:
                continue
        rows.append({
            "direction": "outgoing" if bool(getattr(msg, "out", False)) else "incoming",
            "snippet": text,
        })
    return normalize_chat_context(rows, limit=5, snippet_limit=120)


def _payment_archive_task_key(owner, pid, chat_key):
    return f"{owner}:{pid}:{chat_key}"


def _payment_archive_message_row(message):
    """Convert a Telethon message/event to a masked archival row."""
    try:
        message_id = int(getattr(message, "id", 0) or 0)
    except (TypeError, ValueError):
        return None
    if message_id <= 0:
        return None
    raw = getattr(message, "raw_text", None)
    if not isinstance(raw, str):
        raw = getattr(message, "message", None)
    text = raw if isinstance(raw, str) else ""
    file_obj = getattr(message, "file", None)
    media_type = str(getattr(file_obj, "mime_type", "") or "")[:80]
    has_media = bool(
        getattr(message, "media", None) is not None
        or getattr(message, "photo", None) is not None
        or file_obj is not None
    )
    if not text.strip() and has_media:
        text = "[фото/вложение]" if (
            getattr(message, "photo", None) is not None or media_type.startswith("image/")
        ) else "[вложение]"
    if not text.strip():
        return None

    def iso(value):
        if not isinstance(value, datetime):
            return ""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="seconds")

    return {
        "id": message_id,
        "direction": "outgoing" if bool(getattr(message, "out", False)) else "incoming",
        "text": mask_sensitive_text(text, 4000),
        "at": iso(getattr(message, "date", None)),
        "edited_at": iso(getattr(message, "edit_date", None)),
        "has_media": has_media,
        "media_type": media_type,
    }


def _payment_archive_image_candidate(message):
    file_obj = getattr(message, "file", None)
    mime = str(getattr(file_obj, "mime_type", "") or "")
    is_image = bool(getattr(message, "photo", None) is not None or mime.startswith("image/"))
    try:
        size = int(getattr(file_obj, "size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    return is_image, mime, max(0, size)


async def _prime_payment_chat_archive_locked(
    archive,
    *,
    owner,
    pid,
    chat_key,
    event,
    media_data=None,
    media_mime="",
    case_outbox=None,
):
    """Persist a trigger while the caller holds the owner's audit lock."""
    if not _payment_audit_scope_active(owner, pid):
        return None
    row = _payment_archive_message_row(event)
    if row is None:
        return await _cancel_safe_to_thread(archive.summary, owner, pid, chat_key)
    media = []
    if isinstance(media_data, (bytes, bytearray)):
        media.append({
            "message_id": row["id"],
            "mime": media_mime or row.get("media_type") or "",
            "data": bytes(media_data),
        })
    return await _cancel_safe_to_thread(
        archive.merge,
        owner,
        pid,
        chat_key,
        [row],
        media=media,
        status="pending",
        reopen_purged=True,
        reopen_at=row.get("edited_at") or row.get("at") or None,
        case_outbox=case_outbox,
    )


async def _prime_payment_chat_archive(archive, **kwargs):
    """Persist the trigger atomically against compact/delete operations."""
    owner = kwargs.get("owner")
    async with _audit_owner_lock(owner):
        return await _prime_payment_chat_archive_locked(archive, **kwargs)


async def _append_existing_payment_chat_message(
    archive, *, owner, pid, chat_key, event,
):
    """Append every continuation/edit after a chat has produced its first signal."""
    row = _payment_archive_message_row(event)
    if row is None:
        return {"appended": False, "image_media": False, "status": "missing"}
    async with _audit_owner_lock(owner):
        if not _payment_audit_scope_active(owner, pid):
            return {"appended": False, "image_media": False, "status": "missing"}
        manifest = await _cancel_safe_to_thread(archive.load, owner, pid, chat_key)
        status = str((manifest or {}).get("status") or "missing")
        if status not in {"pending", "ready", "error"}:
            return {"appended": False, "image_media": False, "status": status}
        await _cancel_safe_to_thread(
            archive.merge,
            owner,
            pid,
            chat_key,
            [row],
            status=status,
            reopen_purged=False,
        )
    is_image, _mime, _size = _payment_archive_image_candidate(event)
    return {"appended": True, "image_media": is_image, "status": status}


def _merge_payment_continuation_media_sync(
    archive, owner, pid, chat_key, media,
):
    """Preserve the live capture status while a slow media download finishes."""
    manifest = archive.load(owner, pid, chat_key)
    status = str((manifest or {}).get("status") or "missing")
    if status not in {"pending", "ready", "error"}:
        return archive.summary(owner, pid, chat_key)
    return archive.merge(
        owner, pid, chat_key, [], media=media, status=status, reopen_purged=False
    )


def _mark_payment_continuation_media_error_sync(archive, owner, pid, chat_key):
    manifest = archive.load(owner, pid, chat_key)
    status = str((manifest or {}).get("status") or "missing")
    if status not in {"pending", "ready", "error"}:
        return archive.summary(owner, pid, chat_key)
    return archive.mark_status(
        owner, pid, chat_key, status, error="media_download", truncated=True
    )


async def _capture_payment_continuation_media(
    client, archive, *, owner, pid, chat_key, event, status,
):
    """Save a newly arrived image directly, before it can be deleted remotely."""
    is_image, mime, declared_size = _payment_archive_image_candidate(event)
    if not is_image or declared_size > max(1024, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES):
        return
    try:
        async with asyncio.timeout(max(2.0, min(30.0, PAYMENT_AUDIT_DOWNLOAD_TIMEOUT))):
            raw = await client.download_media(event.message, file=bytes)
        if (
            not isinstance(raw, (bytes, bytearray))
            or not _payment_raster_magic_allowed(raw)
            or len(raw) > max(1024, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES)
        ):
            raise ValueError("invalid_media")
        await _payment_archive_write(
            archive, owner, pid, _merge_payment_continuation_media_sync,
            archive, owner, pid, chat_key, [{
                "message_id": int(getattr(event, "id", 0) or 0),
                "mime": mime,
                "data": bytes(raw),
            }],
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        await _payment_archive_write(
            archive, owner, pid, _mark_payment_continuation_media_error_sync,
            archive, owner, pid, chat_key,
        )


async def _payment_archive_pace():
    """Держит паузу между выкачками историй разных чатов.

    Простаивающий сервис ждать не заставляет: первая выкачка идёт сразу, а вот
    очередь из десятков диалогов растягивается во времени, чтобы Telegram не
    видел с рабочего аккаунта всплеск запросов истории.
    """
    gap = random.uniform(
        max(0.0, PAYMENT_CHAT_ARCHIVE_GAP_MIN),
        max(PAYMENT_CHAT_ARCHIVE_GAP_MIN, PAYMENT_CHAT_ARCHIVE_GAP_MAX),
    )
    now = time.monotonic()
    wait = state.audit_archive_next_at - now
    state.audit_archive_next_at = max(now, state.audit_archive_next_at) + gap
    if wait > 0:
        await asyncio.sleep(wait)


async def _capture_payment_chat(client, *, owner, pid, chat_id, chat_key):
    """Fetch and encrypt a full readable chat snapshot without sending read ACKs."""
    archive = await _get_payment_chat_archive_async()
    if state.audit_archive_semaphore is None:
        # Text snapshots are urgent; two short chats may backfill in parallel.
        state.audit_archive_semaphore = asyncio.Semaphore(2)
    if state.audit_archive_media_semaphore is None:
        # Heavy images are downloaded one at a time and never block text capture.
        state.audit_archive_media_semaphore = asyncio.Semaphore(1)
    if not _payment_audit_scope_active(owner, pid):
        return
    await _payment_archive_write(
        archive, owner, pid, archive.mark_status,
        owner, pid, chat_key, "pending",
        truncated=False, reset_truncated=True,
    )
    truncated = False
    try:
        max_messages = max(1, min(50_000, PAYMENT_CHAT_ARCHIVE_MAX_MESSAGES))
        capture_deadline = time.monotonic() + max(10.0, PAYMENT_CHAT_ARCHIVE_TIMEOUT)
        async with state.audit_archive_semaphore:
            if not _payment_audit_scope_active(owner, pid):
                return
            await _payment_archive_pace()
            async with asyncio.timeout(max(5.0, capture_deadline - time.monotonic())):
                history = list(await client.get_messages(chat_id, limit=max_messages + 1) or [])
            if len(history) > max_messages:
                history = history[:max_messages]
                truncated = True
            rows = [row for row in (_payment_archive_message_row(msg) for msg in history) if row]
            if not _payment_audit_scope_active(owner, pid):
                return
            summary = await _payment_archive_write(
                archive,
                owner,
                pid,
                archive.merge,
                owner,
                pid,
                chat_key,
                rows,
                status="pending",
                truncated=truncated,
            )
            truncated = bool(truncated or (summary or {}).get("truncated"))

        media_count = 0
        media_total = 0
        media_batch = []
        for message in history:
            is_image, mime, declared_size = _payment_archive_image_candidate(message)
            if not is_image:
                continue
            if media_count >= max(0, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_ITEMS):
                truncated = True
                break
            if declared_size > max(1024, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES):
                truncated = True
                continue
            remaining = capture_deadline - time.monotonic()
            if remaining <= 1:
                truncated = True
                break
            try:
                async with state.audit_archive_media_semaphore:
                    async with asyncio.timeout(
                        max(1.0, min(30.0, PAYMENT_AUDIT_DOWNLOAD_TIMEOUT, remaining))
                    ):
                        raw = await client.download_media(message, file=bytes)
            except Exception:
                truncated = True
                continue
            if not isinstance(raw, (bytes, bytearray)):
                truncated = True
                continue
            raw = bytes(raw)
            if (
                not _payment_raster_magic_allowed(raw)
                or len(raw) > max(1024, PAYMENT_CHAT_ARCHIVE_MAX_MEDIA_BYTES)
            ):
                truncated = True
                continue
            if media_total + len(raw) > max(1024, PAYMENT_CHAT_ARCHIVE_MAX_TOTAL_MEDIA_BYTES):
                truncated = True
                break
            media_batch.append({
                "message_id": int(getattr(message, "id", 0) or 0),
                "mime": mime,
                "data": raw,
            })
            media_count += 1
            media_total += len(raw)
            if len(media_batch) >= 5:
                if not _payment_audit_scope_active(owner, pid):
                    return
                summary = await _payment_archive_write(
                    archive,
                    owner,
                    pid,
                    archive.merge,
                    owner,
                    pid,
                    chat_key,
                    [],
                    media=media_batch,
                    status="pending",
                    truncated=truncated,
                )
                truncated = bool(truncated or (summary or {}).get("truncated"))
                media_batch = []
        if media_batch and _payment_audit_scope_active(owner, pid):
            summary = await _payment_archive_write(
                archive,
                owner,
                pid,
                archive.merge,
                owner,
                pid,
                chat_key,
                [],
                media=media_batch,
                status="pending",
                truncated=truncated,
            )
            truncated = bool(truncated or (summary or {}).get("truncated"))
        if not _payment_audit_scope_active(owner, pid):
            return
        await _payment_archive_write(
            archive,
            owner,
            pid,
            archive.mark_status,
            owner,
            pid,
            chat_key,
            "ready",
            truncated=truncated,
        )
    except asyncio.CancelledError:
        raise
    except FloodWaitError as exc:
        await _payment_archive_write(
            archive, owner, pid, archive.mark_status,
            owner, pid, chat_key, "error",
            error=f"FloodWaitError:{max(30, min(3600, int(exc.seconds or 0)))}",
            truncated=truncated,
        )
    except Exception as exc:
        await _payment_archive_write(
            archive, owner, pid, archive.mark_status,
            owner, pid, chat_key, "error",
            error=type(exc).__name__, truncated=truncated,
        )


def _schedule_payment_chat_archive(client, *, owner, pid, chat_id, chat_key):
    key = _payment_archive_task_key(owner, pid, chat_key)
    existing = state.audit_archive_tasks.get(key)
    if existing and not existing["task"].done():
        # A signal may arrive after the running task already fetched history.
        # Remember it and perform exactly one fresh pass when the current pass ends.
        existing["dirty"] = True
        existing["client"] = client
        existing["chat_id"] = chat_id
        return existing["task"]

    async def runner():
        try:
            while True:
                current = asyncio.current_task()
                meta = state.audit_archive_tasks.get(key)
                if meta is None or meta.get("task") is not current:
                    return
                meta["dirty"] = False
                await _capture_payment_chat(
                    meta.get("client") or client,
                    owner=owner,
                    pid=pid,
                    chat_id=meta.get("chat_id", chat_id),
                    chat_key=chat_key,
                )
                meta = state.audit_archive_tasks.get(key)
                if meta is None or meta.get("task") is not current or not meta.get("dirty"):
                    break
        finally:
            current = asyncio.current_task()
            meta = state.audit_archive_tasks.get(key)
            if meta and meta.get("task") is current:
                state.audit_archive_tasks.pop(key, None)

    task = _track_audit_task(runner())
    state.audit_archive_tasks[key] = {
        "task": task,
        "owner": str(owner),
        "pid": str(pid),
        "chat_key": str(chat_key),
        "client": client,
        "chat_id": chat_id,
        "dirty": False,
    }
    return task


async def _cancel_payment_archive_tasks(*, owner=None, profile_ids=None, chat_key=None):
    profiles = {str(pid) for pid in (profile_ids or [])}
    tasks = []
    for meta in list(state.audit_archive_tasks.values()):
        if owner is not None and meta.get("owner") != str(owner):
            continue
        if profiles and meta.get("pid") not in profiles:
            continue
        if chat_key is not None and meta.get("chat_key") != str(chat_key):
            continue
        task = meta.get("task")
        if task is not None and not task.done():
            task.cancel()
            tasks.append(task)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def _payment_amounts_label(case):
    amounts = [
        a for a in (case.get("amounts") or [])
        if isinstance(a, dict) and float(a.get("value") or 0) > 0
    ]
    if not amounts:
        return "сумма не распознана"
    parts = []
    for a in amounts[:3]:
        value = float(a.get("value") or 0)
        currency = a.get("currency") or "RUB"
        suffix = "₽" if currency == "RUB" else str(currency)
        parts.append(f"{value:g} {suffix}")
    return " · ".join(parts)


def _notify_admins_payment_case(case, *, owner_name=""):
    """Surface a fresh medium/high case in the admin panel notifications."""
    if (case or {}).get("level") not in {"high", "medium"}:
        return
    if case.get("created_at") != case.get("updated_at"):
        return
    context = case.get("context") or []
    if context:
        preview = " | ".join(
            ("аккаунт" if row.get("direction") == "outgoing" else "клиент")
            + f": «{row.get('snippet')}»"
            for row in context[-3:]
        )
    else:
        evidence = case.get("evidence") or []
        snippets = [str(e.get("snippet") or "") for e in evidence if e.get("snippet")]
        preview = " · ".join(snippets[-2:]) or "сигнал без текста"
    who = owner_name or case.get("owner") or "?"
    level = "высокая" if case.get("level") == "high" else "средняя"
    text = (
        f"💳 Оплата ({level}): {who} · {_payment_amounts_label(case)} · "
        f"{case.get('chat_label') or 'диалог'}. {preview}"
    )
    for user in load_users():
        if user.get("is_admin") and user.get("status") == "approved":
            _add_notification(user["id"], case.get("profile_id") or "", "warn", text[:500])


def _contextualize_payment_analysis(analysis, *, direction, is_forwarded=False):
    """Interpret a phrase from the work account's point of view.

    A client saying «скинул» is a possible incoming payment; the worker saying
    the same thing is an outgoing transfer. Requests, plans, reversals and
    forwarded evidence stay review signals but can never become proof.
    """
    result = dict(analysis or {})
    categories = set(result.get("categories") or [])
    confidence = float(result.get("confidence") or 0)
    negated = bool(result.get("negated") or categories & {
        "payment_negation", "refund_or_reversal", "negated",
    })
    completed = "transfer_completed" in categories
    confirmed = "payment_confirmation" in categories
    receipt = bool(categories & {"receipt", "receipt_ocr"})
    uncertain = bool(result.get("uncertain") or result.get("question"))

    income_claim = bool(
        result.get("detected")
        and result.get("success_claim")
        and not negated
        and not uncertain
        and not is_forwarded
        and (
            (direction == "incoming" and completed)
            or (direction == "outgoing" and confirmed)
        )
    )

    if direction == "outgoing" and completed and not confirmed:
        categories.add("outgoing_transfer")
        confidence = min(confidence, 0.45)
    if direction == "incoming" and confirmed and not completed:
        categories.add("counterparty_received")
        confidence = min(confidence, 0.45)
    if result.get("event_status") in {"requested", "intent"}:
        confidence = min(confidence, 0.58)
    if negated:
        confidence = min(confidence, 0.42)
        income_claim = False
    if uncertain:
        categories.add("uncertain_claim")
        confidence = min(confidence, 0.45)
        income_claim = False
    if is_forwarded:
        categories.add("forwarded_receipt" if receipt else "forwarded_evidence")
        confidence = min(confidence, 0.42)
        income_claim = False

    result["categories"] = sorted(categories)
    result["confidence"] = round(max(0.0, min(confidence, 1.0)), 2)
    result["level"] = (
        "high" if confidence >= 0.75 else
        "medium" if confidence >= 0.48 else
        "low" if result.get("detected") else "none"
    )
    result["income_claim"] = income_claim
    result["direction"] = direction
    return result


def _payment_event_version(event, source, text):
    if source != "edited":
        return source
    message = getattr(event, "message", None)
    edited_at = getattr(message, "edit_date", None)
    digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:12]
    return f"edited:{edited_at or ''}:{digest}"


def _payment_observed_at(event, source):
    if source == "edited":
        edited_at = getattr(getattr(event, "message", None), "edit_date", None)
        if edited_at is not None:
            return edited_at
    return getattr(event, "date", None)


def _track_audit_task(awaitable, *, ocr_pid=None, priority=False):
    task = asyncio.create_task(awaitable)
    state.audit_tasks.add(task)
    if ocr_pid is not None:
        state.audit_ocr_tasks[task] = {
            "pid": str(ocr_pid),
            "priority": bool(priority),
            "running": False,
        }

    def done(finished):
        state.audit_tasks.discard(finished)
        state.audit_ocr_tasks.pop(finished, None)
        try:
            finished.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            # Не печатаем текст/медиа/имя диалога — только класс технической ошибки.
            print(f"[payment-audit] background {type(exc).__name__}")

    task.add_done_callback(done)
    return task


def _payment_audit_scope_blocked(owner, pid):
    return bool(
        str(owner) in state.audit_deleted_owners
        or str(pid) in state.audit_deleted_profiles
    )


def _audit_owner_lock(owner):
    key = str(owner)
    lock = state.audit_owner_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        state.audit_owner_locks[key] = lock
    return lock


async def _cancel_safe_to_thread(func, /, *args, **kwargs):
    """Keep a filesystem mutation alive until its worker thread really stopped.

    Cancelling ``asyncio.to_thread`` only cancels the awaiter. Without the shield,
    compact/delete could run while the old thread writes the archive back.
    """
    worker = asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        try:
            await worker
        finally:
            raise


async def _payment_archive_write(archive, owner, pid, func, /, *args, **kwargs):
    """Serialize archive writes with profile/owner deletion and manual compact."""
    async with _audit_owner_lock(owner):
        if not _payment_audit_scope_active(owner, pid):
            return None
        return await _cancel_safe_to_thread(func, *args, **kwargs)


def _payment_audit_scope_active(owner, pid):
    if _payment_audit_scope_blocked(owner, pid):
        return False
    user = get_user(owner)
    profile = get_profile(pid)
    return bool(
        _payment_audit_applies(user)
        and _sub_active(user)
        and profile
        and profile.get("owner") == owner
    )


def _payment_case_outbox(record_kwargs):
    """Return a small JSON-safe replay record for the encrypted archive."""
    allowed = {
        "event_key", "chat_key", "observed_at", "direction", "analysis",
        "snippet", "source", "media_hash", "message_ref", "chat_ref", "context",
    }
    unknown = set(record_kwargs) - allowed
    if unknown:
        raise ValueError("unsupported payment outbox fields")

    def encode(value):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat(timespec="seconds")
        raise TypeError(f"unsupported outbox value: {type(value).__name__}")

    record = json.loads(json.dumps(
        record_kwargs,
        ensure_ascii=False,
        separators=(",", ":"),
        default=encode,
        allow_nan=False,
    ))
    if not str(record.get("event_key") or "") or not str(record.get("chat_key") or ""):
        raise ValueError("incomplete payment outbox")
    return {"version": 1, "record": record}


def _payment_archive_stage(archive_seed):
    """Prepare Telegram data on the event loop before a SQLite worker uses it."""
    if not isinstance(archive_seed, dict):
        return None
    chat_key = str(archive_seed.get("chat_key") or "")
    event = archive_seed.get("event")
    row = _payment_archive_message_row(event)
    if not chat_key or row is None:
        return None
    media = []
    media_data = archive_seed.get("media_data")
    if isinstance(media_data, (bytes, bytearray)):
        media.append({
            "message_id": row["id"],
            "mime": archive_seed.get("media_mime") or row.get("media_type") or "",
            "data": bytes(media_data),
        })
    return chat_key, row, media


def _stage_payment_case_sync(archive, *, owner, pid, stage, outbox):
    """Durably seed trigger + replay record before SQLite commits the case."""
    chat_key, row, media = stage
    return archive.merge(
        owner,
        pid,
        chat_key,
        [row],
        media=media,
        status="pending",
        reopen_purged=True,
        reopen_at=row.get("edited_at") or row.get("at") or None,
        case_outbox=outbox,
    )


async def _record_payment_event(store, *, owner, pid, archive_seed=None, **kwargs):
    """Commit one event with an encrypted crash-replay marker for its trigger."""
    async with _audit_owner_lock(owner):
        if not _payment_audit_scope_active(owner, pid):
            return None
        archive = None
        stage = _payment_archive_stage(archive_seed)
        staged = False
        if stage is not None:
            if stage[0] != str(kwargs.get("chat_key") or ""):
                raise ValueError("archive seed does not match payment chat")
            try:
                archive = await _get_payment_chat_archive_async()
                await _cancel_safe_to_thread(
                    _stage_payment_case_sync,
                    archive,
                    owner=owner,
                    pid=pid,
                    stage=stage,
                    outbox=_payment_case_outbox(kwargs),
                )
                staged = True
            except Exception as exc:
                # The compact payment fact is still better than losing the signal
                # when the optional heavy archive cannot be initialized.
                archive = None
                print(f"[payment-archive] prepare {type(exc).__name__}")
        case = await _cancel_safe_to_thread(
            store.record_event,
            owner=owner,
            profile_id=pid,
            **kwargs,
        )
        if isinstance(case, dict) and case.get("id") and archive is not None and staged:
            try:
                await _cancel_safe_to_thread(
                    archive.clear_case_outbox,
                    owner,
                    pid,
                    stage[0],
                )
            except Exception as exc:
                # Leaving the marker is intentional: startup replay is idempotent.
                print(f"[payment-archive] outbox-clear {type(exc).__name__}")
        return case


async def _record_payment_retraction(store, *, owner, pid, chat_key,
                                     message_ref, record_kwargs, archive_seed=None):
    """Check-and-retract the same message under one audit/delete lock."""
    async with _audit_owner_lock(owner):
        if not _payment_audit_scope_active(owner, pid):
            return None
        exists = await _cancel_safe_to_thread(
            store.has_message, owner, pid, chat_key, message_ref
        )
        if not exists:
            return None
        archive = None
        stage = _payment_archive_stage(archive_seed)
        staged = False
        if stage is not None:
            if stage[0] != str(chat_key) or stage[0] != str(record_kwargs.get("chat_key") or ""):
                raise ValueError("archive seed does not match payment chat")
            try:
                archive = await _get_payment_chat_archive_async()
                await _cancel_safe_to_thread(
                    _stage_payment_case_sync,
                    archive,
                    owner=owner,
                    pid=pid,
                    stage=stage,
                    outbox=_payment_case_outbox(record_kwargs),
                )
                staged = True
            except Exception as exc:
                archive = None
                print(f"[payment-archive] prepare-retraction {type(exc).__name__}")
        case = await _cancel_safe_to_thread(
            store.record_event,
            owner=owner,
            profile_id=pid,
            **record_kwargs,
        )
        if isinstance(case, dict) and case.get("id") and archive is not None and staged:
            try:
                await _cancel_safe_to_thread(
                    archive.clear_case_outbox,
                    owner,
                    pid,
                    stage[0],
                )
            except Exception as exc:
                print(f"[payment-archive] retraction-outbox-clear {type(exc).__name__}")
        return case


def _active_ocr_meta():
    return [
        meta for task, meta in state.audit_ocr_tasks.items()
        if not task.done() and not task.cancelling()
    ]


def _cancel_audit_ocr_for_profiles(profile_ids):
    targets = {str(pid) for pid in profile_ids}
    for task, meta in list(state.audit_ocr_tasks.items()):
        if str(meta.get("pid")) in targets and not task.done():
            task.cancel()


def _audit_ocr_queue_has_capacity(pid, *, priority=False):
    if priority:
        # A likely receipt must not sit behind a burst of ordinary photos.
        for task, meta in list(state.audit_ocr_tasks.items()):
            if not meta.get("priority") and not meta.get("running") and not task.done():
                task.cancel()
                state.audit_ocr_dropped["queue"] += 1
    active = _active_ocr_meta()
    total_limit = max(1, PAYMENT_AUDIT_OCR_QUEUE_MAX)
    pid_count = sum(1 for meta in active if meta.get("pid") == str(pid))
    if priority:
        return len(active) < total_limit and pid_count < 4
    ordinary_limit = min(4, max(1, total_limit - max(2, total_limit // 5)))
    return len(active) < ordinary_limit and pid_count < 2


def _audit_ocr_allowed(pid, *, priority=False):
    now = time.monotonic()
    recent = [
        (ts, was_priority) for ts, was_priority in state.audit_ocr_recent.get(pid, [])
        if now - ts < 3600
    ]
    limit = max(1, PAYMENT_AUDIT_OCR_PER_HOUR)
    ordinary_limit = max(1, limit - max(3, limit // 4))
    if len(recent) >= limit or (
        not priority and sum(1 for _ts, was_priority in recent if not was_priority) >= ordinary_limit
    ):
        state.audit_ocr_recent[pid] = recent
        state.audit_ocr_dropped["quota"] += 1
        return False
    recent.append((now, bool(priority)))
    state.audit_ocr_recent[pid] = recent
    return True


async def _audit_receipt_media(client, event, *, owner, pid, chat_id, direction,
                               media_type, is_forwarded=False, priority=False,
                               message_source="message"):
    archive_media_data = None
    if _payment_audit_scope_blocked(owner, pid):
        return
    user = get_user(owner)
    if not _payment_audit_applies(user) or not _sub_active(user):
        return
    if not _payment_ocr_media_allowed(event, media_type):
        return
    file_obj = getattr(event, "file", None)
    size = int(getattr(file_obj, "size", 0) or 0)
    if size > PAYMENT_AUDIT_OCR_MAX_BYTES:
        return
    if state.audit_ocr_semaphore is None:
        state.audit_ocr_semaphore = asyncio.Semaphore(1)

    async with state.audit_ocr_semaphore:
        meta = state.audit_ocr_tasks.get(asyncio.current_task())
        if meta is not None:
            meta["running"] = True
        # A queued item may start after access expired or the account was deleted.
        user = get_user(owner)
        if (
            _payment_audit_scope_blocked(owner, pid)
            or not _payment_audit_applies(user)
            or not _sub_active(user)
            or not _audit_ocr_allowed(pid, priority=priority)
        ):
            return
        try:
            async with asyncio.timeout(max(1.0, PAYMENT_AUDIT_DOWNLOAD_TIMEOUT)):
                data = await client.download_media(event.message, file=bytes)
        except TimeoutError:
            print("[payment-audit] media download TimeoutError")
            return
        if (
            not _payment_raster_magic_allowed(data)
            or len(data) > PAYMENT_AUDIT_OCR_MAX_BYTES
        ):
            state.audit_ocr_dropped["invalid"] += 1
            return
        user = get_user(owner)
        if (
            _payment_audit_scope_blocked(owner, pid)
            or not _payment_audit_applies(user)
            or not _sub_active(user)
        ):
            data = None
            return
        try:
            result = await receipt_ocr.analyze_bytes_async(data)
            # OCR already downloaded the likely receipt. Keep one bounded copy
            # until the case is recorded so a Telegram deletion cannot erase it.
            archive_media_data = bytes(data)
        except ReceiptOcrError as exc:
            print(f"[payment-audit] OCR {type(exc).__name__}")
            return
        finally:
            # Явно отпускаем единственную ссылку на банковский скриншот.
            data = None

    # OCR часто «рисует» голые цифры (телефон, id, мусор). Без ₽/руб им нельзя
    # верить — иначе получаются фантомные 30108 ₽ вместо реальных 400 ₽.
    rich = analyze_payment_signal(
        result.text,
        direction=direction,
        media_type=media_type,
        is_forwarded=is_forwarded,
        allow_bare_amounts=False,
    )
    if not rich.get("detected") and not result.signals.is_likely_payment:
        return

    categories = set(rich.get("categories") or [])
    categories.update({"receipt", "receipt_ocr"})
    amounts = _trusted_ocr_amounts(rich, result.signals)
    caption = (getattr(event, "raw_text", None) or "").strip()
    if caption:
        caption_rich = analyze_payment_signal(
            caption,
            direction=direction,
            media_type=media_type,
            is_forwarded=is_forwarded,
            allow_bare_amounts=False,
        )
        for item in caption_rich.get("amounts") or []:
            if item.get("currency_explicit") or float(item.get("value") or 0) > 0:
                key = (float(item.get("value") or 0), item.get("currency") or "RUB")
                if key not in {(float(a.get("value") or 0), a.get("currency") or "RUB") for a in amounts}:
                    if item.get("currency_explicit"):
                        amounts.append(item)
    ocr_confidence = {"high": 0.86, "medium": 0.62, "low": 0.35}.get(
        result.signals.confidence, 0.3
    )
    confidence = max(float(rich.get("confidence") or 0), ocr_confidence)
    success_claim = bool(rich.get("success_claim"))
    event_status = rich.get("event_status") if rich.get("event_status") != "none" else "receipt"
    if not amounts:
        # Чек/слова про перевод есть, но надёжной суммы нет — не выдумываем.
        categories.discard("amount")
        confidence = min(confidence, 0.45)
        success_claim = False
        if event_status == "completed":
            event_status = "receipt"
    analysis = {
        **rich,
        "detected": True,
        "categories": sorted(categories),
        "amounts": amounts,
        "confidence": confidence,
        "success_claim": success_claim,
        "event_status": event_status,
        "dedup_hashes": [
            key for key in (result.exact_dedup_key, result.text_dedup_key) if key
        ],
    }
    analysis = _contextualize_payment_analysis(
        analysis,
        direction=direction,
        is_forwarded=is_forwarded,
    )
    user = get_user(owner)
    if (
        _payment_audit_scope_blocked(owner, pid)
        or not _payment_audit_applies(user)
        or not _sub_active(user)
    ):
        return
    profile = get_profile(pid)
    if not profile or profile.get("owner") != owner:
        return
    store = await _get_payment_audit_store_async()
    if store is None:
        return
    message_id = getattr(event, "id", 0)
    ocr_version = "ocr:" + _payment_event_version(
        event, message_source, getattr(event, "raw_text", "") or ""
    )
    chat_key = store.chat_key(pid, chat_id)
    case = await _record_payment_event(
        store,
        owner=owner,
        pid=pid,
        event_key=store.event_key(pid, chat_id, message_id, ocr_version),
        chat_key=chat_key,
        message_ref=store.message_ref(pid, chat_id, message_id),
        chat_ref=chat_id,
        observed_at=_payment_observed_at(event, message_source),
        direction=direction,
        analysis=analysis,
        snippet=_audit_signal_snippet(analysis),
        # Store revisions must use the canonical source so the previous live
        # amount/categories for this exact Telegram message are replaced.
        source="edited" if message_source == "edited" else "ocr",
        media_hash=result.media_sha256,
        context=None,
        archive_seed={
            "chat_key": chat_key,
            "event": event,
            "media_data": archive_media_data,
            "media_mime": media_type,
        },
    )
    archive_media_data = None
    if isinstance(case, dict) and case.get("id"):
        _schedule_payment_chat_archive(
            client,
            owner=owner,
            pid=pid,
            chat_id=chat_id,
            chat_key=chat_key,
        )
        owner_user = get_user(owner) or {}
        _notify_admins_payment_case(case, owner_name=owner_user.get("username") or "")


async def _handle_payment_message(client, pid, event, *, source="message"):
    try:
        if not event.is_private or event.chat_id in (None, 777000):
            return
        if str(pid) in state.audit_deleted_profiles:
            return
        profile = get_profile(pid)
        owner = (profile or {}).get("owner")
        if _payment_audit_scope_blocked(owner, pid):
            return
        user = get_user(owner) if owner else None
        if not _payment_audit_applies(user) or not _sub_active(user):
            return
        store = await _get_payment_audit_store_async()
        if store is None:
            return
        direction = "outgoing" if bool(getattr(event, "out", False)) else "incoming"
        media_type = _payment_media_type(event)
        text = getattr(event, "raw_text", "") or ""
        forwarded = bool(getattr(getattr(event, "message", None), "fwd_from", None))
        analysis = analyze_payment_signal(
            text,
            direction=direction,
            media_type=media_type,
            is_forwarded=forwarded,
        )
        analysis = _contextualize_payment_analysis(
            analysis,
            direction=direction,
            is_forwarded=forwarded,
        )
        event_version = _payment_event_version(event, source, text)
        message_ref = store.message_ref(pid, event.chat_id, event.id)
        chat_key = store.chat_key(pid, event.chat_id)
        case = None
        if analysis.get("detected"):
            case = await _record_payment_event(
                store,
                owner=owner,
                pid=pid,
                event_key=store.event_key(pid, event.chat_id, event.id, event_version),
                chat_key=chat_key,
                message_ref=message_ref,
                chat_ref=event.chat_id,
                observed_at=_payment_observed_at(event, source),
                direction=direction,
                analysis=analysis,
                snippet=_audit_signal_snippet(analysis),
                source=source,
                context=None,
                archive_seed={"chat_key": chat_key, "event": event},
            )
        elif analysis.get("money_mentioned") and source != "edited":
            # Про деньги в этом сообщении говорили, но на полноценный сигнал не
            # набралось. Всё равно сохраняем: рабочие чаты часто удаляют сразу
            # после заказа, и переспросить будет уже негде.
            weak = dict(analysis)
            weak.update({
                "detected": True,
                "categories": sorted(set(analysis.get("categories") or []) | {"money_mentioned"}),
                "amounts": analysis.get("money_amounts") or [],
                "evidence": analysis.get("money_evidence") or [],
                "confidence": min(float(analysis.get("confidence") or 0), 0.25),
                "event_status": "possible",
                "success_claim": False,
                "income_claim": False,
                "level": "low",
            })
            case = await _record_payment_event(
                store,
                owner=owner,
                pid=pid,
                event_key=store.event_key(pid, event.chat_id, event.id, event_version),
                chat_key=chat_key,
                message_ref=message_ref,
                chat_ref=event.chat_id,
                observed_at=_payment_observed_at(event, source),
                direction=direction,
                analysis=weak,
                snippet=_audit_signal_snippet(weak),
                source=source,
                context=None,
                archive_seed={"chat_key": chat_key, "event": event},
            )
        notify_case = isinstance(case, dict) and bool(case.get("id"))
        if not notify_case and not analysis.get("detected") and source == "edited":
            # An edited message that used to be a payment signal is material:
            # keep the historical evidence but remove its live amount/status.
            case = await _record_payment_retraction(
                store,
                owner=owner,
                pid=pid,
                chat_key=chat_key,
                message_ref=message_ref,
                record_kwargs={
                    "event_key": store.event_key(pid, event.chat_id, event.id, event_version),
                    "chat_key": chat_key,
                    "message_ref": message_ref,
                    "chat_ref": event.chat_id,
                    "observed_at": _payment_observed_at(event, source),
                    "direction": direction,
                    "analysis": {
                        "detected": True,
                        "categories": ["message_retracted"],
                        "amounts": [],
                        "confidence": 0,
                        "event_status": "retracted",
                        "success_claim": False,
                        "income_claim": False,
                        "attribution": "forwarded" if forwarded else "direct",
                    },
                    "snippet": "",
                    "source": "edited",
                },
                archive_seed={"chat_key": chat_key, "event": event},
            )

        if isinstance(case, dict) and case.get("id"):
            _schedule_payment_chat_archive(
                client,
                owner=owner,
                pid=pid,
                chat_id=event.chat_id,
                chat_key=chat_key,
            )
            is_archive_image, _archive_mime, _archive_size = _payment_archive_image_candidate(event)
            if is_archive_image:
                archive = await _get_payment_chat_archive_async()
                _track_audit_task(_capture_payment_continuation_media(
                    client,
                    archive,
                    owner=owner,
                    pid=pid,
                    chat_key=chat_key,
                    event=event,
                    status="pending",
                ))
            if notify_case:
                _notify_admins_payment_case(case, owner_name=(user or {}).get("username") or "")
        else:
            try:
                archive = await _get_payment_chat_archive_async()
                continuation = await _append_existing_payment_chat_message(
                    archive,
                    owner=owner,
                    pid=pid,
                    chat_key=chat_key,
                    event=event,
                )
                started = False
                if not continuation.get("appended"):
                    seeded = await _prime_payment_chat_archive(
                        archive,
                        owner=owner,
                        pid=pid,
                        chat_key=chat_key,
                        event=event,
                    )
                    started = True
                    continuation["status"] = str((seeded or {}).get("status") or "pending")
                if started or continuation.get("status") in {"pending", "error"}:
                    # Первый любой диалог сохраняем сразу, не дожидаясь слов об
                    # оплате. Если сигнал появится позже, ранняя часть уже на диске.
                    _schedule_payment_chat_archive(
                        client,
                        owner=owner,
                        pid=pid,
                        chat_id=event.chat_id,
                        chat_key=chat_key,
                    )
                is_archive_image, _archive_mime, _archive_size = _payment_archive_image_candidate(event)
                if is_archive_image and (started or continuation.get("appended")):
                    _track_audit_task(_capture_payment_continuation_media(
                        client,
                        archive,
                        owner=owner,
                        pid=pid,
                        chat_key=chat_key,
                        event=event,
                        status=continuation.get("status"),
                    ))
            except (PaymentChatArchiveError, ValueError) as exc:
                print(f"[payment-archive] continuation {type(exc).__name__}")

        ocr_priority = bool(analysis.get("detected"))
        if _payment_ocr_media_allowed(event, media_type):
            if not _audit_ocr_queue_has_capacity(pid, priority=ocr_priority):
                state.audit_ocr_dropped["queue"] += 1
                return
            _track_audit_task(_audit_receipt_media(
                client,
                event,
                owner=owner,
                pid=pid,
                chat_id=event.chat_id,
                direction=direction,
                media_type=media_type,
                is_forwarded=forwarded,
                priority=ocr_priority,
                message_source=source,
            ), ocr_pid=pid, priority=ocr_priority)
    except Exception as exc:
        print(f"[payment-audit] message {type(exc).__name__}")


def _register_response_listener(client, pid):
    """Вешает счётчик откликов и, после согласия, проверку оплат рабочих ЛС."""
    if getattr(client, "_resp_listener", False):
        return
    client._resp_listener = True

    @client.on(events.NewMessage(incoming=True))
    async def _on_incoming(event):
        try:
            if not event.is_private:
                return                      # интересуют только личные сообщения
            if event.chat_id == 777000:
                return                      # служебные уведомления Telegram — не отклик
            _bump_response(pid)
        except Exception:
            pass                            # учёт отклика не критичен — молча пропускаем

    @client.on(events.NewMessage())
    async def _on_payment_message(event):
        await _handle_payment_message(client, pid, event)

    @client.on(events.MessageEdited())
    async def _on_payment_edit(event):
        await _handle_payment_message(client, pid, event, source="edited")


async def get_client(pid) -> TelegramClient | None:
    """Возвращает подключённый клиент для профиля (создаёт при необходимости)."""
    lock = state.client_locks.setdefault(pid, asyncio.Lock())
    async with lock:
        # Повторно проверяем кэш уже под lock: другой запрос мог подключить
        # клиента, пока мы ждали, иначе Telethon получит SQLite "database locked".
        client = state.clients.get(pid)
        if client is not None:
            if not client.is_connected():
                await client.connect()
            _register_response_listener(client, pid)
            return client

        profile = get_profile(pid)
        if profile is None:
            return None

        client = TelegramClient(
            _session_path(profile), profile["api_id"], profile["api_hash"],
            proxy=_parse_proxy(profile.get("proxy")),
        )
        try:
            await client.connect()
        except BaseException:
            # connect() успевает поднять внутренние Telethon task до ошибки или
            # отмены. Явно закрываем их, иначе они остаются pending до GC.
            try:
                await client.disconnect()
            except Exception:
                pass
            raise
        state.clients[pid] = client
        state.entities.setdefault(pid, {})
        _register_response_listener(client, pid)
        return client


# ---------------------------------------------------------------------------
# Описание чатов
# ---------------------------------------------------------------------------
def _kind(e):
    if isinstance(e, User):
        return "user"
    if isinstance(e, Chat):
        return "group"
    if isinstance(e, Channel):
        return "group" if e.megagroup else "channel"
    return "chat"


def _name(e):
    if isinstance(e, User):
        full = " ".join(filter(None, [e.first_name, e.last_name]))
        return full or (("@" + e.username) if e.username else str(e.id))
    return getattr(e, "title", None) or str(e.id)


def _brief(e):
    return {
        "id": utils.get_peer_id(e),
        "name": _name(e),
        "kind": _kind(e),
        "username": getattr(e, "username", None) or "",
    }


def _cache(pid, e):
    state.entities.setdefault(pid, {})[utils.get_peer_id(e)] = e


async def _resolve(pid, peer_id):
    """Возвращает Telethon-сущность по id: из кэша или через сессию."""
    cache = state.entities.setdefault(pid, {})
    if peer_id in cache:
        return cache[peer_id]
    client = await get_client(pid)
    entity = await client.get_entity(peer_id)
    cache[peer_id] = entity
    return entity


# ---------------------------------------------------------------------------
# Фоновый планировщик
# ---------------------------------------------------------------------------
def _due(rule, now):
    """Пора ли срабатывать правилу в момент now (с окном 5 минут)."""
    try:
        hh, mm = rule["time"].split(":")
        sched = int(hh) * 60 + int(mm)
    except Exception:
        return False
    cur = now.hour * 60 + now.minute
    if not (0 <= cur - sched <= 5):
        return False

    today = now.strftime("%Y-%m-%d")
    dates = rule.get("dates") or []
    weekdays = rule.get("weekdays") or []
    if dates:
        return today in dates
    if weekdays:
        return now.weekday() in weekdays
    return True  # каждый день


# ---------------------------------------------------------------------------
# Защита от флуда / бана (FloodWait, PeerFlood)
# ---------------------------------------------------------------------------
# Пауза между сообщениями в разные чаты (анти-всплеск), сек — дефолт.
SEND_GAP_MIN = float(os.environ.get("SEND_GAP_MIN", "10"))
SEND_GAP_MAX = float(os.environ.get("SEND_GAP_MAX", "30"))


def _send_gap(lo=None, hi=None):
    """Случайная пауза между чатами (сек). Использует заданный диапазон или дефолт."""
    try:
        lo = float(lo) if lo is not None else SEND_GAP_MIN
        hi = float(hi) if hi is not None else SEND_GAP_MAX
    except (TypeError, ValueError):
        lo, hi = SEND_GAP_MIN, SEND_GAP_MAX
    if lo < 0:
        lo = 0
    if hi < lo:
        hi = lo
    return random.uniform(lo, hi)


def _on_cooldown(profile):
    """True, если профиль сейчас на охлаждении после флуда."""
    cu = (profile or {}).get("cooldown_until")
    if not cu:
        return False
    try:
        return datetime.now() < datetime.fromisoformat(cu)
    except Exception:
        return False


def _set_cooldown(pid, seconds, note=None, flagged=False):
    """Ставит профиль на паузу на `seconds` секунд (и опционально помечает спам-флагом)."""
    profiles = load_profiles()
    for p in profiles:
        if p["id"] == pid:
            until = datetime.now() + timedelta(seconds=max(1, int(seconds)))
            p["cooldown_until"] = until.isoformat(timespec="seconds")
            p["flood_note"] = note or ""
            if flagged:
                p["flagged"] = True
            break
    save_profiles(profiles)


def _clear_cooldown(pid):
    profiles = load_profiles()
    changed = False
    for p in profiles:
        if p["id"] == pid:
            for k in ("cooldown_until", "flood_note", "flagged"):
                if k in p:
                    p.pop(k, None)
                    changed = True
            break
    if changed:
        save_profiles(profiles)


# ---------------------------------------------------------------------------
# Прогрев аккаунта (мягкий старт для новых акков — анти-бан)
# ---------------------------------------------------------------------------
# Лимиты в режиме прогрева: (в час, в сутки). Консервативно, чтобы не забанили.
WARMUP_LIMITS = {
    "join": (int(os.environ.get("WARMUP_JOIN_HOUR", "5")), int(os.environ.get("WARMUP_JOIN_DAY", "20"))),
    "send": (int(os.environ.get("WARMUP_SEND_HOUR", "10")), int(os.environ.get("WARMUP_SEND_DAY", "30"))),
}


def _wu_allow(pid, kind):
    """True, если действие (kind='join'|'send') разрешено. При прогреве считает лимиты в час/сутки."""
    profile = get_profile(pid)
    if not profile or not profile.get("warmup"):
        return True  # прогрев выключен — без ограничений
    now = datetime.now()
    hour_key = now.strftime("%Y-%m-%d-%H")
    day_key = now.strftime("%Y-%m-%d")
    per_hour, per_day = WARMUP_LIMITS.get(kind, (999999, 999999))
    profiles = load_profiles()
    for p in profiles:
        if p["id"] != pid:
            continue
        ctr = p.setdefault("wu", {})
        hk, dk = f"{kind}_h", f"{kind}_d"
        if ctr.get(hk, {}).get("k") != hour_key:
            ctr[hk] = {"k": hour_key, "n": 0}
        if ctr.get(dk, {}).get("k") != day_key:
            ctr[dk] = {"k": day_key, "n": 0}
        if ctr[hk]["n"] >= per_hour or ctr[dk]["n"] >= per_day:
            return False
        ctr[hk]["n"] += 1
        ctr[dk]["n"] += 1
        save_profiles(profiles)
        return True
    return True


def _send_gate(pid):
    """True, если отправка сейчас разрешена.
    Прогрев → лимиты прогрева. Иначе → дневной лимит профиля (daily_limit, 0 = без лимита).
    В любом случае ведёт дневной счётчик sent_today для показа пользователю."""
    profile = get_profile(pid) or {}
    if profile.get("warmup"):
        return _wu_allow(pid, "send")
    limit = int(profile.get("daily_limit") or 0)
    day_key = datetime.now().strftime("%Y-%m-%d")
    profiles = load_profiles()
    for p in profiles:
        if p["id"] != pid:
            continue
        ctr = p.get("sent_today") or {}
        if ctr.get("k") != day_key:
            ctr = {"k": day_key, "n": 0}
        if limit > 0 and ctr["n"] >= limit:
            p["sent_today"] = ctr
            save_profiles(profiles)
            return False
        ctr["n"] += 1
        p["sent_today"] = ctr
        save_profiles(profiles)
        return True
    return True


_SPIN_RE = re.compile(r"\{([^{}]*)\}")


def _spin(text):
    """Spintax: {привет|здравствуй} → случайный вариант (с поддержкой вложенности)."""
    out = text or ""
    for _ in range(50):
        new = _SPIN_RE.sub(lambda m: random.choice(m.group(1).split("|")), out)
        if new == out:
            break
        out = new
    return out


def _spin_issue(text):
    """Проверяет spintax на пустые варианты. Возвращает текст ошибки или None."""
    for m in _SPIN_RE.finditer(text or ""):
        opts = m.group(1).split("|")
        if any(o.strip() == "" for o in opts):
            return "В фигурных скобках {…} есть пустой вариант — сообщение может уйти пустым. Убери лишний «|» или заполни вариант."
    return None


# имитация набора текста перед отправкой (человечнее — меньше похоже на бота)
HUMAN_TYPING = os.environ.get("HUMAN_TYPING", "1") != "0"


def _classify_send_error(e):
    """Разбирает причину, почему сообщение не ушло, и как на неё реагировать.
    Возвращает (category, reason_human, seconds).
      'dead'  — аккаунт забанен/деактивирован/сессия отозвана → СТОП всей рассылки;
      'badmsg'— проблема с текстом (длина/пустой) → СТОП (везде не отправится);
      'slow'  — медленный режим чата → пропустить чат (временно, не в счётчик мёртвых);
      'skip'  — чат недоступен (нет прав/бан в чате/не участник) → пропустить + в счётчик;
      'error' — неизвестная причина → пропустить + в счётчик.
    """
    name = type(e).__name__
    low = (name + " " + str(e)).lower()
    seconds = getattr(e, "seconds", None)

    # 0) получатель удалил свой аккаунт — это про ЧАТ, а не про нас (проверяем раньше «dead»,
    #    т.к. 'inputuserdeactivated' содержит подстроку 'userdeactivated')
    if "inputuserdeactivated" in low:
        return "skip", "получатель удалил аккаунт", None

    # 1) НАШ аккаунт мёртв — слать дальше бессмысленно и опасно
    for k in ("userdeactivatedban", "userdeactivated", "authkeyunregistered",
              "authkeyduplicated", "sessionrevoked", "sessionexpired",
              "phonenumberbanned"):
        if k in low:
            return "dead", "аккаунт заблокирован/деактивирован Telegram", None

    # 2) проблема с самим текстом — не отправится ни в один чат
    if "messagetoolong" in low or "message is too long" in low:
        return "badmsg", "сообщение слишком длинное — сократи текст", None
    if "messageempty" in low or "message empty" in low or "textempty" in low:
        return "badmsg", "пустое сообщение (проверь текст/spintax)", None

    # 3) медленный режим — временно, просто пропускаем чат
    if "slowmodewait" in low or "slow mode" in low:
        s = f" (жди {seconds}с)" if seconds else ""
        return "slow", f"медленный режим в чате{s} — пропущен", seconds

    # 4) чат недоступен — пропускаем и копим счётчик на авто-удаление
    if "userbannedinchannel" in low or "banned" in low:
        return "skip", "аккаунт забанен в этом чате", None
    if "channelprivate" in low:
        return "skip", "чат приватный или тебя удалили/не участник", None
    if ("chatwriteforbidden" in low or "chatadminrequired" in low
            or "chatsendmediaforbidden" in low or "forbidden" in low
            or "chatrestricted" in low or "notallowed" in low
            or "chatguestsendforbidden" in low or "senderrestricted" in low):
        return "skip", "нет прав писать в этот чат (нужно вступить/подписаться или доступ закрыт)", None
    if "peeridinvalid" in low or "invalid" in low and "peer" in low:
        return "skip", "чат недоступен (неверный/удалён)", None

    return "error", (str(e) or name)[:120], None


async def _send_one(client, pid, target, text):
    """Отправляет одно сообщение. Возвращает (category, detail).
    category: ok|flood|spam|limit|dead|badmsg|slow|skip|error (см. _classify_send_error)."""
    if not _send_gate(pid):
        return "limit", None   # достигнут лимит (прогрев или дневной)
    try:
        entity = await _resolve(pid, target["id"])
        msg = _spin(text)   # каждый раз свой вариант текста
        if HUMAN_TYPING:
            try:
                async with client.action(entity, "typing"):
                    await asyncio.sleep(random.uniform(0.8, 2.2))
            except Exception:
                pass  # имитация не критична — при сбое просто шлём
        await client.send_message(entity, msg)
        return "ok", None
    except FloodWaitError as e:
        wait = e.seconds + 30  # запас сверху
        _set_cooldown(pid, wait, note=f"Пауза {e.seconds}с — Telegram просит притормозить (FloodWait).")
        print(f"[flood] профиль {pid}: FloodWait {e.seconds}s → пауза до отправки")
        if e.seconds >= 120:   # мелкие флуды не спамим уведомлениями
            prof = get_profile(pid) or {}
            _add_notification(prof.get("owner"), pid, "warn",
                              f"⏸ «{prof.get('name', pid)}»: Telegram просит паузу {e.seconds}с (FloodWait). Рассылка приостановлена, продолжится сама.")
            await _notify_saved(pid, f"⏸ Бот рассылки: аккаунт на паузе {e.seconds}с (FloodWait). Снизь частоту.")
        return "flood", e.seconds
    except PeerFloodError:
        _set_cooldown(pid, 6 * 3600, note="Telegram пометил аккаунт как спам. Отправки остановлены на 6 ч — снизь частоту.", flagged=True)
        print(f"[flood] профиль {pid}: PeerFloodError (спам-флаг) → длинная пауза + флаг")
        prof = get_profile(pid) or {}
        _add_notification(prof.get("owner"), pid, "error",
                          f"⛔ «{prof.get('name', pid)}»: Telegram пометил аккаунт как СПАМ. Рассылки остановлены на 6 ч. Снизь частоту/объём, включи прогрев.")
        await _notify_saved(pid, "⛔ Бот рассылки: аккаунт помечен спамом (PeerFlood). Отправки на паузе 6 ч.")
        return "spam", None
    except Exception as e:
        cat, reason, _ = _classify_send_error(e)
        print(f"[send] профиль {pid} → {target.get('name')}: [{cat}] {e}")
        if cat == "dead":
            # аккаунт мёртв — длинная пауза, флаг, стоп рассылки, алерт
            _set_cooldown(pid, 24 * 3600, note="Аккаунт заблокирован Telegram. Отправки остановлены.", flagged=True)
            prof = get_profile(pid) or {}
            _add_notification(prof.get("owner"), pid, "error",
                              f"⛔ «{prof.get('name', pid)}»: аккаунт ЗАБЛОКИРОВАН Telegram — рассылки остановлены. Нужен новый аккаунт.")
            await _notify_saved(pid, "⛔ Бот рассылки: этот аккаунт заблокирован Telegram. Рассылки остановлены.")
        return cat, reason


# статус завершения bulk-рассылки → человекочитаемая метка
_BULK_STATUS = {
    "cancel": "остановлено",
    "inactive": "аккаунт не активный",
    "flood": "флуд-пауза",
    "spam": "спам-флаг",
    "limit": "дневной лимит",
    "cooldown": "на паузе",
    "dead": "аккаунт заблокирован",
    "badmsg": "проблема с текстом",
    "error": "ошибка",
    None: "готово",
}


class _InitialQueuePersistError(RuntimeError):
    """Первичная запись очереди не удалась: отправку ещё можно безопасно откатить."""


# категории, при которых рассылку надо ОСТАНОВИТЬ целиком (а не пропускать чат)
_STOP_CATEGORIES = ("flood", "spam", "limit", "dead", "badmsg")


async def _send_bulk(pid, targets, text, gap_lo=None, gap_hi=None, source="ручная",
                     label="", started=None, done=0, ok=0, failed=None, fresh=True):
    """Последовательная отправка по чатам: пауза между ними, защита от флуда,
    живой прогресс (state.send_jobs), отмена, докатка при рестарте и запись в историю.
    targets — оставшиеся к отправке чаты (при докатке — недоотправленный хвост)."""
    remaining = list(targets)
    if fresh:
        random.shuffle(remaining)   # случайный порядок чатов — меньше похоже на бота
    started = started or datetime.now().isoformat(timespec="seconds")
    n = done + len(remaining)   # общий размер рассылки (с учётом уже отправленных при докатке)
    job = {
        "running": True, "cancel": False,
        "total": n, "done": done, "ok": ok, "failed": failed or [],
        "status": "running", "source": source, "label": label,
        "started": started,
        "text_preview": (text or "")[:80],
    }
    state.send_jobs[pid] = job
    owner = (get_profile(pid) or {}).get("owner")

    def _persist():
        _queue_put({
            "pid": pid, "text": text, "gap_lo": gap_lo, "gap_hi": gap_hi,
            "source": source, "label": label, "owner": owner, "started": started,
            "done": job["done"], "ok": job["ok"], "failed": job["failed"],
            "remaining": remaining,
        })

    interrupted = None   # None | cancel | flood | spam | limit | cooldown
    shutdown = False
    errored = False
    ready = False
    persisted = False
    try:
        # Сохраняем полный хвост ДО первого await. Если процесс остановится при
        # подключении к Telegram, задача безопасно докатится после рестарта.
        try:
            _persist()
        except Exception as e:
            raise _InitialQueuePersistError(str(e)) from e
        persisted = True
        client = await get_client(pid)
        if client is None or not await client.is_user_authorized():
            return
        ready = True

        while remaining:
            if job.get("cancel"):
                interrupted = "cancel"
                break
            if _on_cooldown(get_profile(pid)):
                interrupted = "cooldown"
                break
            if _active_pid(owner) != pid:   # активным сделали другой аккаунт — стоп
                interrupted = "inactive"
                break
            target = remaining[0]
            status, detail = await _send_one(client, pid, target, text)
            # категории, требующие остановить всю рассылку (аккаунт/текст, а не чат)
            if status in _STOP_CATEGORIES:
                interrupted = status
                if status == "badmsg":   # текст не отправится никуда — сообщаем причину
                    _add_notification(owner, pid, "error",
                                      f"✋ «{get_profile(pid).get('name', pid) if get_profile(pid) else pid}»: рассылка остановлена — {detail}. Исправь текст и запусти заново.")
                break
            remaining.pop(0)
            job["done"] += 1
            if status == "ok":
                job["ok"] += 1
                _record_chat_result(pid, target.get("id"), True)   # сброс счётчика ошибок чата
            elif status == "slow":
                # медленный режим — временно, чат пропущен, но НЕ считаем «мёртвым»
                job["failed"].append({"name": target.get("name") or "", "reason": detail or "медленный режим"})
            else:  # 'skip' (чат недоступен) или 'error' (неизвестно) — пропуск + счётчик
                job["failed"].append({"name": target.get("name") or "", "reason": (detail or "")[:120]})
                # авто-удаление мёртвого чата после N подряд ошибок
                if _record_chat_result(pid, target.get("id"), False):
                    if _remove_chat_from_schedules(pid, target.get("id")):
                        _add_notification(owner, pid, "info",
                                          f"🧹 Чат «{target.get('name') or target.get('id')}» убран из расписаний — {CHAT_FAIL_LIMIT} ошибки подряд (недоступен/бан).")
            _persist()   # прогресс на диск → докатится после краша
            if remaining and not job.get("cancel"):
                await asyncio.sleep(_send_gap(gap_lo, gap_hi))
    except asyncio.CancelledError:
        shutdown = True   # выключение сервера — оставляем хвост в очереди для докатки
        raise
    except Exception:
        interrupted = "error"
        errored = True
        raise
    finally:
        job["running"] = False
        if shutdown or errored:
            if errored:
                # Пока хвост лежит на диске, не даём новой ручной рассылке
                # заменить его до следующей попытки scheduler.
                job["retry_pending"] = persisted
                job["status"] = (
                    "ошибка — повторю автоматически" if persisted
                    else "ошибка сохранения — попробуй снова"
                )
            if persisted:
                try:
                    _persist()   # хвост подхватит scheduler или следующий старт
                except Exception as e:
                    print(f"[send] не удалось обновить очередь {pid}: {e}")
        elif ready:
            try:
                _queue_clear(pid)
            except Exception as e:
                print(f"[send] не удалось очистить очередь {pid}: {e}")
            job["status"] = _BULK_STATUS.get(interrupted, "готово")
            job["finished"] = datetime.now().isoformat(timespec="seconds")
            _log_send_run({
                "id": secrets.token_hex(6),
                "profile_id": pid,
                "owner": owner,
                "started": job["started"],
                "finished": job["finished"],
                "total": n,
                "ok": job["ok"],
                "failed": job["failed"],
                "status": job["status"],
                "source": source,
                "label": label,
                "text_preview": job["text_preview"],
            })
        elif persisted:
            # Профиль не авторизован или подключение упало до отправки. Старое
            # поведение — не писать пустую историю и убрать очередь.
            try:
                _queue_clear(pid)
            except Exception as e:
                print(f"[send] не удалось очистить очередь {pid}: {e}")


async def _send_bulk_safe(pid, targets, text, gap_lo=None, gap_hi=None, source="ручная",
                          label="", started=None, done=0, ok=0, failed=None, fresh=True):
    try:
        await _send_bulk(pid, targets, text, gap_lo, gap_hi, source, label,
                         started, done, ok, failed, fresh)
    except Exception as e:
        print(f"[send] фоновая отправка {pid}: {e}")


# ---------------------------------------------------------------------------
# Авто-вступление в чаты/каналы по ссылкам
# ---------------------------------------------------------------------------
# Вступление — операция с ВЫСОКИМ риском бана, поэтому паузы большие.
JOIN_GAP_MIN = float(os.environ.get("JOIN_GAP_MIN", "25"))
JOIN_GAP_MAX = float(os.environ.get("JOIN_GAP_MAX", "60"))


def _parse_join_link(link):
    """('private', invite_hash) | ('public', username) | None."""
    s = (link or "").strip()
    if not s:
        return None
    s = s.replace("https://", "").replace("http://", "")
    s = s.replace("t.me/", "").replace("telegram.me/", "").strip("/")
    if s.startswith("@"):
        s = s[1:]
    if s.startswith("joinchat/"):
        return ("private", s[len("joinchat/"):])
    if s.startswith("+"):
        return ("private", s[1:])
    username = s.split("/")[0].split("?")[0]
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", username):
        return ("public", username)
    return None


def _join_err(e):
    name = type(e).__name__
    low = (str(e) + name).lower()
    if "already" in low:
        return "уже участник"
    if "expired" in low:
        return "ссылка истекла"
    if "invalid" in low or "invitehashempty" in low:
        return "ссылка недействительна"
    if "toomuch" in low or "too much" in low:
        return "лимит каналов аккаунта исчерпан"
    if "privacy" in low or "ban" in low or "kick" in low:
        return "нет доступа (бан/приват)"
    return name


async def _interruptible_sleep(job, seconds):
    """Спит, периодически проверяя флаг отмены."""
    slept = 0
    while slept < seconds:
        if job.get("cancel"):
            return
        await asyncio.sleep(2)
        slept += 2


async def _join_job(pid, links):
    job = state.join_jobs[pid]
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        job["running"] = False
        job["status"] = "не авторизован"
        return

    # собрать уже вступленные публичные username — чтобы пропускать без попытки
    joined_usernames = set()
    try:
        async for d in client.iter_dialogs():
            u = getattr(d.entity, "username", None)
            if u:
                joined_usernames.add(u.lower())
    except Exception:
        pass

    for i, link in enumerate(links):
        if job.get("cancel"):
            break
        parsed = _parse_join_link(link)
        if not parsed:
            job["failed"].append({"link": link, "reason": "не похоже на ссылку"})
            job["done"] += 1
            continue
        kind, val = parsed

        # пропуск уже вступленных публичных каналов
        if kind == "public" and val.lower() in joined_usernames:
            job["skipped"].append({"link": link, "reason": "уже участник"})
            job["done"] += 1
            continue

        # лимит прогрева на вступления
        if not _wu_allow(pid, "join"):
            job["status"] = "достигнут лимит прогрева — продолжи позже"
            break

        attempts = 0
        while True:
            attempts += 1
            try:
                if kind == "private":
                    await client(ImportChatInviteRequest(val))
                else:
                    ent = await client.get_entity(val)
                    await client(JoinChannelRequest(ent))
                job["joined"].append({"link": link})
                if kind == "public":
                    joined_usernames.add(val.lower())
                break
            except FloodWaitError as e:
                # авто-продолжение: ждём флуд и пробуем снова (если не слишком долго)
                if e.seconds > 3600 or attempts > 3:
                    job["failed"].append({"link": link, "reason": f"flood {e.seconds}s — слишком долго, пропуск"})
                    break
                job["status"] = f"флуд: жду {e.seconds}с и продолжаю…"
                await _interruptible_sleep(job, e.seconds + 5)
                if job.get("cancel"):
                    break
                job["status"] = "running"
                continue
            except Exception as e:
                reason = _join_err(e)
                job["skipped" if reason == "уже участник" else "failed"].append({"link": link, "reason": reason})
                break

        job["done"] += 1
        if job.get("cancel"):
            break
        if i < len(links) - 1:
            await _interruptible_sleep(job, random.uniform(JOIN_GAP_MIN, JOIN_GAP_MAX))

    job["running"] = False
    if job.get("cancel"):
        job["status"] = "остановлено"
    elif not str(job.get("status", "")).startswith("достигнут лимит"):
        job["status"] = "готово"


async def _join_job_safe(pid, links):
    try:
        await _join_job(pid, links)
    except Exception as e:
        print(f"[join] {pid}: {e}")
        if pid in state.join_jobs:
            state.join_jobs[pid]["running"] = False


async def _fire_rule(rule):
    """Отправляет сообщение правила по всем его чатам, с защитой от флуда."""
    pid = rule["profile_id"]
    if _on_cooldown(get_profile(pid)):
        return
    label = rule.get("name") or rule.get("time") or "по интервалу"
    await _send_bulk(pid, rule.get("targets", []), rule["text"],
                     rule.get("gap_min"), rule.get("gap_max"),
                     source="расписание", label=label)


async def _fire_rule_safe(rule):
    try:
        await _fire_rule(rule)
    except asyncio.CancelledError:
        raise
    except _InitialQueuePersistError:
        # Только scheduler знает, какой claim надо вернуть в due-состояние.
        raise
    except Exception as e:
        print(f"[scheduler] правило {rule.get('id')}: {e}")


def _interval_due_priority(rule, now):
    """Ключ очередности для наступившего интервала; None если ещё рано."""
    nf = rule.get("next_fire")
    if not nf:
        created = str(rule.get("created") or "").replace(" ", "T")
        return created or now.isoformat(timespec="seconds")
    try:
        due_at = datetime.fromisoformat(nf)
        if now < due_at:
            return None
    except Exception:
        created = str(rule.get("created") or "").replace(" ", "T")
        return created or now.isoformat(timespec="seconds")
    return due_at.isoformat(timespec="seconds")


def _schedule_allowed(rule):
    if not rule.get("enabled", True):
        return False
    owner = rule.get("owner")
    if owner is not None:
        user = get_user(owner)
        if user is None or user.get("status") != "approved" or not _sub_active(user):
            return False
    prof = get_profile(rule["profile_id"])
    if _on_cooldown(prof):
        return False
    return prof is not None and _active_pid(prof.get("owner")) == prof["id"]


def _claim_scheduled_rule(sid, pid, now):
    """Свежим чтением атомарно помечает одно due-правило перед первым await."""
    schedules = load_schedules()
    rule = next((item for item in schedules
                 if item.get("id") == sid and item.get("profile_id") == pid), None)
    if rule is None or not _schedule_allowed(rule):
        return None

    if rule.get("interval_min"):
        if _interval_due_priority(rule, now) is None:
            return None
        before_present = "next_fire" in rule
        before = rule.get("next_fire")
        lo = int(rule.get("interval_min") or 1)
        hi = int(rule.get("interval_max") or lo)
        if hi < lo:
            hi = lo
        delay = random.randint(lo, hi)
        rule["next_fire"] = (now + timedelta(minutes=delay)).isoformat(timespec="seconds")
        claim = {
            "kind": "interval", "before": before, "before_present": before_present,
            "after": rule["next_fire"],
        }
    else:
        occ = rule.get("pending_fire")
        if not occ:
            if not _due(rule, now):
                return None
            occ = now.strftime("%Y-%m-%d") + "T" + rule["time"]
        if rule.get("last_fired") == occ:
            rule.pop("pending_fire", None)
            save_schedules(schedules)
            return None
        before_present = "last_fired" in rule
        before = rule.get("last_fired")
        rule["last_fired"] = occ
        rule.pop("pending_fire", None)
        claim = {
            "kind": "clock", "before": before, "before_present": before_present,
            "after": occ,
        }

    save_schedules(schedules)
    claimed = dict(rule)
    claimed["_scheduler_claim"] = claim
    return claimed


def _rollback_scheduled_claim(claimed):
    """Возвращает claim в due-состояние, если очередь не удалось создать."""
    marker = claimed.get("_scheduler_claim") or {}
    schedules = load_schedules()
    rule = next((item for item in schedules
                 if item.get("id") == claimed.get("id")
                 and item.get("profile_id") == claimed.get("profile_id")), None)
    if rule is None:
        return

    kind = marker.get("kind")
    after = marker.get("after")
    if kind == "interval":
        if rule.get("next_fire") != after:
            return
        if marker.get("before_present"):
            rule["next_fire"] = marker.get("before")
        else:
            rule.pop("next_fire", None)
    elif kind == "clock":
        if rule.get("last_fired") != after:
            return
        if marker.get("before_present"):
            rule["last_fired"] = marker.get("before")
        else:
            rule.pop("last_fired", None)
        rule["pending_fire"] = after
    else:
        return
    save_schedules(schedules)


async def _run_scheduled_rule(sid, pid, now):
    rule = None
    try:
        rule = _claim_scheduled_rule(sid, pid, now)
        if rule is not None:
            await _fire_rule_safe(rule)
    except _InitialQueuePersistError as e:
        try:
            if rule is not None:
                _rollback_scheduled_claim(rule)
        except Exception as rollback_error:
            print(f"[scheduler] не удалось вернуть claim правила {sid}: {rollback_error}")
        print(f"[scheduler] очередь правила {sid} не сохранена: {e}")
    except asyncio.CancelledError:
        raise
    except Exception as e:
        print(f"[scheduler] правило {sid}: {e}")


def _scheduler_tick(now=None):
    """Один неблокирующий проход планировщика.

    Файл читается, изменяется и сохраняется без единого ``await``. Поэтому API не
    может вклиниться между чтением и записью, а новая настройка пользователя не
    будет затёрта старым снимком после многоминутной рассылки.
    """
    now = now or datetime.now()
    today = now.strftime("%Y-%m-%d")
    schedules = load_schedules()
    changed = False
    candidates = []

    for pos, rule in enumerate(schedules):
        try:
            if not _schedule_allowed(rule):
                continue

            # Режим интервала: каждые N (случайно min..max) минут
            if rule.get("interval_min"):
                priority = _interval_due_priority(rule, now)
                if priority is not None:
                    candidates.append((priority, pos, rule["id"], rule["profile_id"]))
                continue

            # Уже зафиксированное occurrence важнее очистки даты: если отправка
            # в 23:58 ждала занятой профиль до полуночи, она не должна исчезнуть.
            pending = rule.get("pending_fire")
            if pending and rule.get("last_fired") != pending:
                candidates.append((pending, pos, rule["id"], rule["profile_id"]))
                continue
            if pending:
                rule.pop("pending_fire", None)
                changed = True

            # Чистим прошедшие конкретные даты у разовых правил
            if rule.get("dates"):
                fresh = [d for d in rule["dates"] if d >= today]
                if fresh != rule["dates"]:
                    rule["dates"] = fresh
                    changed = True
                if not fresh:
                    rule["enabled"] = False
                    changed = True
                    continue

            if not _due(rule, now):
                continue

            occ = today + "T" + rule["time"]
            if rule.get("last_fired") != occ:
                # Если профиль занят или перед ним есть другое правило, occurrence
                # не потеряется после узкого пятиминутного окна _due().
                rule["pending_fire"] = occ
                changed = True
                candidates.append((occ, pos, rule["id"], rule["profile_id"]))
        except Exception as e:
            print(f"[scheduler] повреждённое правило {rule.get('id')}: {e}")

    # Если у одного профиля несколько просроченных правил, первым запускаем
    # самое старое. Остальные останутся due и попадут в следующий свободный тик.
    candidates.sort(key=lambda item: (item[0], item[1]))
    claimed_pids = set()
    pending = []
    for _, _, sid, pid in candidates:
        if pid in claimed_pids or _send_busy(pid):
            continue
        claimed_pids.add(pid)
        pending.append((sid, pid))

    # Здесь сохраняются только очистка дат и pending occurrence. next_fire и
    # last_fired ставит _claim_scheduled_rule свежим чтением внутри task — до
    # первого await и без сохранения старого снимка после отправки.
    if changed:
        save_schedules(schedules)

    for sid, pid in pending:
        _start_send_task(pid, lambda sid=sid, pid=pid, now=now: _run_scheduled_rule(sid, pid, now))


async def _scheduler_loop():
    """Каждые 20 секунд отмечает due-правила и запускает их в фоне."""
    while True:
        try:
            # Подхватывает хвост не только после рестарта, но и после временной
            # ошибки подключения/диска в фоновой задаче.
            await _resume_queued_sends()
            _scheduler_tick()
            if time.monotonic() >= state.audit_archive_resume_at:
                state.audit_archive_resume_at = time.monotonic() + 5 * 60
                await _resume_pending_payment_archives()
            if time.monotonic() >= state.audit_cleanup_at:
                state.audit_cleanup_at = time.monotonic() + 24 * 60 * 60
                store = await _get_payment_audit_store_async()
                if store is not None:
                    await asyncio.to_thread(store.cleanup)
                    if PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS > 0:
                        archive = await _get_payment_chat_archive_async()
                        await asyncio.to_thread(
                            archive.cleanup, PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS
                        )
        except Exception as e:
            print(f"[scheduler] ошибка цикла: {e}")

        await asyncio.sleep(20)


async def _resume_queued_sends():
    """Докатка: после рестарта продолжает рассылки, прерванные на середине."""
    queued_pids = list(dict.fromkeys(j.get("pid") for j in _queue_load()))
    for queued_pid in queued_pids:
        # Предыдущий discard мог await отмену активной task. Поэтому берём
        # запись заново и не запускаем устаревший снимок очереди.
        j = next((item for item in _queue_load() if item.get("pid") == queued_pid), None)
        if j is None:
            continue
        remaining = j.get("remaining") or []
        if not remaining:
            await _discard_queued_send(queued_pid, "готово")
            continue
        # владелец должен быть активен, иначе не возобновляем
        ou = get_user(j.get("owner")) if j.get("owner") else None
        if j.get("owner") and (ou is None or ou.get("status") != "approved" or not _sub_active(ou)):
            await _discard_queued_send(queued_pid, "доступ закрыт")
            continue
        # докатываем только активный аккаунт — с неактивного рассылать нельзя
        prof = get_profile(j.get("pid"))
        if prof is None or _active_pid(prof.get("owner")) != prof["id"]:
            await _discard_queued_send(queued_pid, "аккаунт не активный")
            continue
        task = _start_send_task(
            j["pid"],
            lambda j=j, remaining=remaining: _send_bulk_safe(
                j["pid"], remaining, j.get("text", ""),
                j.get("gap_lo"), j.get("gap_hi"),
                j.get("source", "ручная"), j.get("label", ""),
                j.get("started"), int(j.get("done") or 0), int(j.get("ok") or 0),
                j.get("failed") or [], False,   # fresh=False — хвост не перемешиваем
            ),
            allow_retry=True,
        )
        if task is not None:
            print(f"[resume] докатка рассылки {j.get('pid')}: осталось {len(remaining)} чат(ов)")


async def _warm_response_listeners():
    """Подключает Telegram listeners последовательно, не создавая залп сессий.

    Для обычного счётчика достаточно активного профиля. После явного согласия
    на проверку рабочих оплат слушаем все рабочие профили владельца, чтобы смена
    активного аккаунта не создавала слепое окно.
    """
    profiles = load_profiles()
    owners = {p.get("owner") for p in profiles if p.get("owner")}
    pids = []
    for owner in owners:
        pid = _active_pid(owner)
        if pid:
            pids.append(pid)
        user = get_user(owner)
        if _payment_audit_applies(user) and _sub_active(user):
            pids.extend(p["id"] for p in profiles if p.get("owner") == owner)

    for pid in dict.fromkeys(pids):
        try:
            client = await get_client(pid)   # подключит + зарегистрирует слушатель
            if client:
                try:
                    await client.catch_up()   # добрать апдейты, пропущенные в даунтайм
                except Exception:
                    pass
        except Exception as e:
            print(f"[resp] прогрев слушателя {pid}: {e}")
        await asyncio.sleep(2)
    await _resume_pending_payment_archives()


async def _resume_pending_payment_archives():
    """Replay committed archive markers, then resume interrupted snapshots."""
    try:
        archive = await _get_payment_chat_archive_async()
        store = await _get_payment_audit_store_async()
    except Exception as exc:
        print(f"[payment-archive] resume {type(exc).__name__}")
        return
    if store is None:
        return
    try:
        outboxes = await asyncio.to_thread(archive.list_case_outboxes)
    except Exception as exc:
        print(f"[payment-archive] outbox-list {type(exc).__name__}")
        outboxes = []
    allowed = {
        "event_key", "chat_key", "observed_at", "direction", "analysis",
        "snippet", "source", "media_hash", "message_ref", "chat_ref", "context",
    }
    for item in outboxes:
        owner = str(item.get("owner") or "")
        pid = str(item.get("profile_id") or "")
        chat_key = str(item.get("chat_key") or "")
        payload = item.get("outbox")
        record = payload.get("record") if isinstance(payload, dict) else None
        if (
            not owner or not pid or not chat_key
            or not isinstance(payload, dict) or payload.get("version") != 1
            or not isinstance(record, dict) or set(record) - allowed
            or str(record.get("chat_key") or "") != chat_key
            or not str(record.get("event_key") or "")
        ):
            print("[payment-archive] invalid encrypted outbox")
            continue
        async with _audit_owner_lock(owner):
            if not _payment_audit_scope_active(owner, pid):
                # Consent/profile removal wins over a crash-replay marker.
                try:
                    await _cancel_safe_to_thread(
                        archive.purge, owner, pid, chat_key, tombstone=False
                    )
                except Exception as exc:
                    print(f"[payment-archive] stale-outbox-purge {type(exc).__name__}")
                continue
            try:
                await _cancel_safe_to_thread(
                    store.record_event,
                    owner=owner,
                    profile_id=pid,
                    **record,
                )
                await _cancel_safe_to_thread(
                    archive.clear_case_outbox, owner, pid, chat_key
                )
            except Exception as exc:
                # The marker remains encrypted and is safe to retry next startup.
                print(f"[payment-archive] outbox-replay {type(exc).__name__}")

    try:
        pending = await asyncio.to_thread(archive.list_statuses, ("pending", "error"))
    except Exception as exc:
        print(f"[payment-archive] pending-list {type(exc).__name__}")
        return
    for item in pending:
        if item.get("status") == "error":
            retry_seconds = 5 * 60
            error = str(item.get("last_error") or "")
            if error.startswith("FloodWaitError:"):
                try:
                    retry_seconds = max(retry_seconds, min(3600, int(error.split(":", 1)[1])))
                except (TypeError, ValueError):
                    pass
            try:
                changed = datetime.fromisoformat(str(item.get("updated_at") or "").replace("Z", "+00:00"))
                if changed.tzinfo is None:
                    changed = changed.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) < changed.astimezone(timezone.utc) + timedelta(seconds=retry_seconds):
                    continue
            except (TypeError, ValueError):
                pass
        owner = str(item.get("owner") or "")
        pid = str(item.get("profile_id") or "")
        chat_key = str(item.get("chat_key") or "")
        if not _payment_audit_scope_active(owner, pid):
            continue
        cases = await asyncio.to_thread(store.list_chat_cases, owner, chat_key)
        case = next((row for row in reversed(cases) if row.get("chat_ref")), None)
        if case is None:
            continue
        try:
            client = await get_client(pid)
            if client is None or not await client.is_user_authorized():
                continue
            _schedule_payment_chat_archive(
                client,
                owner=owner,
                pid=pid,
                chat_id=case["chat_ref"],
                chat_key=chat_key,
            )
        except Exception as exc:
            print(f"[payment-archive] resume-chat {type(exc).__name__}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _bootstrap_admin()   # гарантируем вход админа (ADMIN_USER/ADMIN_PASS), если заданы
    try:
        store = _get_payment_audit_store()
        if store is not None:
            # Разово сводит карточки, разделённые старым правилом «каждый платёж
            # отдельно»: один собеседник должен быть одной карточкой.
            merged = store.merge_duplicate_chat_cases()
            if merged:
                print(f"[payment-audit] склеено дублей карточек: {merged}")
            store.cleanup()
            if PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS > 0:
                _get_payment_chat_archive().cleanup(PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS)
            state.audit_cleanup_at = time.monotonic() + 24 * 60 * 60
    except Exception as exc:
        print(f"[payment-audit] cleanup {type(exc).__name__}")
    # Сначала резервируем профили под докатку, чтобы планировщик не запустил
    # для них ещё одну рассылку в момент старта процесса.
    await _resume_queued_sends()
    state.scheduler_task = asyncio.create_task(_scheduler_loop())
    # Держим сильную ссылку: asyncio loop хранит фоновые task только слабо, и
    # иначе прогрев Telethon может быть уничтожен сборщиком мусора на полпути.
    state.warm_task = asyncio.create_task(_warm_response_listeners())
    yield
    background_tasks = [task for task in (state.scheduler_task, state.warm_task) if task]
    for task in background_tasks:
        task.cancel()
    if background_tasks:
        await asyncio.gather(*background_tasks, return_exceptions=True)
    state.scheduler_task = None
    state.warm_task = None
    # Даём _send_bulk обработать CancelledError и сохранить недоотправленный
    # хвост в queue.json для докатки после перезапуска.
    send_tasks = list(state.send_tasks.values())
    for task in send_tasks:
        task.cancel()
    if send_tasks:
        await asyncio.gather(*send_tasks, return_exceptions=True)
    audit_tasks = list(state.audit_tasks)
    for task in audit_tasks:
        task.cancel()
    if audit_tasks:
        await asyncio.gather(*audit_tasks, return_exceptions=True)
    try:
        await receipt_ocr.aclose()
    except Exception:
        pass
    state.audit_tasks.clear()
    state.audit_ocr_tasks.clear()
    state.audit_archive_tasks.clear()
    state.audit_ocr_recent.clear()
    state.audit_ocr_dropped = {"queue": 0, "quota": 0, "invalid": 0}
    state.audit_deleted_owners.clear()
    state.audit_deleted_profiles.clear()
    state.audit_owner_locks.clear()
    state.audit_ocr_semaphore = None
    state.audit_archive_semaphore = None
    state.audit_archive_media_semaphore = None
    state.audit_archive_next_at = 0.0
    state.audit_cleanup_at = 0.0
    state.audit_archive_resume_at = 0.0
    for client in state.clients.values():
        try:
            await client.disconnect()
        except Exception:
            pass


app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------------------------
# Регистрация / вход / выход
# ---------------------------------------------------------------------------
class RegisterIn(BaseModel):
    username: str
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


def _claim_orphan_data(uid):
    """Привязывает профили/расписания без владельца к первому админу."""
    profiles = load_profiles()
    changed = False
    for p in profiles:
        if not p.get("owner"):
            p["owner"] = uid
            changed = True
    if changed:
        save_profiles(profiles)
    schedules = load_schedules()
    changed = False
    for s in schedules:
        if not s.get("owner"):
            s["owner"] = uid
            changed = True
    if changed:
        save_schedules(schedules)


@app.post("/api/auth/register")
async def register(body: RegisterIn):
    username = body.username.strip()
    password = body.password
    if len(username) < 3:
        return JSONResponse({"error": "Логин — минимум 3 символа"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"error": "Пароль — минимум 6 символов"}, status_code=400)
    if get_user_by_name(username):
        return JSONResponse({"error": "Такой логин уже занят"}, status_code=400)

    users = load_users()
    is_first = len(users) == 0
    salt, pw_hash = _hash_pw(password)
    uid = uuid.uuid4().hex[:8]
    user = {
        "id": uid,
        "username": username,
        "salt": salt,
        "pw_hash": pw_hash,
        "status": "approved" if is_first else "pending",
        "is_admin": is_first,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    users.append(user)
    save_users(users)

    if is_first:
        # Первый пользователь — админ. Забираем старые профили без владельца.
        _claim_orphan_data(uid)
        resp = JSONResponse({"step": "ready", "user": _user_public(user)})
        _set_session_cookie(resp, uid)
        return resp

    return JSONResponse({"step": "pending"})


@app.post("/api/auth/login")
async def login(body: LoginIn):
    user = get_user_by_name(body.username)
    if not user or not _verify_pw(body.password, user["salt"], user["pw_hash"]):
        return JSONResponse({"error": "Неверный логин или пароль"}, status_code=400)
    if user.get("status") == "pending":
        return JSONResponse({"error": "Аккаунт ждёт одобрения администратором"}, status_code=403)
    if user.get("status") == "blocked":
        return JSONResponse({"error": "Аккаунт заблокирован"}, status_code=403)
    resp = JSONResponse({"step": "ready", "user": _user_public(user)})
    _set_session_cookie(resp, user["id"])
    return resp


@app.post("/api/auth/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session", path="/")
    return resp


# ---------------------------------------------------------------------------
# Сброс пароля (самообслуживание с одобрением администратора)
# ---------------------------------------------------------------------------
class ResetReqIn(BaseModel):
    username: str


class ResetDoneIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/reset/request")
async def reset_request(body: ResetReqIn):
    """Пользователь просит сброс пароля. Ждёт одобрения админа."""
    username = (body.username or "").strip()
    if not username:
        return JSONResponse({"error": "Введи логин"}, status_code=400)
    users = load_users()
    for u in users:
        if u["username"].lower() == username.lower():
            # если уже одобрено — не сбрасываем обратно в pending
            if u.get("reset_status") != "approved":
                u["reset_status"] = "pending"
            u["reset_requested"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            save_users(users)
            break
    # не раскрываем, существует ли такой логин
    return {"ok": True}


@app.post("/api/auth/reset/complete")
async def reset_complete(body: ResetDoneIn):
    """Пользователь задаёт новый пароль — только если админ одобрил сброс."""
    username = (body.username or "").strip()
    password = body.password or ""
    if len(password) < 6:
        return JSONResponse({"error": "Пароль — минимум 6 символов"}, status_code=400)
    users = load_users()
    user = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not user or user.get("reset_status") != "approved":
        return JSONResponse(
            {"error": "Сброс ещё не одобрен. Сначала нажми «Запросить сброс» и дождись одобрения администратором."},
            status_code=403,
        )
    salt, pw_hash = _hash_pw(password)
    user["salt"] = salt
    user["pw_hash"] = pw_hash
    user.pop("reset_status", None)
    user.pop("reset_requested", None)
    save_users(users)
    if user.get("status") == "blocked":
        return JSONResponse({"error": "Пароль обновлён, но аккаунт заблокирован администратором."}, status_code=403)
    if user.get("status") == "pending":
        return JSONResponse({"step": "pending"})
    resp = JSONResponse({"step": "ready", "user": _user_public(user)})
    _set_session_cookie(resp, user["id"])
    return resp


@app.get("/api/auth/me")
async def auth_me(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    return {"user": _user_public(u)}


class SetupCredsIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/setup_credentials")
async def setup_credentials(body: SetupCredsIn, user=Depends(require_user)):
    """Одноразовая настройка своих логина/пароля (после входа по дефолтному admin/admin).

    Помечает аккаунт как admin_customized — после этого дефолтный вход из
    docker-compose (admin/admin) больше не действует.
    """
    username = (body.username or "").strip()
    password = body.password or ""
    if len(username) < 3:
        return JSONResponse({"error": "Логин — минимум 3 символа"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"error": "Пароль — минимум 6 символов"}, status_code=400)
    existing = get_user_by_name(username)
    if existing and existing["id"] != user["id"]:
        return JSONResponse({"error": "Такой логин уже занят"}, status_code=400)
    users = load_users()
    target = next((u for u in users if u["id"] == user["id"]), None)
    if not target:
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)
    salt, pw_hash = _hash_pw(password)
    target["username"] = username
    target["salt"] = salt
    target["pw_hash"] = pw_hash
    target["admin_customized"] = True   # дефолтный admin/admin больше не применяется
    target["admin_token"] = _admin_reset_token()   # закрепляем текущий токен сброса
    target.pop("must_setup", None)
    save_users(users)
    resp = JSONResponse({"step": "ready", "user": _user_public(target)})
    _set_session_cookie(resp, target["id"])   # uid не меняется, но обновим срок куки
    return resp


# ---------------------------------------------------------------------------
# Админка: управление пользователями
# ---------------------------------------------------------------------------
class UserStatusIn(BaseModel):
    status: str  # "approved" | "blocked"


@app.get("/api/admin/users")
async def admin_list_users(admin=Depends(require_admin)):
    return {"users": [_user_public(u) for u in load_users()]}


@app.post("/api/admin/users/{uid}/status")
async def admin_set_status(uid: str, body: UserStatusIn, admin=Depends(require_admin)):
    if body.status not in ("approved", "blocked"):
        return JSONResponse({"error": "Неверный статус"}, status_code=400)
    if uid == admin["id"]:
        return JSONResponse({"error": "Нельзя менять статус самому себе"}, status_code=400)
    async with _audit_owner_lock(uid):
        users = load_users()
        target = next((u for u in users if u["id"] == uid), None)
        if not target:
            return JSONResponse({"error": "Пользователь не найден"}, status_code=404)
        target["status"] = body.status
        save_users(users)
    return {"ok": True, "user": _user_public(target)}


@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: str, admin=Depends(require_admin)):
    if uid == admin["id"]:
        return JSONResponse({"error": "Нельзя удалить самого себя"}, status_code=400)
    users = load_users()
    if not any(u["id"] == uid for u in users):
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)

    owner_profiles = [p for p in load_profiles() if p.get("owner") == uid]
    store = await _get_payment_audit_store_async()
    if store is None and os.path.exists(PAYMENT_AUDIT_DB):
        return JSONResponse({"error": "Не удалось безопасно удалить данные проверки оплат"}, status_code=503)
    state.audit_deleted_owners.add(str(uid))
    state.audit_deleted_profiles.update(str(p["id"]) for p in owner_profiles)
    _cancel_audit_ocr_for_profiles(p["id"] for p in owner_profiles)
    await _cancel_payment_archive_tasks(owner=uid)
    try:
        async with _audit_owner_lock(uid):
            archive = await _get_payment_chat_archive_async()
            chat_keys = await _cancel_safe_to_thread(store.owner_chat_keys, uid) if store is not None else []
            for chat_key in chat_keys:
                await _cancel_safe_to_thread(
                    archive.purge, uid, "detached", chat_key, tombstone=False
                )
            await _cancel_safe_to_thread(archive.purge_owner, uid)
            if store is not None:
                await _cancel_safe_to_thread(store.delete_owner, uid)
    except Exception as exc:
        state.audit_deleted_owners.discard(str(uid))
        state.audit_deleted_profiles.difference_update(str(p["id"]) for p in owner_profiles)
        print(f"[payment-audit] delete owner {type(exc).__name__}")
        return JSONResponse({"error": "Не удалось безопасно удалить данные проверки оплат"}, status_code=503)

    # Удаляем профили пользователя (вместе с сессиями Telegram) и его расписания.
    for p in owner_profiles:
        await _destroy_profile(p)
    save_profiles([p for p in load_profiles() if p.get("owner") != uid])
    save_schedules([s for s in load_schedules() if s.get("owner") != uid])
    save_packs([p for p in load_packs() if p.get("owner") != uid])
    save_users([u for u in users if u["id"] != uid])
    return {"ok": True}


class ResetActionIn(BaseModel):
    action: str  # "approve" | "reject"


@app.post("/api/admin/users/{uid}/reset")
async def admin_reset(uid: str, body: ResetActionIn, admin=Depends(require_admin)):
    """Админ одобряет ('approve') или отклоняет ('reject') запрос на сброс пароля."""
    users = load_users()
    target = next((u for u in users if u["id"] == uid), None)
    if not target:
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)
    if body.action == "approve":
        target["reset_status"] = "approved"
    elif body.action == "reject":
        target.pop("reset_status", None)
        target.pop("reset_requested", None)
    else:
        return JSONResponse({"error": "Неверное действие"}, status_code=400)
    save_users(users)
    return {"ok": True, "user": _user_public(target)}


class SubIn(BaseModel):
    add_days: int | None = None


@app.post("/api/admin/users/{uid}/subscription")
async def admin_subscription(uid: str, body: SubIn, admin=Depends(require_admin)):
    """Админ вручную продлевает доступ на N дней (+7 / +30). Оплата — вне сайта."""
    target = get_user(uid)
    if not target:
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)
    if body.add_days:
        _extend_subscription(uid, int(body.add_days))
    current = get_user(uid)
    if _payment_audit_applies(current) and _sub_active(current):
        _track_audit_task(_warm_payment_owner_profiles(uid))
    return {"ok": True, "user": _user_public(current)}


def _activity_verdict(s):
    """Светофор «пошло / не пошло» по данным недели.
    good — доходит и людям пишут в ответ; mid — рассылает, но отклика мало;
    bad — спам-флаг или почти не доходит; idle — простаивает/не подключён."""
    attempts = s["msgs_7d"] + s["fails_7d"]
    rate = (s["msgs_7d"] / attempts) if attempts else 0.0
    pct = round(rate * 100)
    resp = s["responses_7d"]
    if s["spam_flag"]:
        return {"level": "bad", "reason": "аккаунт под спам-флагом/паузой Telegram"}
    if not s["accounts"]:
        return {"level": "idle", "reason": "аккаунтов нет"}
    if s["runs_7d"] == 0:
        return {"level": "idle", "reason": "простаивает — рассылок за 7 дней нет"}
    if attempts and rate < 0.5:
        return {"level": "bad", "reason": f"рассылки почти не доходят ({pct}% дошло)"}
    if resp > 0 and rate >= 0.7:
        return {"level": "good", "reason": f"доходит ({pct}%), пишут в ответ: {resp} за 7 дн"}
    if resp > 0:
        return {"level": "mid", "reason": f"есть ответы ({resp}), но доставка средняя ({pct}%)"}
    return {"level": "mid", "reason": f"рассылает ({pct}% доходит), но в ответ пока не пишут"}


@app.get("/api/admin/stats")
async def admin_stats(admin=Depends(require_admin)):
    """Статистика активности по каждому пользователю (включая самого админа):
    аккаунты, расписания, рассылки за 7 дней и отклик (входящие в личку) —
    видно, кто реально работает, у кого «пошло», а кто простаивает или лишкует."""
    now = datetime.now()
    week_ago = now - timedelta(days=7)
    today = now.strftime("%Y-%m-%d")

    out = {}
    for u in load_users():
        out[u["id"]] = {
            "id": u["id"],
            "accounts": [], "_pids": [], "spam_flag": False,
            "schedules_on": 0, "schedules_total": 0, "sched_max_targets": 0,
            "runs_7d": 0, "msgs_7d": 0, "fails_7d": 0, "max_run_7d": 0,
            "msgs_today": 0, "last_run": None, "recent": [],
            "responses_7d": 0, "responses_today": 0,
        }

    for p in load_profiles():
        s = out.get(p.get("owner"))
        if s is None:
            continue
        s["_pids"].append(p["id"])
        if p.get("flagged"):
            s["spam_flag"] = True
        s["accounts"].append({
            "name": p.get("name") or p["id"],
            "active": bool(p.get("active")),
            "paused": bool(p.get("flagged")) or _on_cooldown(p),
            "warmup": bool(p.get("warmup")),
        })

    for r in load_schedules():
        s = out.get(r.get("owner"))
        if s is None:
            continue
        s["schedules_total"] += 1
        if r.get("enabled", True):
            s["schedules_on"] += 1
        s["sched_max_targets"] = max(s["sched_max_targets"], len(r.get("targets") or []))

    for rec in load_sends():   # история newest-first
        s = out.get(rec.get("owner"))
        if s is None:
            continue
        started = rec.get("started") or ""
        try:
            dt = datetime.fromisoformat(started)
        except Exception:
            continue
        if s["last_run"] is None:
            s["last_run"] = started
        if len(s["recent"]) < 3:
            s["recent"].append({
                "started": started,
                "source": rec.get("source") or "",
                "label": rec.get("label") or "",
                "total": int(rec.get("total") or 0),
                "ok": int(rec.get("ok") or 0),
                "status": rec.get("status") or "",
                "text_preview": rec.get("text_preview") or "",
            })
        if dt < week_ago:
            continue
        s["runs_7d"] += 1
        s["msgs_7d"] += int(rec.get("ok") or 0)
        s["fails_7d"] += len(rec.get("failed") or [])
        s["max_run_7d"] = max(s["max_run_7d"], int(rec.get("total") or 0))
        if started[:10] == today:
            s["msgs_today"] += int(rec.get("ok") or 0)

    # отклик: входящие в личку на все аккаунты пользователя
    for s in out.values():
        for pid in s["_pids"]:
            s["responses_7d"] += _responses_window(pid, 7)
            s["responses_today"] += _responses_window(pid, 1)
        s["verdict"] = _activity_verdict(s)
        s.pop("_pids", None)

    return {"stats": list(out.values())}


# ---------------------------------------------------------------------------
# Доступ (подписка). Оплата — вне сайта; продлевает только админ вручную.
# ---------------------------------------------------------------------------
@app.get("/api/billing/info")
async def billing_info(user=Depends(require_user)):
    return {
        "active": _sub_active(user),
        "paid_until": user.get("paid_until"),
        "days_left": _days_left(user),
    }


# ---------------------------------------------------------------------------
# Модели запросов
# ---------------------------------------------------------------------------
class CreateProfileIn(BaseModel):
    name: str
    api_id: str
    api_hash: str
    proxy: str = ""
    warmup: bool = False


class ProxyIn(BaseModel):
    proxy: str = ""


class WarmupIn(BaseModel):
    warmup: bool


class LimitIn(BaseModel):
    daily_limit: int = 0   # макс. отправок в сутки (0 = без лимита)


class PhoneIn(BaseModel):
    phone: str


class CodeIn(BaseModel):
    code: str


class PasswordIn(BaseModel):
    password: str


class Target(BaseModel):
    id: int
    name: str
    kind: str = "chat"


class SendIn(BaseModel):
    targets: list[Target]
    text: str
    gap_min: int | None = None   # пауза между чатами, сек (от)
    gap_max: int | None = None   # пауза между чатами, сек (до)


class ScheduleIn(BaseModel):
    targets: list[Target]
    text: str
    time: str = "12:00"       # "HH:MM" (для режима «по времени»)
    weekdays: list[int] = []  # 0=Пн ... 6=Вс
    dates: list[str] = []     # ["YYYY-MM-DD", ...]
    interval_min: int | None = None  # минуты; если задано — режим «каждые N минут»
    interval_max: int | None = None  # верхняя граница случайного интервала
    gap_min: int | None = None       # пауза между чатами, сек (от)
    gap_max: int | None = None       # пауза между чатами, сек (до)


class PackIn(BaseModel):
    name: str
    targets: list[Target]


class JoinIn(BaseModel):
    links: str


class FolderIn(BaseModel):
    name: str = "Каналы"


class PaymentCaseResponseIn(BaseModel):
    status: str
    note: str = ""


class PaymentCaseReviewIn(BaseModel):
    status: str
    amount: float | None = None
    note: str = ""


class PaymentWeekIn(BaseModel):
    amount: float
    note: str = ""


# ---------------------------------------------------------------------------
# Проверка оплат в рабочих Telegram-диалогах
# ---------------------------------------------------------------------------
def _current_week_start():
    today = datetime.now().date()
    return (today - timedelta(days=today.weekday())).isoformat()


def _current_week_bounds():
    start = datetime.fromisoformat(_current_week_start()).date()
    return start.isoformat(), (start + timedelta(days=7)).isoformat()


def _audit_case_view(case, *, profiles=None, users=None):
    row = dict(case)
    profiles = profiles if profiles is not None else load_profiles()
    profile = next((p for p in profiles if p.get("id") == row.get("profile_id")), None)
    row["profile_name"] = (profile or {}).get("name") or row.get("profile_id")
    chat_ref = row.get("chat_ref")
    row["chat_link"] = f"tg://user?id={chat_ref}" if isinstance(chat_ref, int) and chat_ref > 0 else ""
    if users is not None:
        owner = next((u for u in users if u.get("id") == row.get("owner")), None)
        row["username"] = (owner or {}).get("username") or row.get("owner")
    return row


def _payment_archive_scope(case, archive=None):
    archive = archive or _get_payment_chat_archive()
    owner = str(case.get("owner") or "")
    chat_key = str(case.get("chat_key") or "")
    profile_id = str(case.get("profile_id") or "")
    if owner and profile_id and chat_key:
        return profile_id, archive.load(owner, profile_id, chat_key)
    found = archive.find_chat(owner, chat_key)
    return found if found is not None else ("", None)


def _payment_archive_summary(case, archive=None):
    archive = archive or _get_payment_chat_archive()
    owner = str(case.get("owner") or "")
    chat_key = str(case.get("chat_key") or "")
    profile_id = str(case.get("profile_id") or "")
    if owner and profile_id and chat_key:
        return archive.summary(owner, profile_id, chat_key)
    try:
        found = archive.find_chat(owner, chat_key)
    except PaymentChatArchiveError:
        return {
            "status": "error", "message_count": 0, "media_count": 0,
            "captured_at": "", "truncated": False,
            "last_error": "archive_corrupt", "size_bytes": 0,
        }
    if found is None:
        return archive.summary(owner, "missing-profile", chat_key) if owner and chat_key else {
            "status": "missing", "message_count": 0, "media_count": 0,
            "captured_at": "", "truncated": False, "last_error": "", "size_bytes": 0,
        }
    archived_profile_id, _manifest = found
    return archive.summary(owner, archived_profile_id, chat_key)


def _admin_payment_case_views(cases, profiles, users):
    archive = _get_payment_chat_archive()
    rows = []
    summaries = {}
    for case in cases:
        view = _audit_case_view(case, profiles=profiles, users=users)
        key = (
            str(case.get("owner") or ""),
            str(case.get("profile_id") or ""),
            str(case.get("chat_key") or ""),
        )
        if key not in summaries:
            summaries[key] = _payment_archive_summary(case, archive)
        view["archive"] = dict(summaries[key])
        rows.append(view)
    return rows


async def _warm_payment_owner_profiles(owner):
    if str(owner) in state.audit_deleted_owners:
        return
    for profile in [p for p in load_profiles() if p.get("owner") == owner]:
        if _payment_audit_scope_blocked(owner, profile["id"]):
            continue
        try:
            client = await get_client(profile["id"])
            if client:
                await client.catch_up()
        except Exception as exc:
            print(f"[payment-audit] warm {profile['id']} {type(exc).__name__}")
        await asyncio.sleep(1)


@app.get("/api/payment-audit")
async def payment_audit_info(response: Response, user=Depends(require_user)):
    response.headers["Cache-Control"] = "private, no-store"
    week, next_week = _current_week_bounds()
    store = await _get_payment_audit_store_async()
    if store is None:
        return {
            "version": PAYMENT_AUDIT_VERSION,
            "available": False,
            "retention_days": PAYMENT_AUDIT_RETENTION_DAYS,
            "commission_rate": PAYMENT_COMMISSION_RATE,
            "ocr_available": False,
            "week_start": week,
            "week_report": None,
            "week_reports": [],
            "summary": {},
        }
    report = await asyncio.to_thread(store.weekly_report, user["id"], week)
    week_reports = await asyncio.to_thread(store.recent_weekly_reports, user["id"], 4)
    summary = await asyncio.to_thread(
        store.weekly_summary,
        user["id"], week, next_week,
        commission_rate=PAYMENT_COMMISSION_RATE,
    )
    ocr_available = await _payment_ocr_available()
    return {
        "version": PAYMENT_AUDIT_VERSION,
        "available": True,
        "retention_days": PAYMENT_AUDIT_RETENTION_DAYS,
        "commission_rate": PAYMENT_COMMISSION_RATE,
        "ocr_available": ocr_available,
        "week_start": week,
        "week_report": report,
        "week_reports": week_reports,
        "summary": summary,
    }


@app.get("/api/payment-audit/cases")
async def payment_audit_cases(response: Response, days: int = 7, limit: int = 100,
                              user=Depends(require_user)):
    response.headers["Cache-Control"] = "private, no-store"
    profiles = load_profiles()
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse(
            {"error": "Проверка оплат временно недоступна"},
            status_code=503,
            headers={"Cache-Control": "private, no-store"},
        )
    cases = await asyncio.to_thread(
        store.list_cases,
        owner=user["id"], days=max(1, min(int(days), 90)), limit=max(1, min(int(limit), 200))
    )
    return {"cases": [_audit_case_view(c, profiles=profiles) for c in cases]}


@app.post("/api/payment-audit/cases/{case_id}/respond")
async def payment_audit_respond(case_id: str, body: PaymentCaseResponseIn,
                                user=Depends(require_user)):
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    try:
        case = await asyncio.to_thread(
            store.respond, case_id, user["id"], body.status, body.note
        )
    except ValueError:
        return JSONResponse({"error": "Неверный ответ"}, status_code=400)
    except KeyError:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    return {"ok": True, "case": _audit_case_view(case)}


@app.post("/api/payment-audit/week")
async def payment_audit_week(body: PaymentWeekIn, user=Depends(require_user)):
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    try:
        report = await asyncio.to_thread(
            store.submit_week,
            user["id"], _current_week_start(), body.amount, body.note
        )
    except (TypeError, ValueError):
        return JSONResponse({"error": "Неверная сумма"}, status_code=400)
    return {"ok": True, "report": report, "commission": round(report["amount"] * PAYMENT_COMMISSION_RATE, 2)}


@app.get("/api/admin/payment-audit")
async def admin_payment_audit(response: Response, days: int = 7,
                              limit: int = 300, offset: int = 0,
                              admin=Depends(require_admin)):
    response.headers["Cache-Control"] = "private, no-store"
    days = max(1, min(int(days), 36_500))
    users = load_users()
    profiles = load_profiles()
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse(
            {"error": "Проверка оплат временно недоступна"},
            status_code=503,
            headers={"Cache-Control": "private, no-store"},
        )
    limit = max(50, min(int(limit), 500))
    offset = max(0, min(int(offset), 10_000_000))
    cases_page = await asyncio.to_thread(
        store.list_cases, days=days, limit=limit + 1, offset=offset
    )
    has_more = len(cases_page) > limit
    cases = cases_page[:limit]
    summaries = []
    week, next_week = _current_week_bounds()
    for owner in users:
        summary = await asyncio.to_thread(
            store.weekly_summary,
            owner["id"], week, next_week,
            commission_rate=PAYMENT_COMMISSION_RATE,
        )
        week_report = await asyncio.to_thread(store.weekly_report, owner["id"], week)
        week_reports = await asyncio.to_thread(store.recent_weekly_reports, owner["id"], 4)
        summary.update({
            "owner": owner["id"],
            "username": owner.get("username") or owner["id"],
            "week_report": week_report,
            "week_reports": week_reports,
        })
        summaries.append(summary)
    case_views = await asyncio.to_thread(
        _admin_payment_case_views, cases, profiles, users
    )
    return {
        "days": days,
        "week_start": week,
        "commission_rate": PAYMENT_COMMISSION_RATE,
        "archive_retention_days": PAYMENT_CHAT_ARCHIVE_RETENTION_DAYS,
        "summaries": summaries,
        "cases": case_views,
        "offset": offset,
        "next_offset": offset + len(cases),
        "has_more": has_more,
        "ocr_queue": {
            "active": len(_active_ocr_meta()),
            "dropped": dict(state.audit_ocr_dropped),
        },
    }


@app.post("/api/admin/payment-audit/cases/{case_id}/review")
async def admin_payment_audit_review(case_id: str, body: PaymentCaseReviewIn,
                                     admin=Depends(require_admin)):
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    amount = body.amount
    if body.status == "confirmed" and amount is None:
        return JSONResponse({"error": "Укажи подтверждённую сумму вручную"}, status_code=400)
    try:
        case = await asyncio.to_thread(
            store.review, case_id, admin["id"], body.status, amount, body.note
        )
    except ValueError:
        return JSONResponse({"error": "Неверное решение или сумма"}, status_code=400)
    except KeyError:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    if body.status == "needs_info":
        note = (body.note or "").strip() or "нужно пояснение по этому сигналу"
        _add_notification(
            case.get("owner"),
            case.get("profile_id") or "",
            "warn",
            f"❓ Админ просит пояснение по оплате ({_payment_amounts_label(case)}): {note}"[:500],
        )
    return {"ok": True, "case": _audit_case_view(case, users=load_users())}


def _peek_image_mime(raw: bytes) -> str:
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return "image/jpeg"


@app.post("/api/admin/payment-audit/cases/{case_id}/restore")
async def admin_payment_audit_restore(case_id: str, admin=Depends(require_admin)):
    """Достаёт карточку из корзины обратно в очередь на проверку."""
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    try:
        case = await asyncio.to_thread(store.restore, case_id, admin["id"])
    except KeyError:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    return {"ok": True, "case": _audit_case_view(case, users=load_users())}


@app.post("/api/admin/payment-audit/cases/{case_id}/archive")
async def admin_payment_archive_refresh(case_id: str, admin=Depends(require_admin)):
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    case = await asyncio.to_thread(store.get_case, case_id)
    if not case:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    pid = case.get("profile_id")
    chat_ref = case.get("chat_ref")
    if not pid or not case.get("profile_active", True) or not isinstance(chat_ref, int):
        return JSONResponse(
            {"error": "Рабочий аккаунт отключён; сохранённый архив можно только читать"},
            status_code=409,
        )
    if not _payment_audit_scope_active(case.get("owner"), pid):
        return JSONResponse(
            {"error": "Доступ сотрудника сейчас неактивен; сохранённый архив можно читать"},
            status_code=409,
        )
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Аккаунт сотрудника сейчас офлайн"}, status_code=503)
    archive = await _get_payment_chat_archive_async()
    await _payment_archive_write(
        archive, case["owner"], pid, archive.mark_status,
        case["owner"], pid, case["chat_key"], "pending",
        truncated=False, reset_truncated=True, reopen_purged=True,
    )
    _schedule_payment_chat_archive(
        client,
        owner=case["owner"],
        pid=pid,
        chat_id=chat_ref,
        chat_key=case["chat_key"],
    )
    return JSONResponse(
        {
            "ok": True,
            "archive": await asyncio.to_thread(
                archive.summary, case["owner"], pid, case["chat_key"]
            ),
        },
        status_code=202,
        headers={"Cache-Control": "private, no-store"},
    )


@app.delete("/api/admin/payment-audit/cases/{case_id}/archive")
async def admin_payment_archive_compact(case_id: str, admin=Depends(require_admin)):
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    case = await asyncio.to_thread(store.get_case, case_id)
    if not case:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    owner = str(case.get("owner") or "")
    chat_key = str(case.get("chat_key") or "")
    archive = await _get_payment_chat_archive_async()
    await _cancel_payment_archive_tasks(owner=owner, chat_key=chat_key)
    async with _audit_owner_lock(owner):
        kept = await asyncio.to_thread(
            store.compact_chat, owner, chat_key, admin["id"]
        )
        summary = await _cancel_safe_to_thread(
            archive.purge,
            owner,
            str(case.get("profile_id") or "detached"),
            chat_key,
            tombstone=True,
        )
    return JSONResponse(
        {"ok": True, "archive": summary, "payment_facts_kept": kept},
        headers={"Cache-Control": "private, no-store"},
    )


@app.get("/api/admin/payment-audit/cases/{case_id}/archive/media/{file_id}")
async def admin_payment_archive_media(case_id: str, file_id: str, admin=Depends(require_admin)):
    store = await _get_payment_audit_store_async()
    if store is None:
        raise HTTPException(status_code=503, detail="Проверка оплат недоступна")
    case = await asyncio.to_thread(store.get_case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Событие не найдено")
    archive = await _get_payment_chat_archive_async()
    profile_id, manifest = await asyncio.to_thread(_payment_archive_scope, case, archive)
    if not profile_id or manifest is None:
        raise HTTPException(status_code=404, detail="Вложение не найдено")
    try:
        raw, mime = await asyncio.to_thread(
            archive.read_media,
            case["owner"],
            profile_id,
            case["chat_key"],
            file_id,
        )
    except (KeyError, PaymentChatArchiveError):
        raise HTTPException(status_code=404, detail="Вложение не найдено")
    return Response(
        content=raw,
        media_type=mime,
        headers={
            "Cache-Control": "private, no-store",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


async def _peek_collect_messages(client, entity, *, pid, chat_ref, target_refs, limit=80):
    """Fetch a quiet history window and prefer the case trigger message."""
    collected = []
    offset_id = 0
    matched = None
    for _ in range(4):
        batch = await client.get_messages(entity, limit=min(40, limit), offset_id=offset_id)
        batch = list(batch or [])
        if not batch:
            break
        collected.extend(batch)
        for msg in batch:
            mid = int(getattr(msg, "id", 0) or 0)
            if mid and PaymentAuditStore.message_ref(pid, chat_ref, mid) in target_refs:
                matched = msg
        if matched or len(collected) >= limit:
            break
        offset_id = int(getattr(batch[-1], "id", 0) or 0)
        if offset_id <= 0:
            break
    # Keep chronological uniqueness.
    by_id = {}
    for msg in collected:
        mid = int(getattr(msg, "id", 0) or 0)
        if mid:
            by_id[mid] = msg
    ordered = [by_id[k] for k in sorted(by_id)]
    if matched is not None:
        mid = int(matched.id)
        # Window around the trigger: older + newer neighbors already fetched.
        idx = next((i for i, m in enumerate(ordered) if int(m.id) == mid), None)
        if idx is not None:
            ordered = ordered[max(0, idx - 20): idx + 21]
    else:
        ordered = ordered[-40:]
    return ordered, matched


def _payment_origin(case, *, trigger_found=False, trigger_message_id=None):
    evidence_bits = []
    for item in case.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        snippet = str(item.get("snippet") or "").strip()
        if snippet:
            evidence_bits.append(f"{item.get('source') or 'message'}: «{snippet}»")
    return {
        "summary": (
            f"Сумма {_payment_amounts_label(case)} взята из сохранённого сигнала/чека."
            if any(a.get("value") for a in (case.get("amounts") or []))
            else "Сумма не распознана — проверь сохранённую переписку и вложения."
        ),
        "detector": evidence_bits[-6:],
        "trigger_found": bool(trigger_found),
        "trigger_message_id": trigger_message_id,
    }


def _archived_payment_peek(store, case, case_id):
    archive = _get_payment_chat_archive()
    profile_id, manifest = _payment_archive_scope(case, archive)
    if manifest is None:
        return None
    owner = str(case.get("owner") or "")
    chat_key = str(case.get("chat_key") or "")
    summary = archive.summary(owner, profile_id, chat_key)
    target_refs = store.chat_message_refs(owner, chat_key)
    chat_ref = case.get("chat_ref")
    rows = []
    trigger_id = None
    trigger_by_id = {}
    for item in manifest.get("messages") or []:
        message_id = int(item.get("id") or 0)
        is_trigger = bool(
            message_id
            and isinstance(chat_ref, int)
            and chat_ref > 0
            and PaymentAuditStore.message_ref(profile_id, chat_ref, message_id) in target_refs
        )
        if is_trigger and trigger_id is None:
            trigger_id = message_id
        trigger_by_id[message_id] = is_trigger
        revisions = [
            {
                "text": str(revision.get("text") or ""),
                "captured_at": str(revision.get("captured_at") or ""),
                "original": False,
            }
            for revision in (item.get("revisions") or [])[-3:]
            if isinstance(revision, dict) and revision.get("text")
        ]
        original_text = str(item.get("original_text") or "")
        if (
            original_text
            and original_text != str(item.get("text") or "")
            and not any(revision["text"] == original_text for revision in revisions)
        ):
            revisions.insert(0, {
                "text": original_text,
                "captured_at": str(item.get("original_captured_at") or ""),
                "original": True,
            })
        rows.append({
            "id": message_id,
            "direction": "outgoing" if item.get("direction") == "outgoing" else "incoming",
            "text": str(item.get("text") or ""),
            "at": str(item.get("at") or ""),
            "has_media": bool(item.get("has_media")),
            "is_trigger": is_trigger,
            "edited": bool(revisions),
            "revisions": revisions,
        })
    photos = []
    by_message = {row["id"]: row for row in rows}
    media_counts = {}
    for item in manifest.get("media") or []:
        message_id = int(item.get("message_id") or 0)
        media_counts[message_id] = media_counts.get(message_id, 0) + 1
    for item in manifest.get("media") or []:
        message_id = int(item.get("message_id") or 0)
        photos.append({
            "message_id": message_id,
            "direction": (by_message.get(message_id) or {}).get("direction", "incoming"),
            "mime": str(item.get("mime") or "image/jpeg"),
            "is_trigger": bool(trigger_by_id.get(message_id)),
            "matches_case_amount": False,
            "ocr_text": "",
            "ocr_amounts": [],
            "versioned": media_counts.get(message_id, 0) > 1,
            "captured_at": str(item.get("captured_at") or ""),
            "url": f"/api/admin/payment-audit/cases/{case_id}/archive/media/{item.get('file_id')}",
        })
    related = store.list_chat_cases(owner, chat_key)
    profiles = load_profiles()
    users = load_users()
    related_views = [_audit_case_view(row, profiles=profiles, users=users) for row in related]
    view = _audit_case_view(case, profiles=profiles, users=users)
    view["archive"] = summary
    return {
        "ok": True,
        "quiet": True,
        "archived": True,
        "archive": summary,
        "case": view,
        "related_cases": related_views,
        "peer": {"name": case.get("chat_label") or "сохранённый диалог", "username": ""},
        "origin": _payment_origin(
            case,
            trigger_found=trigger_id is not None,
            trigger_message_id=trigger_id,
        ),
        "messages": rows,
        "photos": photos,
        "hint": "Сохранённая зашифрованная копия. Telegram не открывался.",
    }


@app.get("/api/admin/payment-audit/cases/{case_id}/peek")
async def admin_payment_audit_peek(case_id: str, admin=Depends(require_admin)):
    """Тихий просмотр диалога глазами рабочего аккаунта.

    Только чтение: ничего не отправляем и не помечаем сообщения прочитанными.
    Ссылка «открыть в Telegram» с телефона админа не подходит — диалог живёт
    на чужой сессии сотрудника.
    """
    store = await _get_payment_audit_store_async()
    if store is None:
        return JSONResponse({"error": "Проверка оплат временно недоступна"}, status_code=503)
    case = await asyncio.to_thread(store.get_case, case_id)
    if not case:
        return JSONResponse({"error": "Событие не найдено"}, status_code=404)
    try:
        archived = await asyncio.to_thread(_archived_payment_peek, store, case, case_id)
    except PaymentChatArchiveError:
        archived = None
    if archived is not None:
        return JSONResponse(
            archived,
            headers={"Cache-Control": "private, no-store", "Pragma": "no-cache"},
        )
    pid = case.get("profile_id")
    chat_ref = case.get("chat_ref")
    if not pid or not isinstance(chat_ref, int) or chat_ref <= 0:
        return JSONResponse({"error": "Нет привязки к диалогу"}, status_code=404)
    if not case.get("profile_active", True):
        return JSONResponse({"error": "Профиль сотрудника уже отключён"}, status_code=404)

    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Аккаунт сотрудника сейчас офлайн"}, status_code=503)

    try:
        entity = await client.get_entity(chat_ref)
    except Exception:
        return JSONResponse({"error": "Не удалось открыть диалог на аккаунте сотрудника"}, status_code=404)

    peer = _brief(entity)
    target_refs = await asyncio.to_thread(
        store.chat_message_refs, case.get("owner"), case.get("chat_key")
    )

    try:
        # get_messages сам по себе не шлёт read-ack — клиент/сотрудник ничего не видит.
        messages, matched = await _peek_collect_messages(
            client, entity, pid=pid, chat_ref=chat_ref, target_refs=target_refs, limit=80,
        )
    except Exception as exc:
        return JSONResponse(
            {"error": f"Не удалось прочитать историю: {type(exc).__name__}"},
            status_code=502,
        )

    origin = _payment_origin(
        case,
        trigger_found=matched is not None,
        trigger_message_id=int(matched.id) if matched is not None else None,
    )

    rows = []
    image_msgs = []
    for msg in messages:
        mid = int(getattr(msg, "id", 0) or 0)
        text = (getattr(msg, "raw_text", None) or getattr(msg, "message", None) or "").strip()
        has_media = getattr(msg, "media", None) is not None
        is_image = bool(
            getattr(msg, "photo", None) is not None
            or str(getattr(getattr(msg, "file", None), "mime_type", "") or "").startswith("image/")
        )
        if not text and has_media:
            text = "[фото/файл]" if is_image else "[файл]"
        if not text:
            continue
        at = getattr(msg, "date", None)
        is_trigger = bool(
            mid
            and PaymentAuditStore.message_ref(pid, chat_ref, mid) in target_refs
        )
        rows.append({
            "id": mid,
            "direction": "outgoing" if bool(getattr(msg, "out", False)) else "incoming",
            "text": mask_sensitive_text(text, 400),
            "at": at.astimezone(timezone.utc).isoformat(timespec="seconds") if at else "",
            "has_media": bool(has_media),
            "is_trigger": is_trigger,
        })
        if is_image and has_media:
            image_msgs.append((msg, mid, is_trigger))

    # Сначала исходный чек-сигнал, потом остальные скрины рядом.
    image_msgs.sort(key=lambda item: (not item[2], -item[1]))
    case_values = {
        round(float(a.get("value") or 0), 2)
        for a in (case.get("amounts") or [])
        if float(a.get("value") or 0) > 0
    }
    ocr_ready = await _payment_ocr_available()
    photos = []
    for msg, mid, is_trigger in image_msgs[:8]:
        try:
            raw = await client.download_media(msg, file=bytes)
        except Exception:
            raw = None
        if not (isinstance(raw, (bytes, bytearray)) and 32 < len(raw) <= 2_500_000):
            continue
        mime = _peek_image_mime(bytes(raw))
        ocr_text = ""
        ocr_amounts = []
        if ocr_ready and len([p for p in photos if p.get("ocr_text")]) < 5:
            try:
                async with asyncio.timeout(20):
                    result = await receipt_ocr.analyze_bytes_async(bytes(raw))
                signals = getattr(result, "signals", None)
                term_bits = list(getattr(signals, "terms", ()) or [])[:4]
                amount_bits = [
                    str(getattr(a, "raw", "") or getattr(a, "value", ""))
                    for a in (getattr(signals, "amounts", ()) or [])[:4]
                ]
                raw_preview = mask_sensitive_text(str(getattr(result, "text", "") or ""), 180)
                joined = " · ".join(x for x in (term_bits + amount_bits) if x)
                ocr_text = raw_preview or mask_sensitive_text(joined, 240)
                for a in (getattr(signals, "amounts", ()) or [])[:6]:
                    try:
                        value = float(str(getattr(a, "value", "") or "0").replace(",", "."))
                    except (TypeError, ValueError):
                        continue
                    if value > 0:
                        ocr_amounts.append({
                            "value": value,
                            "currency": getattr(a, "currency", None) or "RUB",
                            "raw": str(getattr(a, "raw", "") or value),
                        })
            except Exception:
                pass
        photo_values = {round(float(a["value"]), 2) for a in ocr_amounts}
        photos.append({
            "message_id": mid,
            "direction": "outgoing" if bool(getattr(msg, "out", False)) else "incoming",
            "mime": mime,
            "is_trigger": is_trigger,
            "matches_case_amount": bool(case_values and case_values & photo_values),
            "ocr_text": ocr_text,
            "ocr_amounts": ocr_amounts,
            "data_url": f"data:{mime};base64,{base64.b64encode(bytes(raw)).decode('ascii')}",
        })

    photos.sort(key=lambda p: (not p.get("is_trigger"), not p.get("matches_case_amount"), -p["message_id"]))

    users = load_users()
    profiles = load_profiles()
    view = _audit_case_view(case, profiles=profiles, users=users)
    view["archive"] = await asyncio.to_thread(_payment_archive_summary, case)
    related = await asyncio.to_thread(
        store.list_chat_cases, case.get("owner"), case.get("chat_key")
    )
    payload = {
        "ok": True,
        "quiet": True,
        "archived": False,
        "archive": view["archive"],
        "case": view,
        "related_cases": [
            _audit_case_view(row, profiles=profiles, users=users) for row in related
        ],
        "peer": peer,
        "origin": origin,
        "messages": rows,
        "photos": photos,
        "hint": "Просмотр только для тебя. Сообщения не отмечены прочитанными, ничего не отправлено.",
    }
    return JSONResponse(
        payload,
        headers={"Cache-Control": "private, no-store", "Pragma": "no-cache"},
    )


# ---------------------------------------------------------------------------
# Профили
# ---------------------------------------------------------------------------
async def _profile_status(pid):
    client = await get_client(pid)
    if client is None:
        return "phone"
    try:
        if await client.is_user_authorized():
            return "ready"
    except Exception:
        return "phone"
    return "code" if state.login.get(pid, {}).get("phone_code_hash") else "phone"


def _owned_profile(pid, user):
    """Профиль, принадлежащий пользователю, иначе HTTPException 404."""
    profile = get_profile(pid)
    if profile is None or profile.get("owner") != user["id"]:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    return profile


def _active_pid(owner):
    """id активного профиля владельца — единственного, с которого разрешена рассылка.
    Если флаг ещё никому не назначен (старые данные) — активным молча становится
    первый профиль владельца. None, если профилей нет."""
    profiles = load_profiles()
    mine = [p for p in profiles if p.get("owner") == owner]
    if not mine:
        return None
    act = next((p for p in mine if p.get("active")), None)
    if act is None:
        mine[0]["active"] = True
        save_profiles(profiles)
        act = mine[0]
    return act["id"]


_INACTIVE_MSG = ("Этот аккаунт не активный — рассылать можно только с активного. "
                 "Нажми «☆ сделать активным» на карточке аккаунта.")


async def _destroy_profile(profile):
    """Отзывает сессию Telegram и удаляет файлы сессии профиля."""
    pid = profile["id"]
    client = state.clients.pop(pid, None)
    if client is None:
        try:
            client = TelegramClient(
                _session_path(profile), profile["api_id"], profile["api_hash"],
                proxy=_parse_proxy(profile.get("proxy")),
            )
            await client.connect()
        except Exception:
            client = None
    if client is not None:
        try:
            await client.log_out()       # отзываем сессию на стороне Telegram
        except Exception:
            pass
        try:
            await client.disconnect()
        except Exception:
            pass

    for suffix in (".session", ".session-journal"):
        path = _session_path(profile) + suffix
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    state.login.pop(pid, None)
    state.entities.pop(pid, None)


@app.get("/api/profiles")
async def list_profiles(user=Depends(require_user)):
    active_pid = _active_pid(user["id"])   # заодно назначит активного старым данным
    out = []
    for p in load_profiles():
        if p.get("owner") != user["id"]:
            continue
        try:
            client = await get_client(p["id"])
            authorized = bool(client and await client.is_user_authorized())
        except Exception:
            authorized = False
        out.append({
            "id": p["id"],
            "name": p["name"],
            "active": p["id"] == active_pid,
            "authorized": authorized,
            "cooldown_until": p.get("cooldown_until"),
            "on_cooldown": _on_cooldown(p),
            "flagged": bool(p.get("flagged")),
            "flood_note": p.get("flood_note") or "",
            "has_proxy": bool(p.get("proxy")),
            "warmup": bool(p.get("warmup")),
            "daily_limit": int(p.get("daily_limit") or 0),
            "sent_today": (p.get("sent_today") or {}).get("n", 0)
                if (p.get("sent_today") or {}).get("k") == datetime.now().strftime("%Y-%m-%d") else 0,
        })
    return {"profiles": out}


@app.post("/api/profiles")
async def create_profile(body: CreateProfileIn, user=Depends(require_active)):
    name = body.name.strip() or "Аккаунт"
    api_id = body.api_id.strip()
    api_hash = body.api_hash.strip()
    if not api_id.isdigit():
        return JSONResponse({"error": "api_id должен состоять только из цифр"}, status_code=400)
    if not _valid_hash(api_hash):
        return JSONResponse({"error": "api_hash должен быть ровно 32 hex-символа"}, status_code=400)

    # Лимита на число аккаунтов нет — доступ ко всем возможностям у всех одобренных.

    proxy = body.proxy.strip()
    if proxy and _parse_proxy(proxy) is None:
        return JSONResponse({"error": "Прокси в неверном формате (нужно socks5://user:pass@host:port или host:port:user:pass)"}, status_code=400)

    pid = uuid.uuid4().hex[:8]
    profiles = load_profiles()
    profiles.append({"id": pid, "name": name, "api_id": int(api_id), "api_hash": api_hash, "owner": user["id"], "proxy": proxy, "warmup": bool(body.warmup)})
    save_profiles(profiles)
    state.login[pid] = {"phone": None, "phone_code_hash": None}
    return {"id": pid, "step": "phone"}


@app.get("/api/profiles/{pid}/proxy")
async def get_proxy(pid: str, user=Depends(require_user)):
    profile = _owned_profile(pid, user)
    return {"proxy": profile.get("proxy", "")}


@app.post("/api/profiles/{pid}/proxy")
async def set_proxy(pid: str, body: ProxyIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    proxy = body.proxy.strip()
    if proxy and _parse_proxy(proxy) is None:
        return JSONResponse({"error": "Прокси в неверном формате"}, status_code=400)
    # отключаем текущий клиент — пересоздастся с новым прокси
    client = state.clients.pop(pid, None)
    if client is not None:
        try:
            await client.disconnect()
        except Exception:
            pass
    profiles = load_profiles()
    for p in profiles:
        if p["id"] == pid:
            p["proxy"] = proxy
            break
    save_profiles(profiles)
    return {"ok": True, "proxy": proxy}


@app.post("/api/profiles/{pid}/warmup")
async def set_warmup(pid: str, body: WarmupIn, user=Depends(require_user)):
    """Включает/выключает режим прогрева (безопасные лимиты в час/сутки)."""
    _owned_profile(pid, user)
    profiles = load_profiles()
    for p in profiles:
        if p["id"] == pid:
            p["warmup"] = bool(body.warmup)
            break
    save_profiles(profiles)
    return {"ok": True, "warmup": bool(body.warmup), "limits": WARMUP_LIMITS}


@app.post("/api/profiles/{pid}/limit")
async def set_daily_limit(pid: str, body: LimitIn, user=Depends(require_user)):
    """Дневной лимит отправок вне прогрева (анти-бан на объёме). 0 = без лимита."""
    _owned_profile(pid, user)
    lim = max(0, int(body.daily_limit or 0))
    profiles = load_profiles()
    for p in profiles:
        if p["id"] == pid:
            p["daily_limit"] = lim
            break
    save_profiles(profiles)
    return {"ok": True, "daily_limit": lim}


def _health_verdict(text):
    """Разбор ответа @SpamBot → ok | limited | unknown.
    Сначала «хорошие» фразы: русский добрый ответ «Ваш аккаунт свободен от
    каких-либо ограничений» содержит подстроку «ограничен», и без этого
    порядка здоровый аккаунт получал бы вердикт limited (и паузу 6 ч)."""
    low = (text or "").lower()
    if ("no limits" in low or "free as a bird" in low or "не ограничен" in low
            or "ограничения сняты" in low or "свободен" in low or "нет ограничений" in low):
        return "ok"
    if "limited" in low or "ограничен" in low or "restrict" in low or "banned" in low or "заблокирован" in low:
        return "limited"
    return "unknown"


@app.post("/api/profiles/{pid}/health")
async def check_health(pid: str, user=Depends(require_user)):
    """Проверка здоровья аккаунта через @SpamBot — не в теневом ли бане."""
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    try:
        async with client.conversation("SpamBot", timeout=25) as conv:
            await conv.send_message("/start")
            resp = await conv.get_response()
            text = (resp.text or "").strip()
    except Exception as e:
        return JSONResponse({"error": f"Не удалось спросить @SpamBot: {e}"}, status_code=502)
    verdict = _health_verdict(text)
    # авто-действие: если аккаунт ограничен — сразу на паузу, чтобы не лить в бан
    auto_paused = False
    if verdict == "limited" and not _on_cooldown(get_profile(pid)):
        _set_cooldown(pid, 6 * 3600, note="@SpamBot: аккаунт ограничен Telegram. Отправки на паузе 6 ч.", flagged=True)
        prof = get_profile(pid) or {}
        _add_notification(prof.get("owner"), pid, "error",
                          f"⛔ «{prof.get('name', pid)}»: @SpamBot сообщил об ограничении аккаунта. Рассылки авто-остановлены на 6 ч.")
        auto_paused = True
    return {"verdict": verdict, "text": text[:1000], "auto_paused": auto_paused}


@app.get("/api/notifications")
async def list_notifications(user=Depends(require_user)):
    """Уведомления владельца о ЧП (спам-флаг, флуд, авто-действия)."""
    items = _read_json(NOTIFS_JSON, {"items": []})["items"]
    mine = [n for n in items if n.get("owner") == user["id"]][:30]
    unread = sum(1 for n in mine if not n.get("read"))
    return {"items": mine, "unread": unread}


@app.post("/api/notifications/read")
async def mark_notifications_read(user=Depends(require_user)):
    """Помечает все уведомления пользователя прочитанными (сбрасывает счётчик)."""
    data = _read_json(NOTIFS_JSON, {"items": []})
    changed = False
    for n in data["items"]:
        if n.get("owner") == user["id"] and not n.get("read"):
            n["read"] = True
            changed = True
    if changed:
        _write_json(NOTIFS_JSON, data)
    return {"ok": True}


@app.get("/api/profiles/{pid}/status")
async def profile_status(pid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    step = await _profile_status(pid)
    if step == "ready":
        client = await get_client(pid)
        me = await client.get_me()
        return {"step": "ready", "me": {"id": me.id, "name": me.first_name or "", "username": me.username or ""}}
    return {"step": step}


@app.delete("/api/profiles/{pid}")
async def delete_profile(pid: str, user=Depends(require_user)):
    profile = _owned_profile(pid, user)
    store = await _get_payment_audit_store_async()
    if store is None and os.path.exists(PAYMENT_AUDIT_DB):
        return JSONResponse({"error": "Не удалось безопасно удалить данные проверки оплат"}, status_code=503)
    state.audit_deleted_profiles.add(str(pid))
    _cancel_audit_ocr_for_profiles([pid])
    await _cancel_payment_archive_tasks(profile_ids=[pid])
    try:
        async with _audit_owner_lock(profile.get("owner")):
            if store is not None:
                # Profile/session deletion is not evidence deletion. Detach its
                # identifiers and keep cases until the disclosed retention expiry.
                await asyncio.to_thread(store.archive_profile, pid)
    except Exception as exc:
        state.audit_deleted_profiles.discard(str(pid))
        print(f"[payment-audit] delete profile {type(exc).__name__}")
        return JSONResponse({"error": "Не удалось безопасно удалить данные проверки оплат"}, status_code=503)
    await _destroy_profile(profile)
    save_profiles([p for p in load_profiles() if p["id"] != pid])
    save_schedules([s for s in load_schedules() if s["profile_id"] != pid])
    save_packs([p for p in load_packs() if p["profile_id"] != pid])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Вход в профиль
# ---------------------------------------------------------------------------
@app.post("/api/profiles/{pid}/activate")
async def activate_profile(pid: str, user=Depends(require_user)):
    """Делает профиль активным. Рассылки (и «сейчас», и по расписанию) идут
    только с активного аккаунта; остальные — запас на случай замены."""
    _owned_profile(pid, user)
    profiles = load_profiles()
    for p in profiles:
        if p.get("owner") != user["id"]:
            continue
        p["active"] = (p["id"] == pid)
        if p["id"] != pid:
            # у прежнего активного глушим идущую рассылку (после текущего чата)
            job = state.send_jobs.get(p["id"])
            if job and job.get("running"):
                job["cancel"] = True
    save_profiles(profiles)

    # Интервальные правила нового активного могли «протухнуть», пока он был
    # запасным. Сдвигаем их next_fire вперёд, чтобы активация не выстрелила
    # мгновенным залпом по всем правилам сразу (анти-бан).
    now = datetime.now()
    schedules = load_schedules()
    changed = False
    for r in schedules:
        if r.get("profile_id") != pid or not r.get("interval_min"):
            continue
        try:
            overdue = r.get("next_fire") is None or now >= datetime.fromisoformat(r["next_fire"])
        except Exception:
            overdue = True
        if overdue:
            lo = int(r.get("interval_min") or 1)
            hi = int(r.get("interval_max") or lo)
            if hi < lo:
                hi = lo
            r["next_fire"] = (now + timedelta(minutes=random.randint(lo, hi))).isoformat(timespec="seconds")
            changed = True
    if changed:
        save_schedules(schedules)
    return {"ok": True}


@app.post("/api/profiles/{pid}/login/send_code")
async def send_code(pid: str, body: PhoneIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)
    phone = body.phone.strip()
    try:
        sent = await client.send_code_request(phone)
    except FloodWaitError as e:
        print(f"[send_code] FLOOD WAIT {e.seconds}s для {phone} — слишком частые запросы кода")
        return JSONResponse(
            {"error": f"Слишком много запросов кода. Подожди {e.seconds} сек и попробуй снова."},
            status_code=429,
        )
    except (PhoneNumberInvalidError, ApiIdInvalidError) as e:
        print(f"[send_code] ОШИБКА для {phone}: {type(e).__name__}: {e}")
        return JSONResponse({"error": f"Не удалось отправить код: {e}"}, status_code=400)
    except Exception as e:
        print(f"[send_code] НЕОЖИДАННАЯ ОШИБКА для {phone}: {type(e).__name__}: {e}")
        return JSONResponse({"error": f"Ошибка отправки кода: {e}"}, status_code=400)

    # Куда Telegram отправил код — самое важное для диагностики
    code_type = type(sent.type).__name__  # SentCodeTypeApp / ...Sms / ...Call / ...
    next_type = type(sent.next_type).__name__ if sent.next_type else None
    where = {
        "SentCodeTypeApp": "в приложение Telegram (служебный чат «Telegram»)",
        "SentCodeTypeSms": "по SMS",
        "SentCodeTypeCall": "звонком",
        "SentCodeTypeFlashCall": "флеш-звонком",
        "SentCodeTypeMissedCall": "пропущенным звонком",
        "SentCodeTypeEmailCode": "на e-mail",
    }.get(code_type, code_type)
    print(
        f"[send_code] {phone}: код отправлен {where} "
        f"(type={code_type}, next_type={next_type}, "
        f"timeout={getattr(sent.type, 'length', '?')})"
    )

    state.login[pid] = {"phone": phone, "phone_code_hash": sent.phone_code_hash}
    return {"step": "code", "code_via": where}


@app.post("/api/profiles/{pid}/login/sign_in")
async def sign_in(pid: str, body: CodeIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    client = await get_client(pid)
    login = state.login.get(pid, {})
    if client is None or not login.get("phone_code_hash"):
        return JSONResponse({"error": "Сначала запроси код"}, status_code=400)
    try:
        await client.sign_in(
            phone=login["phone"],
            code=body.code.strip(),
            phone_code_hash=login["phone_code_hash"],
        )
    except SessionPasswordNeededError:
        return {"step": "password"}
    except PhoneCodeInvalidError:
        return JSONResponse({"error": "Неверный код"}, status_code=400)
    state.login[pid] = {"phone": None, "phone_code_hash": None}
    return {"step": "ready"}


@app.post("/api/profiles/{pid}/login/password")
async def login_password(pid: str, body: PasswordIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)
    try:
        await client.sign_in(password=body.password)
    except Exception as e:
        return JSONResponse({"error": f"Неверный пароль 2FA: {e}"}, status_code=400)
    state.login[pid] = {"phone": None, "phone_code_hash": None}
    return {"step": "ready"}


# ---------------------------------------------------------------------------
# Вход по QR-коду (обходит SMS/код — сканируешь QR в Telegram)
# ---------------------------------------------------------------------------
def _qr_svg(data):
    """Рендерит QR в SVG прямо на сервере (токен входа не уходит к третьим лицам)."""
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=11, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


@app.post("/api/profiles/{pid}/login/qr")
async def login_qr_start(pid: str, user=Depends(require_active)):
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)
    if await client.is_user_authorized():
        return {"status": "ready"}
    try:
        qr = await client.qr_login()
    except Exception as e:
        return JSONResponse({"error": f"Не удалось создать QR: {e}"}, status_code=400)
    state.login.setdefault(pid, {})["qr"] = qr
    return {"status": "pending", "url": qr.url, "svg": _qr_svg(qr.url)}


@app.post("/api/profiles/{pid}/login/qr/poll")
async def login_qr_poll(pid: str, user=Depends(require_active)):
    _owned_profile(pid, user)
    qr = state.login.get(pid, {}).get("qr")
    if qr is None:
        return {"status": "expired"}
    try:
        await qr.wait(timeout=5)
    except asyncio.TimeoutError:
        # ещё не отсканировали; если токен истёк — пересоздаём (новый QR)
        try:
            if qr.expires and qr.expires <= datetime.now(timezone.utc):
                await qr.recreate()
                return {"status": "pending", "url": qr.url, "svg": _qr_svg(qr.url)}
        except Exception:
            pass
        return {"status": "pending"}
    except SessionPasswordNeededError:
        return {"status": "password"}
    except Exception as e:
        return JSONResponse({"error": f"Ошибка входа по QR: {e}"}, status_code=400)
    state.login[pid].pop("qr", None)
    state.login[pid].update({"phone": None, "phone_code_hash": None})
    return {"status": "ready"}


# ---------------------------------------------------------------------------
# Поиск чатов
# ---------------------------------------------------------------------------
@app.get("/api/profiles/{pid}/search")
async def search(pid: str, q: str = "", user=Depends(require_user)):
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)

    q = q.strip()
    results = []
    seen = set()

    if not q:
        # Без запроса показываем недавние диалоги
        async for d in client.iter_dialogs(limit=30):
            _cache(pid, d.entity)
            pid_int = utils.get_peer_id(d.entity)
            if pid_int in seen:
                continue
            seen.add(pid_int)
            results.append(_brief(d.entity))
        return {"results": results}

    try:
        res = await client(SearchRequest(q=q, limit=30))
    except Exception as e:
        return JSONResponse({"error": f"Ошибка поиска: {e}"}, status_code=400)

    for e in list(res.users) + list(res.chats):
        _cache(pid, e)
        peer_id = utils.get_peer_id(e)
        if peer_id in seen:
            continue
        seen.add(peer_id)
        results.append(_brief(e))
    return {"results": results}


# ---------------------------------------------------------------------------
# Немедленная отправка
# ---------------------------------------------------------------------------
@app.post("/api/profiles/{pid}/send")
async def send_now(pid: str, body: SendIn, user=Depends(require_active)):
    profile = _owned_profile(pid, user)
    if _active_pid(user["id"]) != pid:
        return JSONResponse({"error": _INACTIVE_MSG}, status_code=409)
    if _on_cooldown(profile):
        return JSONResponse(
            {"error": f"Аккаунт на паузе из-за флуда. {profile.get('flood_note') or ''}".strip()},
            status_code=429,
        )
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    spin_err = _spin_issue(body.text)
    if spin_err:
        return JSONResponse({"error": spin_err}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)

    # Резервируем профиль ДО get_client(): параллельные запросы и scheduler не
    # должны одновременно открывать одну Telethon session DB.
    reservation = _reserve_current_send(pid)
    if reservation is None:
        return JSONResponse({"error": "Рассылка уже идёт — дождись окончания или нажми Стоп"}, status_code=409)

    try:
        client = await get_client(pid)
        if client is None or not await client.is_user_authorized():
            return JSONResponse({"error": "Не авторизован"}, status_code=401)

        targets = [{"id": t.id, "name": t.name, "kind": t.kind} for t in body.targets]
        if len(targets) == 1:
            # один чат — шлём сразу, чтобы дать мгновенный ответ
            status, detail = await _send_one(client, pid, targets[0], body.text)
            # запись в историю (одиночная отправка тоже учитывается)
            now_iso = datetime.now().isoformat(timespec="seconds")
            reason = detail or status
            rec = {
                "id": secrets.token_hex(6), "profile_id": pid, "owner": profile.get("owner"),
                "started": now_iso, "finished": now_iso, "total": 1,
                "ok": 1 if status == "ok" else 0,
                "failed": [] if status == "ok" else [{"name": targets[0]["name"], "reason": reason[:120]}],
                "status": _BULK_STATUS.get(status, "ошибка") if status != "ok" else "готово",
                "source": "ручная", "label": "", "text_preview": (body.text or "")[:80],
            }
            _log_send_run(rec)
            if status == "flood":
                return {"ok": True, "sent": [], "paused": f"Telegram просит подождать {detail}с."}
            if status == "spam":
                return {"ok": True, "sent": [], "paused": "Telegram пометил аккаунт как спам."}
            if status == "limit":
                return {"ok": True, "sent": [], "paused": "Достигнут дневной лимит отправок — попробуй позже."}
            if status == "dead":
                return {"ok": True, "sent": [], "paused": "Аккаунт заблокирован Telegram — отправки остановлены."}
            if status == "badmsg":
                return {"ok": True, "sent": [], "errors": [f"Текст не отправлен: {reason}"]}
            if status in ("skip", "slow", "error"):
                return {"ok": True, "sent": [], "errors": [f"{targets[0]['name']}: {reason}"]}
            return {"ok": True, "sent": [targets[0]["name"]], "errors": []}

        # Несколько чатов: без окна гонки передаём резерв фоновой задаче.
        task = _handoff_current_send(
            pid,
            reservation,
            lambda: _send_bulk_safe(
                pid, targets, body.text, body.gap_min, body.gap_max, source="ручная"
            ),
        )
        if task is None:
            return JSONResponse({"error": "Не удалось запустить рассылку"}, status_code=409)
        return {"ok": True, "started": len(targets)}
    finally:
        # После handoff в словаре уже лежит фоновая task, поэтому её не снимет.
        _release_current_send(pid, reservation)


class TestIn(BaseModel):
    text: str


@app.post("/api/profiles/{pid}/test")
async def send_test(pid: str, body: TestIn, user=Depends(require_active)):
    """Тест-режим: шлёт один вариант текста в «Избранное» (Saved Messages) — проверить перед рассылкой."""
    _owned_profile(pid, user)
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    spin_err = _spin_issue(body.text)
    if spin_err:
        return JSONResponse({"error": spin_err}, status_code=400)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    try:
        await client.send_message("me", _spin(body.text))   # 'me' = Избранное
    except Exception as e:
        return JSONResponse({"error": f"Не удалось отправить: {e}"}, status_code=400)
    return {"ok": True}


@app.post("/api/profiles/{pid}/resume")
async def resume_profile(pid: str, user=Depends(require_user)):
    """Снимает паузу/спам-флаг с профиля (возобновляет отправки)."""
    _owned_profile(pid, user)
    _clear_cooldown(pid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Расписания
# ---------------------------------------------------------------------------
def _validate_time(t):
    try:
        hh, mm = t.split(":")
        return 0 <= int(hh) <= 23 and 0 <= int(mm) <= 59
    except Exception:
        return False


@app.get("/api/profiles/{pid}/schedules")
async def get_schedules(pid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    return {"schedules": [s for s in load_schedules() if s["profile_id"] == pid]}


def _schedule_fields(body):
    """Собирает поля расписания из тела запроса. Возвращает (fields, None) или (None, error)."""
    if not body.text.strip():
        return None, JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    spin_err = _spin_issue(body.text)
    if spin_err:
        return None, JSONResponse({"error": spin_err}, status_code=400)
    if not body.targets:
        return None, JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)
    fields = {
        "targets": [t.model_dump() for t in body.targets],
        "text": body.text,
        "gap_min": body.gap_min,
        "gap_max": body.gap_max,
        "next_fire": None,
    }
    if body.interval_min is not None:
        lo = int(body.interval_min)
        hi = int(body.interval_max) if body.interval_max is not None else lo
        if lo < 1:
            return None, JSONResponse({"error": "Минимальный интервал — 1 минута"}, status_code=400)
        if hi < lo:
            hi = lo
        fields.update({"interval_min": lo, "interval_max": hi, "time": None, "weekdays": [], "dates": []})
    else:
        if not _validate_time(body.time):
            return None, JSONResponse({"error": "Неверное время (нужен формат ЧЧ:ММ)"}, status_code=400)
        fields.update({
            "interval_min": None, "interval_max": None,
            "time": body.time,
            "weekdays": sorted(set(w for w in body.weekdays if 0 <= w <= 6)),
            "dates": sorted(set(body.dates)),
        })
    return fields, None


@app.post("/api/profiles/{pid}/schedules")
async def create_schedule(pid: str, body: ScheduleIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    fields, err = _schedule_fields(body)
    if err:
        return err
    rule = {
        "id": uuid.uuid4().hex[:8],
        "profile_id": pid,
        "owner": user["id"],
        "enabled": True,
        "last_fired": None,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        **fields,
    }
    schedules = load_schedules()
    schedules.append(rule)
    save_schedules(schedules)
    return {"ok": True, "schedule": rule}


@app.post("/api/profiles/{pid}/schedules/{sid}/update")
async def update_schedule(pid: str, sid: str, body: ScheduleIn, user=Depends(require_active)):
    """Изменяет существующее расписание (текст/чаты/время/режим)."""
    _owned_profile(pid, user)
    fields, err = _schedule_fields(body)
    if err:
        return err
    schedules = load_schedules()
    target = next((s for s in schedules if s["id"] == sid and s["profile_id"] == pid), None)
    if target is None:
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    target.update(fields)
    target["last_fired"] = None   # сброс, чтобы новое время отработало
    target.pop("pending_fire", None)
    save_schedules(schedules)
    return {"ok": True, "schedule": target}


@app.post("/api/profiles/{pid}/schedules/{sid}/duplicate")
async def duplicate_schedule(pid: str, sid: str, user=Depends(require_active)):
    """Создаёт копию расписания."""
    _owned_profile(pid, user)
    schedules = load_schedules()
    src = next((s for s in schedules if s["id"] == sid and s["profile_id"] == pid), None)
    if src is None:
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    new = dict(src)
    new["id"] = uuid.uuid4().hex[:8]
    new["enabled"] = True
    new["last_fired"] = None
    new["next_fire"] = None
    new.pop("pending_fire", None)
    new["created"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    schedules.append(new)
    save_schedules(schedules)
    return {"ok": True, "schedule": new}


@app.delete("/api/profiles/{pid}/schedules/{sid}")
async def delete_schedule(pid: str, sid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    schedules = load_schedules()
    new = [s for s in schedules if not (s["id"] == sid and s["profile_id"] == pid)]
    if len(new) == len(schedules):
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    save_schedules(new)
    return {"ok": True}


@app.post("/api/profiles/{pid}/schedules/{sid}/toggle")
async def toggle_schedule(pid: str, sid: str, user=Depends(require_user)):
    """Ставит расписание на паузу / снимает с паузы."""
    _owned_profile(pid, user)
    schedules = load_schedules()
    target = next((s for s in schedules if s["id"] == sid and s["profile_id"] == pid), None)
    if target is None:
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    target["enabled"] = not target.get("enabled", True)
    if not target["enabled"]:
        target.pop("pending_fire", None)
    save_schedules(schedules)
    return {"ok": True, "enabled": target["enabled"]}


# ---------------------------------------------------------------------------
# Папки чатов (сохранённые наборы получателей)
# ---------------------------------------------------------------------------
@app.get("/api/profiles/{pid}/packs")
async def get_packs(pid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    return {"packs": [p for p in load_packs() if p["profile_id"] == pid]}


@app.post("/api/profiles/{pid}/packs")
async def create_pack(pid: str, body: PackIn, user=Depends(require_user)):
    _owned_profile(pid, user)
    name = body.name.strip()
    if not name:
        return JSONResponse({"error": "Введи название папки"}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "В папке нет чатов"}, status_code=400)
    pack = {
        "id": uuid.uuid4().hex[:8],
        "profile_id": pid,
        "owner": user["id"],
        "name": name,
        "targets": [t.model_dump() for t in body.targets],
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    packs = load_packs()
    packs.append(pack)
    save_packs(packs)
    return {"ok": True, "pack": pack}


@app.delete("/api/profiles/{pid}/packs/{packid}")
async def delete_pack(pid: str, packid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    packs = load_packs()
    new = [p for p in packs if not (p["id"] == packid and p["profile_id"] == pid)]
    if len(new) == len(packs):
        return JSONResponse({"error": "Папка не найдена"}, status_code=404)
    save_packs(new)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Вступление в чаты по ссылкам + сбор каналов в папку Telegram
# ---------------------------------------------------------------------------
@app.post("/api/profiles/{pid}/join")
async def join_chats(pid: str, body: JoinIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    links = [x for x in re.split(r"[\s,]+", body.links or "") if x.strip()]
    if not links:
        return JSONResponse({"error": "Вставь хотя бы одну ссылку"}, status_code=400)
    if len(links) > 200:
        return JSONResponse({"error": "За раз не больше 200 ссылок"}, status_code=400)
    existing = state.join_jobs.get(pid)
    if existing and existing.get("running"):
        return JSONResponse({"error": "Вступление уже идёт — дождись окончания или нажми Стоп"}, status_code=409)
    state.join_jobs[pid] = {
        "total": len(links), "done": 0,
        "joined": [], "skipped": [], "failed": [],
        "running": True, "cancel": False, "status": "running",
    }
    asyncio.create_task(_join_job_safe(pid, links))
    return {"ok": True, "total": len(links)}


@app.get("/api/profiles/{pid}/join/status")
async def join_chats_status(pid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    job = state.join_jobs.get(pid)
    if not job:
        return {"running": False, "total": 0, "done": 0, "joined": [], "skipped": [], "failed": [], "status": ""}
    return job


@app.post("/api/profiles/{pid}/join/stop")
async def join_chats_stop(pid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    job = state.join_jobs.get(pid)
    if job:
        job["cancel"] = True
    return {"ok": True}


@app.get("/api/profiles/{pid}/send/status")
async def send_status(pid: str, user=Depends(require_user)):
    """Живой прогресс текущей/последней bulk-рассылки профиля."""
    _owned_profile(pid, user)
    job = state.send_jobs.get(pid)
    if not job:
        return {"running": False, "total": 0, "done": 0, "ok": 0, "failed": [], "status": ""}
    return job


@app.post("/api/profiles/{pid}/send/stop")
async def send_stop(pid: str, user=Depends(require_user)):
    """Останавливает активную bulk-рассылку (после текущего чата)."""
    _owned_profile(pid, user)
    job = state.send_jobs.get(pid)
    if job:
        if job.get("retry_pending") and not job.get("running"):
            try:
                await _discard_queued_send(pid, "остановлено")
            except Exception as e:
                return JSONResponse({"error": f"Не удалось остановить рассылку: {e}"}, status_code=500)
        else:
            job["cancel"] = True
    return {"ok": True}


@app.get("/api/profiles/{pid}/sends")
async def send_history(pid: str, user=Depends(require_user), limit: int = 30):
    """История завершённых рассылок профиля (newest-first)."""
    _owned_profile(pid, user)
    limit = max(1, min(int(limit or 30), 100))
    rows = [s for s in load_sends() if s.get("profile_id") == pid][:limit]
    return {"sends": rows}


@app.get("/api/profiles/{pid}/tgfolders")
async def list_tg_folders(pid: str, user=Depends(require_user)):
    """Список папок Telegram аккаунта с чатами внутри (для импорта в получателей)."""
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    try:
        res = await client(GetDialogFiltersRequest())
        filters = getattr(res, "filters", res) or []
    except Exception as e:
        return JSONResponse({"error": f"Не удалось получить папки: {e}"}, status_code=400)
    out = []
    for f in filters:
        peers = getattr(f, "include_peers", None)
        if peers is None:   # DialogFilterDefault (папка «Все чаты») — пропускаем
            continue
        title = getattr(f, "title", "")
        title_text = getattr(title, "text", title) if title else ""
        chats = []
        for p in peers:
            try:
                ent = await client.get_entity(p)
                _cache(pid, ent)
                chats.append(_brief(ent))
            except Exception:
                pass
        out.append({"name": title_text or "Папка", "chats": chats})
    return {"folders": out}


@app.get("/api/profiles/{pid}/alldialogs")
async def all_dialogs(pid: str, user=Depends(require_user)):
    """Все группы и каналы аккаунта (для кнопки «Выбрать все»)."""
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    out, seen = [], set()
    try:
        async for d in client.iter_dialogs():
            e = d.entity
            if isinstance(e, (Chat, Channel)):
                _cache(pid, e)
                peer_id = utils.get_peer_id(e)
                if peer_id in seen:
                    continue
                seen.add(peer_id)
                out.append(_brief(e))
    except Exception as e:
        return JSONResponse({"error": f"Ошибка: {e}"}, status_code=400)
    return {"results": out}


@app.get("/api/profiles/{pid}/export_links")
async def export_links(pid: str, user=Depends(require_user)):
    """Собирает ссылки на все каналы/группы аккаунта — для переноса на другой аккаунт.
    public: публичные (@username) — можно массово вступить.
    private_invite: приватные, где удалось достать invite-ссылку (ты админ/есть право).
    private_nolink: приватные без ссылки (нет прав) — только по названию."""
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse(
            {"error": "Аккаунт не авторизован (возможно, заморожен/забанен) — прочитать его каналы не выйдет."},
            status_code=401,
        )
    public, private_invite, private_nolink = [], [], []
    try:
        async for d in client.iter_dialogs():
            e = d.entity
            if not isinstance(e, (Chat, Channel)):
                continue   # только группы и каналы
            name = _name(e)
            uname = getattr(e, "username", None)
            if uname:
                public.append({"name": name, "username": uname, "link": f"https://t.me/{uname}"})
                continue
            # приватный — пробуем достать invite-ссылку (нужно право приглашать)
            try:
                res = await client(ExportChatInviteRequest(e))
                link = getattr(res, "link", None) or getattr(res, "invite", None)
                if link:
                    private_invite.append({"name": name, "link": link})
                else:
                    private_nolink.append({"name": name})
            except Exception:
                private_nolink.append({"name": name})
    except Exception as e:
        return JSONResponse({"error": f"Не удалось прочитать чаты: {e}"}, status_code=400)
    return {
        "public": public,
        "private_invite": private_invite,
        "private_nolink": private_nolink,
        "counts": {"public": len(public), "private_invite": len(private_invite), "private_nolink": len(private_nolink)},
    }


# ---------------------------------------------------------------------------
# Клонирование настроек аккаунта (имя/био/фото/приватность/папки) на новый акк
# ---------------------------------------------------------------------------
def _privacy_keys():
    """Ключи приватности, которые умеем переносить: наш_код -> (класс ключа)."""
    from telethon.tl import types as T
    return {
        "phone":    T.InputPrivacyKeyPhoneNumber,
        "lastseen": T.InputPrivacyKeyStatusTimestamp,
        "photo":    T.InputPrivacyKeyProfilePhoto,
        "calls":    T.InputPrivacyKeyPhoneCall,
        "forwards": T.InputPrivacyKeyForwards,
        "groups":   T.InputPrivacyKeyChatInvite,
        "bio":      T.InputPrivacyKeyAbout,
    }


def _privacy_to_token(rules):
    """Правила приватности от Telegram → простой токен all|contacts|none."""
    names = " ".join(type(r).__name__.lower() for r in (rules or []))
    if "disallowall" in names:   # проверяем раньше 'allowall' (это его подстрока)
        return "none"
    if "allowall" in names:
        return "all"
    if "allowcontacts" in names:
        return "contacts"
    return "contacts"


def _token_to_rules(token):
    """Токен → список InputPrivacyValue* для установки на новом аккаунте."""
    from telethon.tl import types as T
    if token == "all":
        return [T.InputPrivacyValueAllowAll()]
    if token == "none":
        return [T.InputPrivacyValueDisallowAll()]
    return [T.InputPrivacyValueAllowContacts()]


def _snap_path(pid):
    return os.path.join(CLONES_DIR, f"{pid}.json")


def _snap_photo(pid):
    return os.path.join(CLONES_DIR, f"{pid}.jpg")


@app.post("/api/profiles/{pid}/clone/export")
async def clone_export(pid: str, user=Depends(require_user)):
    """Снимок настроек аккаунта (имя, био, фото, приватность, папки) — для переноса на другой аккаунт."""
    prof = _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Аккаунт не авторизован (возможно, заморожен) — снять настройки не выйдет."}, status_code=401)
    os.makedirs(CLONES_DIR, exist_ok=True)
    from telethon.tl.functions.account import GetPrivacyRequest
    from telethon.tl.functions.users import GetFullUserRequest

    snap = {"source_pid": pid, "source_name": prof.get("name", ""), "ts": datetime.now().isoformat(timespec="seconds"),
            "first_name": "", "last_name": "", "about": "", "has_photo": False, "privacy": {}, "folders": []}
    try:
        me = await client.get_me()
        snap["first_name"] = me.first_name or ""
        snap["last_name"] = me.last_name or ""
    except Exception as e:
        return JSONResponse({"error": f"Не удалось прочитать профиль: {e}"}, status_code=400)
    # био
    try:
        full = await client(GetFullUserRequest("me"))
        snap["about"] = getattr(full.full_user, "about", "") or ""
    except Exception:
        pass
    # фото
    try:
        got = await client.download_profile_photo("me", file=_snap_photo(pid))
        snap["has_photo"] = bool(got)
    except Exception:
        snap["has_photo"] = False
    # приватность
    try:
        for code, KeyCls in _privacy_keys().items():
            try:
                r = await client(GetPrivacyRequest(KeyCls()))
                snap["privacy"][code] = _privacy_to_token(r.rules)
            except Exception:
                pass
    except Exception:
        pass
    # папки (структура + чаты по username/id)
    try:
        res = await client(GetDialogFiltersRequest())
        filters = getattr(res, "filters", res) or []
        for f in filters:
            peers = getattr(f, "include_peers", None)
            if peers is None:
                continue
            title = getattr(f, "title", "")
            title_text = getattr(title, "text", title) if title else ""
            chats = []
            for p in peers:
                try:
                    ent = await client.get_entity(p)
                    chats.append({"username": getattr(ent, "username", None) or "",
                                  "id": utils.get_peer_id(ent), "title": _name(ent)})
                except Exception:
                    pass
            snap["folders"].append({"name": title_text or "Папка", "chats": chats})
    except Exception:
        pass

    _write_json(_snap_path(pid), snap)
    return {"ok": True, "snapshot": {
        "source_pid": pid, "source_name": snap["source_name"], "ts": snap["ts"],
        "first_name": snap["first_name"], "last_name": snap["last_name"],
        "about": snap["about"], "has_photo": snap["has_photo"],
        "privacy_count": len(snap["privacy"]), "folders_count": len(snap["folders"]),
    }}


@app.get("/api/clone/snapshots")
async def clone_snapshots(user=Depends(require_user)):
    """Список сохранённых снимков настроек (по профилям этого пользователя)."""
    out = []
    my_pids = {p["id"] for p in load_profiles() if p.get("owner") == user["id"]}
    if os.path.isdir(CLONES_DIR):
        for fn in os.listdir(CLONES_DIR):
            if not fn.endswith(".json"):
                continue
            spid = fn[:-5]
            if spid not in my_pids:
                continue
            snap = _read_json(os.path.join(CLONES_DIR, fn), None)
            if not snap:
                continue
            out.append({"source_pid": spid, "source_name": snap.get("source_name", ""), "ts": snap.get("ts", ""),
                        "first_name": snap.get("first_name", ""), "has_photo": snap.get("has_photo", False),
                        "privacy_count": len(snap.get("privacy", {})), "folders_count": len(snap.get("folders", []))})
    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return {"snapshots": out}


class CloneApplyIn(BaseModel):
    source_pid: str
    name: bool = True
    photo: bool = True
    privacy: bool = True
    folders: bool = True


@app.post("/api/profiles/{pid}/clone/apply")
async def clone_apply(pid: str, body: CloneApplyIn, user=Depends(require_active)):
    """Применяет снимок настроек (от другого аккаунта пользователя) к этому аккаунту."""
    _owned_profile(pid, user)
    _owned_profile(body.source_pid, user)   # снимок должен быть от своего же профиля
    if body.source_pid == pid:
        return JSONResponse({"error": "Нельзя применить настройки аккаунта к нему же"}, status_code=400)
    snap = _read_json(_snap_path(body.source_pid), None)
    if not snap:
        return JSONResponse({"error": "Снимок не найден — сначала сохрани настройки на исходном аккаунте"}, status_code=404)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)

    from telethon.tl.functions.account import UpdateProfileRequest, SetPrivacyRequest, GetPrivacyRequest
    from telethon.tl.functions.photos import UploadProfilePhotoRequest
    done = []
    # имя + био
    if body.name:
        try:
            await client(UpdateProfileRequest(first_name=snap.get("first_name") or "",
                                              last_name=snap.get("last_name") or "",
                                              about=snap.get("about") or ""))
            done.append("имя и био")
        except Exception as e:
            done.append(f"имя — ошибка: {e}")
    # фото
    if body.photo and snap.get("has_photo") and os.path.exists(_snap_photo(body.source_pid)):
        try:
            f = await client.upload_file(_snap_photo(body.source_pid))
            await client(UploadProfilePhotoRequest(file=f))
            done.append("фото профиля")
        except Exception as e:
            done.append(f"фото — ошибка: {e}")
    # приватность
    if body.privacy and snap.get("privacy"):
        okc = 0
        keys = _privacy_keys()
        for code, token in snap["privacy"].items():
            KeyCls = keys.get(code)
            if not KeyCls:
                continue
            try:
                await client(SetPrivacyRequest(key=KeyCls(), rules=_token_to_rules(token)))
                okc += 1
            except Exception:
                pass
        if okc:
            done.append(f"приватность ({okc})")
    # папки — только чаты, куда этот аккаунт уже вступил
    folders_added, chats_missing = 0, 0
    if body.folders and snap.get("folders"):
        try:
            from telethon.tl.types import DialogFilter
            try:
                from telethon.tl.types import TextWithEntities
            except Exception:
                TextWithEntities = None
            res = await client(GetDialogFiltersRequest())
            existing = getattr(res, "filters", res) or []
            used = {getattr(f, "id", None) for f in existing if isinstance(getattr(f, "id", None), int)}
            next_id = (lambda: next(i for i in range(2, 250) if i not in used))
            for folder in snap["folders"]:
                peers = []
                for ch in folder.get("chats", []):
                    ref = ch.get("username") or ch.get("id")
                    if not ref:
                        chats_missing += 1
                        continue
                    try:
                        peers.append(await client.get_input_entity(ref))
                    except Exception:
                        chats_missing += 1
                if not peers:
                    continue
                fid = next_id()
                used.add(fid)
                title = folder.get("name") or "Папка"
                title_obj = TextWithEntities(text=title, entities=[]) if TextWithEntities else title
                flt = DialogFilter(id=fid, title=title_obj, pinned_peers=[], include_peers=peers, exclude_peers=[])
                try:
                    await client(UpdateDialogFilterRequest(id=fid, filter=flt))
                    folders_added += 1
                except Exception:
                    pass
        except Exception:
            pass
    if folders_added:
        msg = f"папки ({folders_added})"
        if chats_missing:
            msg += f", {chats_missing} чат(ов) пропущено — нет вступления"
        done.append(msg)
    elif body.folders and chats_missing:
        done.append(f"папки: пропущены — новый аккаунт ещё не вступил в чаты ({chats_missing})")

    return {"ok": True, "applied": done, "from": snap.get("source_name", "")}


@app.post("/api/profiles/{pid}/folder")
async def collect_folder(pid: str, body: FolderIn, user=Depends(require_active)):
    """Собирает все каналы/супергруппы аккаунта в отдельную папку Telegram."""
    _owned_profile(pid, user)
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    name = (body.name or "Каналы").strip() or "Каналы"

    peers = []
    try:
        async for d in client.iter_dialogs():
            e = d.entity
            if isinstance(e, Channel):   # каналы и супергруппы
                try:
                    peers.append(await client.get_input_entity(e))
                except Exception:
                    pass
    except Exception as e:
        return JSONResponse({"error": f"Не удалось получить чаты: {e}"}, status_code=400)
    if not peers:
        return JSONResponse({"error": "Каналов не найдено"}, status_code=400)

    try:
        from telethon.tl.types import DialogFilter
        # свободный id папки
        used = set()
        try:
            res = await client(GetDialogFiltersRequest())
            existing = getattr(res, "filters", res) or []
            for f in existing:
                fid = getattr(f, "id", None)
                if isinstance(fid, int):
                    used.add(fid)
        except Exception:
            pass
        new_id = next(i for i in range(2, 250) if i not in used)
        # title в новых версиях — TextWithEntities, в старых — строка
        try:
            from telethon.tl.types import TextWithEntities
            title = TextWithEntities(text=name, entities=[])
        except Exception:
            title = name
        flt = DialogFilter(id=new_id, title=title, pinned_peers=[], include_peers=peers, exclude_peers=[])
        await client(UpdateDialogFilterRequest(id=new_id, filter=flt))
    except Exception as e:
        return JSONResponse({"error": f"Не удалось создать папку: {type(e).__name__}: {e}"}, status_code=400)

    return {"ok": True, "count": len(peers), "name": name}


# ---------------------------------------------------------------------------
# Статика
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"Открой веб-панель: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
