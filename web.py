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
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, urlencode

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from telethon import TelegramClient, utils
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
SENDS_KEEP = int(os.environ.get("SENDS_KEEP", "300"))  # сколько последних запусков хранить
QUEUE_JSON = os.path.join(PROFILES_DIR, "queue.json")  # активные рассылки (докатка при рестарте)
NOTIFS_JSON = os.path.join(PROFILES_DIR, "notifications.json")  # уведомления владельцу о ЧП
CLONES_DIR = os.path.join(PROFILES_DIR, "clones")  # снимки настроек аккаунта для клонирования
NOTIFS_KEEP = int(os.environ.get("NOTIFS_KEEP", "100"))
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

# --- Тарифы и оплата ---
# Токен CryptoBot (Crypto Pay API). Получить: @CryptoBot → Crypto Pay → Create App.
CRYPTOBOT_TOKEN = os.environ.get("CRYPTOBOT_TOKEN", "")
CRYPTOBOT_API = os.environ.get("CRYPTOBOT_API", "https://pay.crypt.bot/api")
PANEL_DOMAIN = os.environ.get("PANEL_DOMAIN", "")

# Тарифы доступа. Цена в рублях за период `days`. Меняй цифры как нужно.
TIERS = {
    "start":    {"name": "1 неделя",      "price_rub": 990,  "days": 7,  "max_accounts": 1},
    "standard": {"name": "2 недели",      "price_rub": 1790, "days": 14, "max_accounts": 2},
    "pro":      {"name": "1 месяц (Про)", "price_rub": 2990, "days": 30, "max_accounts": 5},
}
DEFAULT_TIER = "start"


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


def _tier_key(user):
    t = (user or {}).get("tier") or DEFAULT_TIER
    return t if t in TIERS else DEFAULT_TIER


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


def _extend_subscription(uid, tier_key, days, clear_invoice=None):
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
            if tier_key:
                u["tier"] = tier_key
            if clear_invoice and u.get("pending_invoice") == clear_invoice:
                u.pop("pending_invoice", None)
            break
    save_users(users)


def _user_public(u):
    return {
        "id": u["id"],
        "username": u["username"],
        "status": u.get("status"),
        "is_admin": bool(u.get("is_admin")),
        "created": u.get("created"),
        "tier": _tier_key(u),
        "paid_until": u.get("paid_until"),
        "sub_active": _sub_active(u),
        "days_left": _days_left(u),
    }


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
    # profile_id -> {"phone": ..., "phone_code_hash": ...}
    login: dict[str, dict] = {}
    # profile_id -> {peer_id: entity}
    entities: dict[str, dict] = {}
    # profile_id -> {"total","done","joined":[],"failed":[],"running"}
    join_jobs: dict[str, dict] = {}
    # profile_id -> {"total","done","ok","failed":[],"running","cancel","status",...}
    send_jobs: dict[str, dict] = {}
    scheduler_task = None


state = State()


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


async def get_client(pid) -> TelegramClient | None:
    """Возвращает подключённый клиент для профиля (создаёт при необходимости)."""
    client = state.clients.get(pid)
    if client is not None:
        if not client.is_connected():
            await client.connect()
        return client

    profile = get_profile(pid)
    if profile is None:
        return None

    client = TelegramClient(
        _session_path(profile), profile["api_id"], profile["api_hash"],
        proxy=_parse_proxy(profile.get("proxy")),
    )
    await client.connect()
    state.clients[pid] = client
    state.entities.setdefault(pid, {})
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
    "flood": "флуд-пауза",
    "spam": "спам-флаг",
    "limit": "дневной лимит",
    "cooldown": "на паузе",
    "dead": "аккаунт заблокирован",
    "badmsg": "проблема с текстом",
    None: "готово",
}

# категории, при которых рассылку надо ОСТАНОВИТЬ целиком (а не пропускать чат)
_STOP_CATEGORIES = ("flood", "spam", "limit", "dead", "badmsg")


async def _send_bulk(pid, targets, text, gap_lo=None, gap_hi=None, source="ручная",
                     label="", started=None, done=0, ok=0, failed=None, fresh=True):
    """Последовательная отправка по чатам: пауза между ними, защита от флуда,
    живой прогресс (state.send_jobs), отмена, докатка при рестарте и запись в историю.
    targets — оставшиеся к отправке чаты (при докатке — недоотправленный хвост)."""
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        _queue_clear(pid)
        return
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

    _persist()
    interrupted = None   # None | cancel | flood | spam | limit | cooldown
    shutdown = False
    try:
        while remaining:
            if job.get("cancel"):
                interrupted = "cancel"
                break
            if _on_cooldown(get_profile(pid)):
                interrupted = "cooldown"
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
    finally:
        job["running"] = False
        if shutdown:
            _persist()   # сохраняем недоотправленное, историю не пишем — рассылка не завершена
        else:
            _queue_clear(pid)
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


async def _scheduler_loop():
    """Каждые 20 секунд проверяет правила и отправляет наступившие."""
    while True:
        try:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            schedules = load_schedules()
            changed = False

            for rule in schedules:
                if not rule.get("enabled", True):
                    continue

                # Не отправляем, если владелец заблокирован/удалён или подписка истекла
                owner = rule.get("owner")
                if owner is not None:
                    ou = get_user(owner)
                    if ou is None or ou.get("status") != "approved" or not _sub_active(ou):
                        continue

                # Профиль на охлаждении после флуда — пропускаем (возобновится сам)
                if _on_cooldown(get_profile(rule["profile_id"])):
                    continue

                # Режим интервала: каждые N (случайно min..max) минут
                if rule.get("interval_min"):
                    nf = rule.get("next_fire")
                    due = nf is None
                    if not due:
                        try:
                            due = now >= datetime.fromisoformat(nf)
                        except Exception:
                            due = True
                    if due:
                        await _fire_rule(rule)
                        lo = int(rule.get("interval_min") or 1)
                        hi = int(rule.get("interval_max") or lo)
                        if hi < lo:
                            hi = lo
                        delay = random.randint(lo, hi)
                        rule["next_fire"] = (now + timedelta(minutes=delay)).isoformat(timespec="seconds")
                        changed = True
                    continue

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
                if rule.get("last_fired") == occ:
                    continue

                await _fire_rule(rule)
                rule["last_fired"] = occ
                changed = True

            if changed:
                save_schedules(schedules)
        except Exception as e:
            print(f"[scheduler] ошибка цикла: {e}")

        await asyncio.sleep(20)


async def _resume_queued_sends():
    """Докатка: после рестарта продолжает рассылки, прерванные на середине."""
    jobs = _queue_load()
    for j in jobs:
        remaining = j.get("remaining") or []
        if not remaining:
            _queue_clear(j.get("pid"))
            continue
        # владелец должен быть активен, иначе не возобновляем
        ou = get_user(j.get("owner")) if j.get("owner") else None
        if j.get("owner") and (ou is None or ou.get("status") != "approved" or not _sub_active(ou)):
            _queue_clear(j.get("pid"))
            continue
        print(f"[resume] докатка рассылки {j.get('pid')}: осталось {len(remaining)} чат(ов)")
        asyncio.create_task(_send_bulk_safe(
            j["pid"], remaining, j.get("text", ""),
            j.get("gap_lo"), j.get("gap_hi"),
            j.get("source", "ручная"), j.get("label", ""),
            j.get("started"), int(j.get("done") or 0), int(j.get("ok") or 0),
            j.get("failed") or [], False,   # fresh=False — хвост не перемешиваем
        ))


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.scheduler_task = asyncio.create_task(_scheduler_loop())
    await _resume_queued_sends()
    yield
    if state.scheduler_task:
        state.scheduler_task.cancel()
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


@app.get("/api/auth/me")
async def auth_me(request: Request):
    u = _current_user(request)
    if not u:
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    return {"user": _user_public(u)}


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

    # Удаляем профили пользователя (вместе с сессиями Telegram) и его расписания.
    for p in [p for p in load_profiles() if p.get("owner") == uid]:
        await _destroy_profile(p)
    save_schedules([s for s in load_schedules() if s.get("owner") != uid])
    save_packs([p for p in load_packs() if p.get("owner") != uid])
    save_users([u for u in users if u["id"] != uid])
    return {"ok": True}


class SubIn(BaseModel):
    tier: str | None = None
    add_days: int | None = None


@app.post("/api/admin/users/{uid}/subscription")
async def admin_subscription(uid: str, body: SubIn, admin=Depends(require_admin)):
    """Админ: сменить тариф и/или продлить подписку вручную."""
    users = load_users()
    target = next((u for u in users if u["id"] == uid), None)
    if not target:
        return JSONResponse({"error": "Пользователь не найден"}, status_code=404)
    if body.tier:
        if body.tier not in TIERS:
            return JSONResponse({"error": "Неизвестный тариф"}, status_code=400)
        target["tier"] = body.tier
    if body.add_days:
        base = datetime.now()
        if target.get("paid_until"):
            try:
                pu = datetime.fromisoformat(target["paid_until"])
                if pu > base:
                    base = pu
            except Exception:
                pass
        target["paid_until"] = (base + timedelta(days=int(body.add_days))).isoformat(timespec="seconds")
    save_users(users)
    return {"ok": True, "user": _user_public(target)}


# ---------------------------------------------------------------------------
# Тарифы и оплата (CryptoBot)
# ---------------------------------------------------------------------------
@app.get("/api/tiers")
async def get_tiers(user=Depends(require_user)):
    return {"tiers": TIERS, "default": DEFAULT_TIER}


@app.get("/api/billing/info")
async def billing_info(user=Depends(require_user)):
    tkey = _tier_key(user)
    return {
        "tier_key": tkey,
        "tier": TIERS[tkey],
        "active": _sub_active(user),
        "paid_until": user.get("paid_until"),
        "days_left": _days_left(user),
        "crypto_enabled": bool(CRYPTOBOT_TOKEN),
    }


class BillIn(BaseModel):
    tier: str | None = None


def _tme_to_tg(url):
    """Конвертирует https://t.me/... в tg://resolve?... — открывает приложение Telegram
    напрямую, минуя браузер (обход блокировки t.me у провайдеров)."""
    try:
        u = urlparse(url or "")
        if u.netloc not in ("t.me", "telegram.me"):
            return None
        parts = [p for p in u.path.split("/") if p]
        if not parts:
            return None
        params = {"domain": parts[0]}
        if len(parts) >= 2:
            params["appname"] = parts[1]
        for k, v in parse_qs(u.query).items():
            params[k] = v[0]
        return "tg://resolve?" + urlencode(params)
    except Exception:
        return None


@app.post("/api/billing/invoice")
async def billing_invoice(body: BillIn, user=Depends(require_user)):
    if not CRYPTOBOT_TOKEN:
        return JSONResponse({"error": "Оплата криптой не настроена (нет CRYPTOBOT_TOKEN)"}, status_code=400)
    tkey = body.tier if (body.tier in TIERS) else _tier_key(user)
    tier = TIERS[tkey]
    import httpx

    data = {
        "currency_type": "fiat",
        "fiat": "RUB",
        "amount": str(tier["price_rub"]),
        "description": f"Доступ «{tier['name']}» ({tier['days']} дн.)",
        "payload": f"{user['id']}:{tkey}",
        "expires_in": 3600,
    }
    if PANEL_DOMAIN:
        data["paid_btn_name"] = "callback"
        data["paid_btn_url"] = f"https://{PANEL_DOMAIN}"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(f"{CRYPTOBOT_API}/createInvoice", json=data,
                             headers={"Crypto-Pay-API-Token": CRYPTOBOT_TOKEN})
            j = r.json()
    except Exception as e:
        return JSONResponse({"error": f"CryptoBot недоступен: {e}"}, status_code=502)
    if not j.get("ok"):
        return JSONResponse({"error": f"CryptoBot: {j.get('error')}"}, status_code=502)
    inv = j["result"]
    users = load_users()
    for u in users:
        if u["id"] == user["id"]:
            u["pending_invoice"] = inv["invoice_id"]
            u["pending_tier"] = tkey
            break
    save_users(users)
    bot_url = inv.get("bot_invoice_url") or inv.get("pay_url")
    pay_url = inv.get("mini_app_invoice_url") or bot_url
    # tg:// — прямое открытие приложения (обход блокировки t.me в браузере)
    deeplink = _tme_to_tg(bot_url) or _tme_to_tg(inv.get("mini_app_invoice_url"))
    return {
        "pay_url": pay_url,
        "pay_deeplink": deeplink,
        "invoice_id": inv["invoice_id"],
        "amount": tier["price_rub"],
    }


@app.post("/api/billing/check")
async def billing_check(user=Depends(require_user)):
    u = get_user(user["id"])
    inv_id = (u or {}).get("pending_invoice")
    if not inv_id or not CRYPTOBOT_TOKEN:
        return {"active": _sub_active(u), "paid": False, "days_left": _days_left(u)}
    import httpx

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(f"{CRYPTOBOT_API}/getInvoices",
                            params={"invoice_ids": str(inv_id)},
                            headers={"Crypto-Pay-API-Token": CRYPTOBOT_TOKEN})
            j = r.json()
    except Exception as e:
        return JSONResponse({"error": f"CryptoBot недоступен: {e}"}, status_code=502)
    items = (j.get("result") or {}).get("items") or []
    paid = any(it.get("status") == "paid" for it in items)
    if paid:
        bought = u.get("pending_tier") if (u.get("pending_tier") in TIERS) else _tier_key(u)
        _extend_subscription(user["id"], bought, TIERS[bought]["days"], clear_invoice=inv_id)
        u2 = get_user(user["id"])
        return {"active": True, "paid": True, "paid_until": u2.get("paid_until"), "days_left": _days_left(u2)}
    return {"active": _sub_active(u), "paid": False, "days_left": _days_left(u)}


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

    # Лимит аккаунтов по тарифу (админа не ограничиваем)
    if not user.get("is_admin"):
        tier = TIERS[_tier_key(user)]
        mine = [p for p in load_profiles() if p.get("owner") == user["id"]]
        if len(mine) >= tier["max_accounts"]:
            return JSONResponse(
                {"error": f"На тарифе «{tier['name']}» лимит аккаунтов: {tier['max_accounts']}. Нужен тариф повыше."},
                status_code=403,
            )

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
    low = text.lower()
    if "no limits" in low or "free as a bird" in low or "не ограничен" in low or "ограничения сняты" in low:
        verdict = "ok"
    elif "limited" in low or "ограничен" in low or "restrict" in low or "banned" in low or "заблокирован" in low:
        verdict = "limited"
    else:
        verdict = "unknown"
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
    await _destroy_profile(profile)
    save_profiles([p for p in load_profiles() if p["id"] != pid])
    save_schedules([s for s in load_schedules() if s["profile_id"] != pid])
    save_packs([p for p in load_packs() if p["profile_id"] != pid])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Вход в профиль
# ---------------------------------------------------------------------------
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
    if _on_cooldown(profile):
        return JSONResponse(
            {"error": f"Аккаунт на паузе из-за флуда. {profile.get('flood_note') or ''}".strip()},
            status_code=429,
        )
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    spin_err = _spin_issue(body.text)
    if spin_err:
        return JSONResponse({"error": spin_err}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)

    active = state.send_jobs.get(pid)
    if active and active.get("running"):
        return JSONResponse({"error": "Рассылка уже идёт — дождись окончания или нажми Стоп"}, status_code=409)

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

    # несколько чатов — отправляем в фоне с паузой между ними
    asyncio.create_task(_send_bulk_safe(pid, targets, body.text, body.gap_min, body.gap_max, source="ручная"))
    return {"ok": True, "started": len(targets)}


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
