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
    scheduler_task = None


state = State()


def _session_path(profile):
    # Сессии лежат в profiles/<id>
    return os.path.join(PROFILES_DIR, profile["id"])


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

    client = TelegramClient(_session_path(profile), profile["api_id"], profile["api_hash"])
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


async def _send_one(client, pid, target, text):
    """Отправляет одно сообщение. Возвращает ('ok'|'flood'|'spam'|'error', detail)."""
    try:
        entity = await _resolve(pid, target["id"])
        await client.send_message(entity, text)
        return "ok", None
    except FloodWaitError as e:
        wait = e.seconds + 30  # запас сверху
        _set_cooldown(pid, wait, note=f"Пауза {e.seconds}с — Telegram просит притормозить (FloodWait).")
        print(f"[flood] профиль {pid}: FloodWait {e.seconds}s → пауза до отправки")
        return "flood", e.seconds
    except PeerFloodError:
        _set_cooldown(pid, 6 * 3600, note="Telegram пометил аккаунт как спам. Отправки остановлены на 6 ч — снизь частоту.", flagged=True)
        print(f"[flood] профиль {pid}: PeerFloodError (спам-флаг) → длинная пауза + флаг")
        return "spam", None
    except Exception as e:
        print(f"[scheduler] не удалось отправить в {target.get('name')}: {e}")
        return "error", str(e)


async def _send_bulk(pid, targets, text, gap_lo=None, gap_hi=None):
    """Последовательная отправка по чатам с паузой между ними и защитой от флуда."""
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return
    n = len(targets)
    for i, target in enumerate(targets):
        if _on_cooldown(get_profile(pid)):
            return
        status, _ = await _send_one(client, pid, target, text)
        if status in ("flood", "spam"):
            return  # профиль на паузе — дальше не шлём
        if i < n - 1:
            await asyncio.sleep(_send_gap(gap_lo, gap_hi))


async def _send_bulk_safe(pid, targets, text, gap_lo=None, gap_hi=None):
    try:
        await _send_bulk(pid, targets, text, gap_lo, gap_hi)
    except Exception as e:
        print(f"[send] фоновая отправка {pid}: {e}")


async def _fire_rule(rule):
    """Отправляет сообщение правила по всем его чатам, с защитой от флуда."""
    pid = rule["profile_id"]
    if _on_cooldown(get_profile(pid)):
        return
    await _send_bulk(pid, rule.get("targets", []), rule["text"],
                     rule.get("gap_min"), rule.get("gap_max"))


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.scheduler_task = asyncio.create_task(_scheduler_loop())
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
            client = TelegramClient(_session_path(profile), profile["api_id"], profile["api_hash"])
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

    pid = uuid.uuid4().hex[:8]
    profiles = load_profiles()
    profiles.append({"id": pid, "name": name, "api_id": int(api_id), "api_hash": api_hash, "owner": user["id"]})
    save_profiles(profiles)
    state.login[pid] = {"phone": None, "phone_code_hash": None}
    return {"id": pid, "step": "phone"}


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
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)

    targets = [{"id": t.id, "name": t.name, "kind": t.kind} for t in body.targets]
    if len(targets) == 1:
        # один чат — шлём сразу, чтобы дать мгновенный ответ
        status, detail = await _send_one(client, pid, targets[0], body.text)
        if status == "flood":
            return {"ok": True, "sent": [], "paused": f"Telegram просит подождать {detail}с."}
        if status == "spam":
            return {"ok": True, "sent": [], "paused": "Telegram пометил аккаунт как спам."}
        if status == "error":
            return {"ok": True, "sent": [], "errors": [f"{targets[0]['name']}: {detail}"]}
        return {"ok": True, "sent": [targets[0]["name"]], "errors": []}

    # несколько чатов — отправляем в фоне с паузой между ними
    asyncio.create_task(_send_bulk_safe(pid, targets, body.text, body.gap_min, body.gap_max))
    return {"ok": True, "started": len(targets)}


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


@app.post("/api/profiles/{pid}/schedules")
async def create_schedule(pid: str, body: ScheduleIn, user=Depends(require_active)):
    _owned_profile(pid, user)
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)

    rule = {
        "id": uuid.uuid4().hex[:8],
        "profile_id": pid,
        "owner": user["id"],
        "targets": [t.model_dump() for t in body.targets],
        "text": body.text,
        "enabled": True,
        "last_fired": None,
        "gap_min": body.gap_min,
        "gap_max": body.gap_max,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

    if body.interval_min is not None:
        # Режим «каждые N минут» (опционально случайно в диапазоне)
        lo = int(body.interval_min)
        hi = int(body.interval_max) if body.interval_max is not None else lo
        if lo < 1:
            return JSONResponse({"error": "Минимальный интервал — 1 минута"}, status_code=400)
        if hi < lo:
            hi = lo
        rule["interval_min"] = lo
        rule["interval_max"] = hi
        rule["next_fire"] = None   # None → отправит на ближайшем тике (сразу)
    else:
        # Режим «по времени»
        if not _validate_time(body.time):
            return JSONResponse({"error": "Неверное время (нужен формат ЧЧ:ММ)"}, status_code=400)
        rule["time"] = body.time
        rule["weekdays"] = sorted(set(w for w in body.weekdays if 0 <= w <= 6))
        rule["dates"] = sorted(set(body.dates))

    schedules = load_schedules()
    schedules.append(rule)
    save_schedules(schedules)
    return {"ok": True, "schedule": rule}


@app.delete("/api/profiles/{pid}/schedules/{sid}")
async def delete_schedule(pid: str, sid: str, user=Depends(require_user)):
    _owned_profile(pid, user)
    schedules = load_schedules()
    new = [s for s in schedules if not (s["id"] == sid and s["profile_id"] == pid)]
    if len(new) == len(schedules):
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    save_schedules(new)
    return {"ok": True}


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
