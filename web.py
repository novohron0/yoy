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
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from telethon import TelegramClient, utils
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.types import User, Chat, Channel
from telethon.errors import (
    ApiIdInvalidError,
    FloodWaitError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    SessionPasswordNeededError,
)

# --- Пути ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")
PROFILES_JSON = os.path.join(PROFILES_DIR, "profiles.json")
SCHEDULES_JSON = os.path.join(PROFILES_DIR, "schedules.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(PROFILES_DIR, exist_ok=True)


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


async def _fire_rule(rule):
    """Отправляет сообщение правила по всем его чатам."""
    pid = rule["profile_id"]
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return
    for target in rule.get("targets", []):
        try:
            entity = await _resolve(pid, target["id"])
            await client.send_message(entity, rule["text"])
        except Exception as e:
            print(f"[scheduler] не удалось отправить в {target.get('name')}: {e}")


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


class ScheduleIn(BaseModel):
    targets: list[Target]
    text: str
    time: str               # "HH:MM"
    weekdays: list[int] = []  # 0=Пн ... 6=Вс
    dates: list[str] = []     # ["YYYY-MM-DD", ...]


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


@app.get("/api/profiles")
async def list_profiles():
    out = []
    for p in load_profiles():
        try:
            client = await get_client(p["id"])
            authorized = bool(client and await client.is_user_authorized())
        except Exception:
            authorized = False
        out.append({"id": p["id"], "name": p["name"], "authorized": authorized})
    return {"profiles": out}


@app.post("/api/profiles")
async def create_profile(body: CreateProfileIn):
    name = body.name.strip() or "Аккаунт"
    api_id = body.api_id.strip()
    api_hash = body.api_hash.strip()
    if not api_id.isdigit():
        return JSONResponse({"error": "api_id должен состоять только из цифр"}, status_code=400)
    if not _valid_hash(api_hash):
        return JSONResponse({"error": "api_hash должен быть ровно 32 hex-символа"}, status_code=400)

    pid = uuid.uuid4().hex[:8]
    profiles = load_profiles()
    profiles.append({"id": pid, "name": name, "api_id": int(api_id), "api_hash": api_hash})
    save_profiles(profiles)
    state.login[pid] = {"phone": None, "phone_code_hash": None}
    return {"id": pid, "step": "phone"}


@app.get("/api/profiles/{pid}/status")
async def profile_status(pid: str):
    if get_profile(pid) is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)
    step = await _profile_status(pid)
    if step == "ready":
        client = await get_client(pid)
        me = await client.get_me()
        return {"step": "ready", "me": {"id": me.id, "name": me.first_name or "", "username": me.username or ""}}
    return {"step": step}


@app.delete("/api/profiles/{pid}")
async def delete_profile(pid: str):
    profile = get_profile(pid)
    if profile is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)

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

    # Удаляем файлы сессии
    for suffix in (".session", ".session-journal"):
        path = _session_path(profile) + suffix
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    save_profiles([p for p in load_profiles() if p["id"] != pid])
    save_schedules([s for s in load_schedules() if s["profile_id"] != pid])
    state.login.pop(pid, None)
    state.entities.pop(pid, None)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Вход в профиль
# ---------------------------------------------------------------------------
@app.post("/api/profiles/{pid}/login/send_code")
async def send_code(pid: str, body: PhoneIn):
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
async def sign_in(pid: str, body: CodeIn):
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
async def login_password(pid: str, body: PasswordIn):
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
# Поиск чатов
# ---------------------------------------------------------------------------
@app.get("/api/profiles/{pid}/search")
async def search(pid: str, q: str = ""):
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
async def send_now(pid: str, body: SendIn):
    client = await get_client(pid)
    if client is None or not await client.is_user_authorized():
        return JSONResponse({"error": "Не авторизован"}, status_code=401)
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)

    sent, errors = [], []
    for t in body.targets:
        try:
            entity = await _resolve(pid, t.id)
            await client.send_message(entity, body.text)
            sent.append(t.name)
        except Exception as e:
            errors.append(f"{t.name}: {e}")
    return {"ok": True, "sent": sent, "errors": errors}


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
async def get_schedules(pid: str):
    return {"schedules": [s for s in load_schedules() if s["profile_id"] == pid]}


@app.post("/api/profiles/{pid}/schedules")
async def create_schedule(pid: str, body: ScheduleIn):
    if get_profile(pid) is None:
        return JSONResponse({"error": "Профиль не найден"}, status_code=404)
    if not body.text.strip():
        return JSONResponse({"error": "Пустое сообщение"}, status_code=400)
    if not body.targets:
        return JSONResponse({"error": "Не выбран ни один чат"}, status_code=400)
    if not _validate_time(body.time):
        return JSONResponse({"error": "Неверное время (нужен формат ЧЧ:ММ)"}, status_code=400)

    rule = {
        "id": uuid.uuid4().hex[:8],
        "profile_id": pid,
        "targets": [t.model_dump() for t in body.targets],
        "text": body.text,
        "time": body.time,
        "weekdays": sorted(set(w for w in body.weekdays if 0 <= w <= 6)),
        "dates": sorted(set(body.dates)),
        "enabled": True,
        "last_fired": None,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    schedules = load_schedules()
    schedules.append(rule)
    save_schedules(schedules)
    return {"ok": True, "schedule": rule}


@app.delete("/api/profiles/{pid}/schedules/{sid}")
async def delete_schedule(pid: str, sid: str):
    schedules = load_schedules()
    new = [s for s in schedules if not (s["id"] == sid and s["profile_id"] == pid)]
    if len(new) == len(schedules):
        return JSONResponse({"error": "Расписание не найдено"}, status_code=404)
    save_schedules(new)
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

    print("Открой веб-панель: http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
