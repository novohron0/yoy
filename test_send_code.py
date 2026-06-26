#!/usr/bin/env python3
"""
Диагностика отправки кода входа — отдельно от веб-панели.

Что делает:
  • поднимает тот же профиль из profiles/, что и web.py;
  • включает ПОЛНЫЙ DEBUG-лог Telethon (видно каждый MTProto-запрос/ответ);
  • подключается и проверяет, авторизована ли уже сессия;
  • если передан телефон — запрашивает код и подробно печатает, КУДА Telegram его отправил
    (приложение / SMS / звонок), таймаут и следующий доступный способ.

Запуск:
    # только проверить подключение и api_id/api_hash, БЕЗ отправки кода:
    .venv/bin/python test_send_code.py 45ab27cc

    # реально запросить код (укажи телефон в межд. формате):
    .venv/bin/python test_send_code.py 45ab27cc +79991234567

    # попробовать ПРИНУДИТЕЛЬНО SMS (добавь sms третьим аргументом):
    .venv/bin/python test_send_code.py 45ab27cc +79991234567 sms

Важно: каждый запрос кода Telegram считает; не дёргай часто — поймаешь FloodWait.
"""

import asyncio
import json
import logging
import os
import sys

from telethon import TelegramClient
from telethon.errors import FloodWaitError, RPCError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")
PROFILES_JSON = os.path.join(PROFILES_DIR, "profiles.json")

# --- Полное логирование: и Telethon, и наши сообщения ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-7s  %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("test_send_code")


def load_profile(pid):
    with open(PROFILES_JSON, "r", encoding="utf-8") as f:
        for p in json.load(f)["profiles"]:
            if p["id"] == pid:
                return p
    return None


async def main():
    if len(sys.argv) < 2:
        print("Использование: python test_send_code.py <profile_id> [phone]")
        return

    pid = sys.argv[1]
    phone = sys.argv[2].strip() if len(sys.argv) > 2 else None
    force_sms = len(sys.argv) > 3 and sys.argv[3].lower() == "sms"

    profile = load_profile(pid)
    if profile is None:
        log.error("Профиль %s не найден в %s", pid, PROFILES_JSON)
        return

    log.info("Профиль: id=%s name=%r api_id=%s", profile["id"], profile["name"], profile["api_id"])
    session_path = os.path.join(PROFILES_DIR, profile["id"])
    client = TelegramClient(session_path, profile["api_id"], profile["api_hash"])

    log.info("Подключаюсь к Telegram…")
    await client.connect()
    log.info("connected=%s", client.is_connected())

    authorized = await client.is_user_authorized()
    log.info("is_user_authorized=%s", authorized)
    if authorized:
        me = await client.get_me()
        log.info("Уже вошли как: %s (@%s) id=%s", me.first_name, me.username, me.id)
        await client.disconnect()
        return

    if not phone:
        log.info("Телефон не передан — код НЕ запрашиваю. Чтобы отправить код, добавь телефон вторым аргументом.")
        await client.disconnect()
        return

    log.info("Запрашиваю код для %s … (force_sms=%s)", phone, force_sms)
    try:
        sent = await client.send_code_request(phone, force_sms=force_sms)
    except FloodWaitError as e:
        log.error("FLOOD WAIT: Telegram просит подождать %s секунд (слишком частые запросы кода).", e.seconds)
        await client.disconnect()
        return
    except RPCError as e:
        log.error("RPCError: %s: %s", type(e).__name__, e)
        await client.disconnect()
        return

    code_type = type(sent.type).__name__
    next_type = type(sent.next_type).__name__ if sent.next_type else None
    where = {
        "SentCodeTypeApp": "В ПРИЛОЖЕНИЕ Telegram (служебный чат «Telegram»), НЕ по SMS",
        "SentCodeTypeSms": "по SMS",
        "SentCodeTypeCall": "звонком",
        "SentCodeTypeFlashCall": "флеш-звонком",
        "SentCodeTypeMissedCall": "пропущенным звонком",
        "SentCodeTypeEmailCode": "на e-mail",
    }.get(code_type, code_type)

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТ ОТПРАВКИ КОДА")
    print("=" * 60)
    print(f"  Куда отправлен:   {where}")
    print(f"  type:             {code_type}")
    print(f"  next_type:        {next_type}  (резервный способ, если этот не дошёл)")
    print(f"  длина кода:       {getattr(sent.type, 'length', '?')}")
    print(f"  phone_code_hash:  {sent.phone_code_hash}")
    print("=" * 60)
    if code_type == "SentCodeTypeApp":
        print("  ⚠️  Код пришёл ВНУТРИ Telegram — ищи его в чате «Telegram» (служебные")
        print("      сообщения), а не в SMS. Это нормально для уже залогиненного номера.")
    print()

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
