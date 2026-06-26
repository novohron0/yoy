#!/usr/bin/env python3
"""
Telegram userbot — «зеркало» личного аккаунта через терминал.

Что делает:
  1. При первом запуске спрашивает api_id, api_hash, номер телефона.
  2. Telegram присылает код -> вводишь его в терминале (если есть 2FA — пароль).
  3. Создаётся файл сессии (.session) — повторно код вводить не нужно.
  4. Показывает список последних чатов, ты выбираешь один.
  5. Показывает историю чата + входящие сообщения в реальном времени.
  6. Всё, что напишешь в терминал, отправляется в этот чат от твоего имени.

Команды внутри чата:
  /chats   — вернуться к списку чатов и выбрать другой
  /history — показать ещё 20 сообщений истории
  /quit    — выход
  (любой другой текст) — отправляется в текущий чат
"""

import asyncio
import os
import sys

from telethon import TelegramClient, events
from telethon.errors import ApiIdInvalidError, SessionPasswordNeededError

# Файлы конфигурации/сессии лежат рядом со скриптом
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_NAME = os.path.join(BASE_DIR, "user_session")
SESSION_FILE = SESSION_NAME + ".session"
CONFIG_FILE = os.path.join(BASE_DIR, ".credentials")


def _valid_hash(value):
    """api_hash должен быть ровно 32 hex-символа."""
    hex_chars = set("0123456789abcdefABCDEF")
    return bool(value) and len(value) == 32 and all(c in hex_chars for c in value)


def reset_saved_data():
    """Удаляет сохранённые ключи и сессию — полный сброс."""
    removed = []
    for path in (CONFIG_FILE, SESSION_FILE):
        if os.path.exists(path):
            os.remove(path)
            removed.append(os.path.basename(path))
    print("Сброшено:", ", ".join(removed) if removed else "нечего удалять")


def load_or_ask_credentials():
    """Читает api_id/api_hash из .credentials либо спрашивает и сохраняет."""
    api_id = api_hash = None

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    if key == "api_id":
                        api_id = value
                    elif key == "api_hash":
                        api_hash = value
        # Проверяем формат загруженных значений. Если файл битый —
        # удаляем его и спрашиваем заново (иначе будет ApiIdInvalidError).
        if not (api_id and api_id.isdigit() and _valid_hash(api_hash)):
            print("⚠️  Сохранённые api_id/api_hash имеют неверный формат — спрошу заново.\n")
            os.remove(CONFIG_FILE)
            api_id = api_hash = None

    if not api_id or not api_hash:
        print("Получи api_id и api_hash здесь: https://my.telegram.org -> API development tools\n")
        # api_id — целое число; api_hash — ровно 32 hex-символа.
        # Проверяем формат сразу, чтобы не получить ApiIdInvalidError от Telegram.
        while True:
            api_id = input("Введи api_id (число): ").strip()
            if api_id.isdigit():
                break
            print("  ✗ api_id должен состоять только из цифр. Попробуй ещё раз.")
        while True:
            api_hash = input("Введи api_hash (32 hex-символа): ").strip()
            if _valid_hash(api_hash):
                break
            hex_chars = set("0123456789abcdefABCDEF")
            bad = [c for c in api_hash if c not in hex_chars]
            reason = (
                f"длина {len(api_hash)}, а нужно 32"
                if len(api_hash) != 32
                else f"есть недопустимые символы: {bad}"
            )
            print(f"  ✗ Неверный api_hash ({reason}). Скопируй заново с my.telegram.org.")
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(f"api_id={api_id}\n")
            f.write(f"api_hash={api_hash}\n")
        # Чуть-чуть безопасности: файл доступен только владельцу
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
        print("Сохранил в .credentials (повторно вводить не нужно).\n")

    return int(api_id), api_hash


async def choose_chat(client):
    """Показывает список последних диалогов и возвращает выбранную сущность."""
    dialogs = await client.get_dialogs(limit=30)

    print("\n=== Твои чаты ===")
    for i, d in enumerate(dialogs, start=1):
        kind = "👤" if d.is_user else ("👥" if d.is_group else "📢")
        unread = f" ({d.unread_count} непрочит.)" if d.unread_count else ""
        print(f"  {i:>2}. {kind} {d.name}{unread}")
    print("=================")

    while True:
        choice = input("Введи номер чата (или username/ID): ").strip()
        if not choice:
            continue
        # Номер из списка
        if choice.isdigit() and 1 <= int(choice) <= len(dialogs):
            return dialogs[int(choice) - 1].entity
        # Иначе пробуем как username / числовой ID
        try:
            target = int(choice) if choice.lstrip("-").isdigit() else choice
            return await client.get_entity(target)
        except Exception as e:
            print(f"Не нашёл такой чат: {e}. Попробуй ещё раз.")


async def print_history(client, entity, limit=20):
    """Печатает последние сообщения чата (от старых к новым)."""
    messages = await client.get_messages(entity, limit=limit)
    print(f"\n--- последние {len(messages)} сообщений ---")
    for msg in reversed(messages):
        if not msg.message:
            continue
        sender = "Я" if msg.out else (msg.sender.first_name if msg.sender else "?")
        ts = msg.date.strftime("%H:%M")
        print(f"[{ts}] {sender}: {msg.message}")
    print("--- конец истории ---\n")


async def main():
    api_id, api_hash = load_or_ask_credentials()
    client = TelegramClient(SESSION_NAME, api_id, api_hash)

    # Подключение + авторизация (код из Telegram спросит сам)
    try:
        await client.start(
            phone=lambda: input("Введи номер телефона (в формате +7...): ").strip(),
            code_callback=lambda: input("Введи код из Telegram: ").strip(),
            password=lambda: input("Введи пароль 2FA (если есть): ").strip(),
        )
    except ApiIdInvalidError:
        print(
            "\n❌ Telegram отверг api_id/api_hash как неверные.\n"
            "   Формат правильный, но сама пара не подходит. Частые причины:\n"
            "   • api_hash скопирован не полностью или с лишним символом;\n"
            "   • api_id и api_hash взяты от РАЗНЫХ приложений (должны быть с одной\n"
            "     страницы my.telegram.org → API development tools);\n"
            "   • опечатка в одном символе.\n\n"
            "   Удаляю сохранённые ключи. Запусти скрипт снова и введи их заново,\n"
            "   аккуратно скопировав ОБА значения с одной страницы.\n"
        )
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        await client.disconnect()
        return

    me = await client.get_me()
    print(f"\n✅ Вошли как: {me.first_name} (@{me.username})  id={me.id}")

    # Текущий выбранный чат хранится в изменяемом контейнере,
    # чтобы обработчик входящих видел актуальное значение.
    current = {"entity": None}

    @client.on(events.NewMessage(incoming=True))
    async def on_incoming(event):
        ent = current["entity"]
        if ent is None:
            return
        # Показываем только сообщения из выбранного чата
        if event.chat_id != getattr(ent, "id", None) and event.chat_id != (
            await event.get_chat()
        ).id:
            return
        sender = await event.get_sender()
        name = getattr(sender, "first_name", None) or "?"
        ts = event.message.date.strftime("%H:%M")
        print(f"\r[{ts}] {name}: {event.message.message}\n> ", end="", flush=True)

    # Основной цикл: выбор чата -> переписка
    while True:
        current["entity"] = await choose_chat(client)
        entity = current["entity"]
        title = getattr(entity, "first_name", None) or getattr(entity, "title", "чат")
        print(f"\n💬 Открыт чат: {title}")
        print("Команды: /chats — др. чат, /history — ещё история, /quit — выход\n")

        await print_history(client, entity)

        in_chat = True
        while in_chat:
            # input() блокирующий — выносим в отдельный поток, чтобы не вешать asyncio
            text = await asyncio.to_thread(input, "> ")
            text = text.strip()
            if not text:
                continue
            if text == "/quit":
                print("Пока 👋")
                await client.disconnect()
                return
            if text == "/chats":
                in_chat = False
                break
            if text == "/history":
                await print_history(client, entity)
                continue
            # Обычный текст -> отправляем в чат
            await client.send_message(entity, text)


if __name__ == "__main__":
    # `python userbot.py --reset` — стереть сохранённые ключи и сессию
    if "--reset" in sys.argv:
        reset_saved_data()
        sys.exit(0)
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        print("\nВыход.")
        sys.exit(0)
