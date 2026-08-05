"""Папка «Клиенты»: кто в неё попадает и что в ней сохраняется.

Ни одного обращения к реальным профилям и к Telegram — клиент подставной,
все записи на диск замоканы.
"""

import json
import unittest
from unittest.mock import patch

from telethon.tl.types import InputPeerUser, User

import web


def person(uid=555, username="klient", bot=False, first="Вася"):
    """Настоящий telethon-пользователь: имя и признак бота читаются как в бою."""
    return User(id=uid, bot=bot, username=username, first_name=first, access_hash=42)


def peer(uid):
    return InputPeerUser(user_id=uid, access_hash=42)


class Filter:
    """Папка Telegram в том виде, в каком её отдаёт GetDialogFilters."""

    def __init__(self, fid, title, include_peers=(), pinned=(), excluded=()):
        self.id = fid
        self.title = title
        self.include_peers = list(include_peers)
        self.pinned_peers = list(pinned)
        self.exclude_peers = list(excluded)


class FakeResult:
    def __init__(self, filters):
        self.filters = list(filters)


class FakeClient:
    """Подставной Telegram: помнит папки и то, что мы в них записали."""

    def __init__(self, filters=()):
        self.filters = list(filters)
        self.written = []

    async def __call__(self, request):
        if isinstance(request, web.GetDialogFiltersRequest):
            return FakeResult(self.filters)
        if isinstance(request, web.UpdateDialogFilterRequest):
            self.written.append(request)
            return True
        raise AssertionError(f"неожиданный запрос: {type(request).__name__}")

    async def get_input_entity(self, chat_id):
        return peer(int(chat_id))


class ListenerClient:
    """Собирает обработчики, которые вешает _register_response_listener."""

    def __init__(self):
        self.handlers = []

    def on(self, _builder):
        def deco(fn):
            self.handlers.append(fn)
            return fn
        return deco


class Event:
    def __init__(self, sender, chat_id=555, private=True):
        self.is_private = private
        self.chat_id = chat_id
        self._sender = sender

    async def get_sender(self):
        return self._sender


class ClientsFolderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.profiles = [{"id": "p1", "owner": "u1", "name": "Рабочий"}]
        self.notifications = []
        web.state.clients_folder_warn_at.clear()   # тесты не наследуют троттлинг
        self.patches = [
            patch.object(web, "load_profiles",
                         side_effect=lambda: json.loads(json.dumps(self.profiles))),
            patch.object(web, "save_profiles",
                         side_effect=lambda p: setattr(self, "profiles", p)),
            patch.object(web, "get_profile",
                         side_effect=lambda pid: next(
                             (json.loads(json.dumps(p)) for p in self.profiles
                              if p["id"] == pid), None)),
            patch.object(web, "_add_notification",
                         side_effect=lambda o, p, lvl, text:
                             self.notifications.append((lvl, text))),
        ]
        for p in self.patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patches])

    def clients(self):
        return self.profiles[0].get("clients") or {}

    async def sync(self, client):
        with patch.object(web, "get_client", return_value=client):
            return await web._sync_clients_folder("p1", "u1")

    # --- кого записываем в клиенты ---

    async def test_new_person_lands_in_the_folder(self):
        web._note_client("p1", 555, "Вася", "klient")
        client = FakeClient()
        self.assertEqual(await self.sync(client), 1)

        written = client.written[0]
        title = written.filter.title
        self.assertEqual(getattr(title, "text", title), web.CLIENTS_FOLDER_NAME)
        self.assertEqual([p.user_id for p in written.filter.include_peers], [555])
        self.assertTrue(self.clients()["555"]["in_folder"])
        self.assertTrue(any("Вася" in t for _, t in self.notifications))

    async def test_second_message_does_not_create_a_second_card(self):
        self.assertTrue(web._note_client("p1", 555, "Вася", "klient"))
        self.assertFalse(web._note_client("p1", 555, "Вася", "klient"))
        self.assertEqual(len(self.clients()), 1)

    async def test_person_already_in_folder_is_not_added_twice(self):
        web._note_client("p1", 555, "Вася", "klient")
        client = FakeClient([Filter(4, "Клиенты", include_peers=[peer(555)])])
        self.assertEqual(await self.sync(client), 0)

        self.assertEqual(client.written, [])          # папку не трогаем зря
        self.assertTrue(self.clients()["555"]["in_folder"])

    async def test_already_synced_person_does_not_reach_telegram(self):
        web._note_client("p1", 555, "Вася", "klient")
        await self.sync(FakeClient())
        client = FakeClient()
        self.assertEqual(await self.sync(client), 0)
        self.assertEqual(client.written, [])

    # --- что происходит с самой папкой ---

    async def test_existing_folder_keeps_its_content_and_id(self):
        web._note_client("p1", 777, "Петя", "petya")
        old = Filter(7, "Клиенты", include_peers=[peer(111)], pinned=[peer(222)])
        client = FakeClient([Filter(2, "Работа", include_peers=[peer(999)]), old])
        await self.sync(client)

        written = client.written[0]
        self.assertEqual(written.id, 7)               # ту же папку, не новую
        self.assertEqual([p.user_id for p in written.filter.include_peers], [111, 777])
        self.assertEqual([p.user_id for p in written.filter.pinned_peers], [222])

    async def test_new_folder_gets_a_free_id(self):
        web._note_client("p1", 555, "Вася", "klient")
        client = FakeClient([Filter(2, "Работа"), Filter(3, "На проверку")])
        await self.sync(client)
        self.assertEqual(client.written[0].id, 4)

    async def test_folder_link_with_same_name_is_not_overwritten(self):
        # Папка-ссылка (chatlist) списком чатов не управляется: её оставляем как есть.
        chatlist = Filter(5, "Клиенты")
        chatlist.include_peers = None
        web._note_client("p1", 555, "Вася", "klient")
        client = FakeClient([chatlist])
        await self.sync(client)
        self.assertNotEqual(client.written[0].id, 5)

    async def test_telegram_error_tells_the_owner(self):
        web._note_client("p1", 555, "Вася", "klient")

        class Broken(FakeClient):
            async def __call__(self, request):
                raise RuntimeError("FILTER_INCLUDE_TOO_MUCH")

        self.assertEqual(await self.sync(Broken()), 0)
        self.assertFalse(self.clients()["555"]["in_folder"])   # попробуем ещё раз позже
        self.assertTrue(any(lvl == "warn" for lvl, _ in self.notifications))

    # --- кто клиентом НЕ считается ---

    async def listen(self, event):
        client = ListenerClient()
        scheduled = []
        with patch.object(web, "_bump_response"), \
             patch.object(web, "_schedule_clients_sync",
                          side_effect=lambda pid, owner=None: scheduled.append(pid)):
            web._register_response_listener(client, "p1")
            await client.handlers[0](event)
        return scheduled

    async def test_private_message_makes_a_client(self):
        self.assertEqual(await self.listen(Event(person())), ["p1"])
        self.assertEqual(self.clients()["555"]["username"], "klient")

    async def test_group_message_is_not_a_client(self):
        self.assertEqual(await self.listen(Event(person(), chat_id=-100777, private=False)), [])
        self.assertEqual(self.clients(), {})

    async def test_bot_is_not_a_client(self):
        self.assertEqual(await self.listen(Event(person(uid=42, bot=True))), [])
        self.assertEqual(self.clients(), {})

    async def test_telegram_service_account_is_not_a_client(self):
        self.assertEqual(await self.listen(Event(person(uid=777000), chat_id=777000)), [])
        self.assertEqual(self.clients(), {})


if __name__ == "__main__":
    unittest.main()
