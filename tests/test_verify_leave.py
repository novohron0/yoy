"""Выход из чатов, которые ждут ручных действий.

Смысл кнопки — чтобы чат перестал мозолить глаза. Поэтому из списка и из
расписаний он уходит даже тогда, когда выйти не удалось: админ уже забанил
или чата больше нет.

Никаких реальных профилей: всё, что пишет на диск, замокано.
"""

import unittest
from unittest.mock import patch

import web


class Body:
    def __init__(self, ids=None):
        self.ids = ids


class FakeClient:
    def __init__(self, fails=()):
        self.fails = set(str(x) for x in fails)
        self.left = []

    async def is_user_authorized(self):
        return True

    async def delete_dialog(self, entity):
        if str(entity) in self.fails:
            raise RuntimeError("админ забанил")
        self.left.append(str(entity))


class VerifyLeaveTests(unittest.IsolatedAsyncioTestCase):
    async def leave(self, pending, ids=None, fails=()):
        self.unmarked, self.schedules_cleaned = [], []
        client = FakeClient(fails)
        with patch.object(web, "_owned_profile"), \
             patch.object(web, "_verify_chats", return_value=dict(pending)), \
             patch.object(web, "get_client", return_value=client), \
             patch.object(web, "_resolve", side_effect=lambda pid, cid: cid), \
             patch.object(web, "_remove_chat_from_schedules",
                          side_effect=lambda pid, cid: self.schedules_cleaned.append(str(cid))), \
             patch.object(web, "_unmark_verify_chats",
                          side_effect=lambda pid, ids: self.unmarked.extend(ids or [])), \
             patch.object(web, "_track_audit_task", side_effect=lambda coro: coro.close()), \
             patch.object(web.random, "uniform", return_value=0):
            result = await web.verify_chats_leave("p1", Body(ids), user={"id": "u1"})
        self.client = client
        return result

    async def test_leaving_one_chat_cleans_it_everywhere(self):
        result = await self.leave({"-100111": {}, "-100222": {}}, ids=["-100111"])
        self.assertEqual(result["left"], 1)
        self.assertEqual(self.client.left, ["-100111"])
        self.assertEqual(self.unmarked, ["-100111"])
        self.assertEqual(self.schedules_cleaned, ["-100111"])

    async def test_banned_chat_still_disappears_from_the_list(self):
        result = await self.leave({"-100111": {}}, fails=["-100111"])
        self.assertEqual(result["left"], 0)
        self.assertEqual(result["cleaned"], 1, "выйти не вышло — но из списка убрали")
        self.assertEqual(self.unmarked, ["-100111"])
        self.assertEqual(self.schedules_cleaned, ["-100111"])

    async def test_leave_all_takes_every_pending_chat(self):
        pending = {"-100111": {}, "-100222": {}, "-100333": {}}
        result = await self.leave(pending)
        self.assertEqual(result["left"], 3)
        self.assertEqual(sorted(self.unmarked), ["-100111", "-100222", "-100333"])

    async def test_unknown_id_is_ignored(self):
        result = await self.leave({"-100111": {}}, ids=["-100999"])
        self.assertEqual(result["left"], 0)
        self.assertEqual(self.unmarked, [])
        self.assertEqual(self.client.left, [])

    async def test_empty_list_does_not_touch_telegram(self):
        result = await self.leave({}, ids=None)
        self.assertEqual((result["left"], result["cleaned"]), (0, 0))
        self.assertEqual(self.client.left, [])


if __name__ == "__main__":
    unittest.main()
