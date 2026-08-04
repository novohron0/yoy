"""Цикл вступления: куда попадает каждая ссылка и когда бот отходит.

Ни одного обращения к реальным профилям и к Telegram — клиент подставной,
все записи на диск замоканы.
"""

import unittest
from datetime import datetime
from unittest.mock import patch

from telethon.tl.types import Channel, ChatBannedRights

import web


def chat(chat_id=777, username="chatone", muted_for_all=False, broadcast=False):
    """Настоящий telethon-канал: id и права читаются как в бою."""
    rights = ChatBannedRights(until_date=None, send_messages=True) if muted_for_all else None
    return Channel(
        id=chat_id, title="Чат", photo=None, date=datetime.now(), creator=False,
        left=False, broadcast=broadcast, verified=False, megagroup=not broadcast,
        restricted=False, signatures=False, min=False, scam=False, has_link=False,
        has_geo=False, slowmode_enabled=False, access_hash=123, username=username,
        default_banned_rights=rights,
    )


class FakeUpdates:
    def __init__(self, chats):
        self.chats = chats


class FakeClient:
    """Отдаёт заранее заданный результат на каждую ссылку по порядку."""

    def __init__(self, outcomes, participant=None):
        self.outcomes = list(outcomes)
        self.participant = participant
        self.calls = 0

    async def is_user_authorized(self):
        return True

    async def iter_dialogs(self):
        return
        yield   # pragma: no cover — генератор без единого элемента

    async def get_entity(self, val):
        return chat(username=val)

    async def __call__(self, request):
        if type(request).__name__ == "GetParticipantRequest":
            return FakeUpdates([]) if self.participant is None else \
                type("R", (), {"participant": self.participant})()
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def error(name):
    return type(name, (Exception,), {})()


class JoinJobTests(unittest.IsolatedAsyncioTestCase):
    async def run_job(self, links, outcomes, participant=None):
        pid = "p-test"
        client = FakeClient(outcomes, participant)
        web.state.join_jobs[pid] = {
            "total": len(links), "done": 0,
            "joined": [], "skipped": [], "failed": [], "verify": [], "requests": [],
            "running": True, "cancel": False, "status": "running",
        }
        self.marked, self.notes, self.folder = [], [], []
        # get_client — async, patch.object подставит AsyncMock сам.
        with patch.object(web, "get_client", return_value=client), \
             patch.object(web, "get_profile", return_value={"owner": "u1", "name": "тест"}), \
             patch.object(web, "_wu_allow", return_value=True), \
             patch.object(web, "_cache"), \
             patch.object(web, "JOIN_GAP_MIN", 0), patch.object(web, "JOIN_GAP_MAX", 0), \
             patch.object(web, "JOIN_CHECK_DELAY", 0), \
             patch.object(web, "_mark_chat_for_verify",
                          side_effect=lambda *a: self.marked.append(a) or True), \
             patch.object(web, "_add_notification",
                          side_effect=lambda *a: self.notes.append(a)), \
             patch.object(web, "_track_audit_task",
                          side_effect=lambda coro: (coro.close(), self.folder.append(1))):
            await web._join_job(pid, links)
        return web.state.join_jobs.pop(pid)

    async def test_captcha_chat_goes_to_the_verify_folder_not_to_joined(self):
        job = await self.run_job(["@chatone"], [FakeUpdates([chat(muted_for_all=True)])])
        self.assertEqual(job["joined"], [])
        self.assertEqual(len(job["verify"]), 1)
        self.assertTrue(self.marked, "чат должен уехать в «На проверку»")
        self.assertTrue(self.folder, "папку в Telegram надо обновить")

    async def test_normal_chat_counts_as_joined(self):
        job = await self.run_job(["@chatone"], [FakeUpdates([chat()])])
        self.assertEqual(len(job["joined"]), 1)
        self.assertEqual(job["verify"], [])
        self.assertFalse(self.marked)

    async def test_join_request_is_its_own_bucket(self):
        job = await self.run_job(["@chatone"], [error("InviteRequestSentError")])
        self.assertEqual(len(job["requests"]), 1)
        self.assertEqual(job["failed"], [])

    async def test_account_block_stops_the_run_and_spares_the_rest(self):
        links = ["@chatone", "@chattwo", "@chatthree"]
        job = await self.run_job(links, [FakeUpdates([chat()]),
                                         error("PeerFloodError")])
        self.assertEqual(len(job["joined"]), 1)
        self.assertEqual(job["done"], 1, "оставшиеся ссылки не тронуты")
        self.assertIn("остановлено", job["status"])
        self.assertTrue(self.notes, "владельцу надо сказать, почему встали")
        self.assertIn("2", self.notes[0][3], "в тексте — сколько ссылок осталось")

    async def test_dead_link_does_not_stop_the_run(self):
        job = await self.run_job(["@chatone", "@chattwo"], [error("InviteHashExpiredError"),
                                                FakeUpdates([chat()])])
        self.assertEqual(job["done"], 2)
        self.assertEqual(len(job["failed"]), 1)
        self.assertEqual(len(job["joined"]), 1)
        self.assertEqual(job["status"], "готово")

    async def test_already_member_is_a_skip_not_a_failure(self):
        job = await self.run_job(["@chatone"], [error("UserAlreadyParticipantError")])
        self.assertEqual(len(job["skipped"]), 1)
        self.assertEqual(job["failed"], [])


if __name__ == "__main__":
    unittest.main()
