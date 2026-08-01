import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import web
from payment_audit_store import PaymentAuditStore
from payment_chat_archive import PaymentChatArchive, PaymentChatArchiveError


class PaymentArchiveWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PaymentAuditStore(
            os.path.join(self.tmp.name, "audit.sqlite3"),
            "test-secret",
            retention_days=0,
        )
        self.archive = PaymentChatArchive(
            os.path.join(self.tmp.name, "archives"),
            "c" * 64,
            min_free_bytes=0,
        )
        self.chat_key = self.store.chat_key("p1", 12345)
        self.case = self.store.record_event(
            event_key=self.store.event_key("p1", 12345, 2, "message"),
            owner="u1",
            profile_id="p1",
            chat_key=self.chat_key,
            message_ref=self.store.message_ref("p1", 12345, 2),
            chat_ref=12345,
            observed_at=datetime(2026, 8, 1, 10, 1, tzinfo=timezone.utc),
            direction="incoming",
            analysis={
                "score": 90,
                "categories": ["transfer_completed", "amount"],
                "amounts": [{"value": 5000, "currency": "RUB"}],
                "event_status": "completed",
                "income_claim": True,
            },
            snippet="скинул 5000 ₽",
            source="message",
        )
        image = b"\xff\xd8\xff" + b"receipt" * 10
        self.archive.merge(
            "u1",
            "p1",
            self.chat_key,
            [
                {"id": 1, "direction": "outgoing", "text": "Стоимость 5000 ₽"},
                {"id": 2, "direction": "incoming", "text": "Скинул, проверяйте", "has_media": True},
                {"id": 3, "direction": "outgoing", "text": "Получил, спасибо"},
            ],
            media=[{"message_id": 2, "mime": "image/jpeg", "data": image}],
        )
        web.state.audit_owner_locks.clear()
        web.state.audit_archive_tasks.clear()
        web.state.audit_deleted_owners.clear()
        web.state.audit_deleted_profiles.clear()

    async def asyncTearDown(self):
        self.tmp.cleanup()

    def app_patches(self):
        return (
            patch.object(web, "payment_audit_store", self.store),
            patch.object(web, "payment_chat_archive", self.archive),
            patch.object(web, "load_profiles", return_value=[{"id": "p1", "owner": "u1", "name": "Рабочий"}]),
            patch.object(web, "load_users", return_value=[{"id": "u1", "username": "worker"}]),
        )

    @staticmethod
    def work_user():
        return {
            "id": "u1",
            "status": "approved",
            "paid_until": "2099-01-01T00:00:00",
        }

    @staticmethod
    def trigger_event(message_id=10, chat_id=67890):
        return SimpleNamespace(
            id=message_id,
            chat_id=chat_id,
            raw_text="Скинул 7000 ₽",
            out=False,
            date=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
            edit_date=None,
            media=None,
            photo=None,
            file=None,
        )

    def record_kwargs(self, event):
        return {
            "event_key": self.store.event_key("p1", event.chat_id, event.id, "message"),
            "chat_key": self.store.chat_key("p1", event.chat_id),
            "message_ref": self.store.message_ref("p1", event.chat_id, event.id),
            "chat_ref": event.chat_id,
            "observed_at": event.date,
            "direction": "incoming",
            "analysis": {
                "score": 90,
                "categories": ["transfer_completed", "amount"],
                "amounts": [{"value": 7000, "currency": "RUB"}],
                "event_status": "completed",
                "income_claim": True,
            },
            "snippet": "скинул · 7000 ₽",
            "source": "message",
            "context": None,
        }

    async def test_peek_reads_complete_saved_chat_without_telegram(self):
        p1, p2, p3, p4 = self.app_patches()
        with p1, p2, p3, p4:
            response = await web.admin_payment_audit_peek(
                self.case["id"], admin={"id": "admin"}
            )

        payload = json.loads(response.body)
        self.assertTrue(payload["archived"])
        self.assertEqual([row["id"] for row in payload["messages"]], [1, 2, 3])
        self.assertEqual(payload["archive"]["status"], "ready")
        self.assertEqual(len(payload["photos"]), 1)
        self.assertIn("/archive/media/", payload["photos"][0]["url"])
        self.assertEqual(response.headers["cache-control"], "private, no-store")

    async def test_compact_removes_chat_but_keeps_amount_and_fact(self):
        p1, p2, p3, p4 = self.app_patches()
        with p1, p2, p3, p4:
            response = await web.admin_payment_archive_compact(
                self.case["id"], admin={"id": "admin"}
            )

        payload = json.loads(response.body)
        kept = self.store.get_case(self.case["id"])
        self.assertEqual(payload["archive"]["status"], "purged")
        self.assertEqual(payload["payment_facts_kept"], 1)
        self.assertEqual(kept["amounts"][0]["value"], 5000)
        self.assertEqual(kept["evidence"], [])
        self.assertEqual(
            self.archive.summary("u1", "p1", self.chat_key)["message_count"], 0
        )

    async def test_archive_failure_never_drops_the_compact_payment_fact(self):
        event = self.trigger_event()
        kwargs = self.record_kwargs(event)
        broken_archive = MagicMock(wraps=self.archive)
        broken_archive.merge.side_effect = PaymentChatArchiveError("disk full")
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "_get_payment_chat_archive_async", AsyncMock(return_value=broken_archive)),
        ):
            case = await web._record_payment_event(
                self.store,
                owner="u1",
                pid="p1",
                archive_seed={"chat_key": kwargs["chat_key"], "event": event},
                **kwargs,
            )

        self.assertEqual(case["amounts"][0]["value"], 7000)
        self.assertEqual(self.store.get_case(case["id"])["event_status"], "completed")

    async def test_encrypted_outbox_replays_case_after_db_crash_without_duplicate(self):
        event = self.trigger_event(message_id=11, chat_id=67891)
        kwargs = self.record_kwargs(event)
        crashing_store = MagicMock(wraps=self.store)
        crashing_store.record_event.side_effect = RuntimeError("simulated crash")
        common = (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "_get_payment_chat_archive_async", AsyncMock(return_value=self.archive)),
        )
        with common[0], common[1], common[2]:
            with self.assertRaises(RuntimeError):
                await web._record_payment_event(
                    crashing_store,
                    owner="u1",
                    pid="p1",
                    archive_seed={"chat_key": kwargs["chat_key"], "event": event},
                    **kwargs,
                )
        self.assertEqual(len(self.archive.list_case_outboxes()), 1)

        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "_get_payment_chat_archive_async", AsyncMock(return_value=self.archive)),
            patch.object(web, "_get_payment_audit_store_async", AsyncMock(return_value=self.store)),
            patch.object(web, "get_client", AsyncMock(return_value=None)),
        ):
            await web._resume_pending_payment_archives()
            await web._resume_pending_payment_archives()

        recovered = [
            case for case in self.store.list_cases(owner="u1", days=36500, limit=100)
            if case["chat_key"] == kwargs["chat_key"]
        ]
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["amounts"][0]["value"], 7000)
        self.assertEqual(self.archive.list_case_outboxes(), [])


if __name__ == "__main__":
    unittest.main()
