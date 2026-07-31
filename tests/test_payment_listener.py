import asyncio
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import web


class FakeEvent:
    def __init__(self, text="Скинул 5 000 ₽ по СБП", *, private=True, outgoing=False,
                 media_type=None, forwarded=False):
        self.is_private = private
        self.chat_id = 12345
        self.id = 77
        self.out = outgoing
        self.raw_text = text
        self.date = datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc)
        self.photo = object() if media_type == "image/jpeg" else None
        self.file = SimpleNamespace(mime_type=media_type, size=1024) if media_type else None
        self.message = SimpleNamespace(fwd_from=object() if forwarded else None, edit_date=None)


class PaymentListenerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        for task in list(web.state.audit_ocr_tasks):
            task.cancel()
        web.state.audit_ocr_tasks.clear()
        web.state.audit_ocr_recent.clear()
        web.state.audit_ocr_dropped = {"queue": 0, "quota": 0, "invalid": 0}
        web.state.audit_deleted_owners.clear()
        web.state.audit_deleted_profiles.clear()
        web.state.audit_owner_locks.clear()
        web.state.audit_ocr_semaphore = None

    def work_user(self, **extra):
        """Одобренный рабочий пользователь: проверка оплат включена для всех таких."""
        base = {
            "id": "u1",
            "status": "approved",
            "paid_until": "2099-01-01T00:00:00",
        }
        base.update(extra)
        return base

    async def test_records_detected_private_payment_signal(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        event = FakeEvent()
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(MagicMock(), "p1", event)

        store.record_event.assert_called_once()
        kwargs = store.record_event.call_args.kwargs
        self.assertEqual(kwargs["owner"], "u1")
        self.assertEqual(kwargs["direction"], "incoming")
        self.assertIn("transfer_completed", kwargs["analysis"]["categories"])
        self.assertTrue(kwargs["analysis"]["income_claim"])

    async def test_stores_only_detector_evidence_not_the_full_message(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        event = FakeEvent("Скинул 5 000 ₽ по СБП. Секретная лишняя переписка")
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(MagicMock(), "p1", event)

        snippet = store.record_event.call_args.kwargs["snippet"]
        self.assertIn("скинул", snippet.casefold())
        self.assertIn("5 000 ₽", snippet)
        self.assertNotIn("Секретная", snippet)

    async def test_outgoing_sent_money_is_not_income(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(
                MagicMock(), "p1", FakeEvent("Скинул 5 000 ₽ по СБП", outgoing=True)
            )

        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertFalse(analysis["income_claim"])
        self.assertIn("outgoing_transfer", analysis["categories"])
        self.assertLessEqual(analysis["confidence"], 0.45)

    async def test_does_not_read_for_user_not_approved_by_admin(self):
        store = MagicMock()
        user = self.work_user(status="pending")
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=user),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "analyze_payment_signal") as detector,
        ):
            await web._handle_payment_message(MagicMock(), "p1", FakeEvent())

        detector.assert_not_called()
        store.record_event.assert_not_called()

    async def test_does_not_read_when_subscription_expired(self):
        store = MagicMock()
        user = self.work_user(paid_until="2020-01-01T00:00:00")
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=user),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "analyze_payment_signal") as detector,
        ):
            await web._handle_payment_message(MagicMock(), "p1", FakeEvent())

        detector.assert_not_called()
        store.record_event.assert_not_called()

    async def test_ignores_groups_and_telegram_service_chat(self):
        store = MagicMock()
        for event in (FakeEvent(private=False), FakeEvent()):
            if event.is_private:
                event.chat_id = 777000
            with (
                patch.object(web, "get_profile") as profile,
                patch.object(web, "payment_audit_store", store),
            ):
                await web._handle_payment_message(MagicMock(), "p1", event)
                profile.assert_not_called()
        store.record_event.assert_not_called()

    async def test_image_is_scheduled_for_ocr(self):
        captured = []
        store = MagicMock()

        def capture(awaitable, **_kwargs):
            captured.append(awaitable)
            awaitable.close()

        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "_track_audit_task", side_effect=capture),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(
                MagicMock(), "p1", FakeEvent(text="обычная фотография", media_type="image/jpeg")
            )

        self.assertEqual(len(captured), 1)

    async def test_pdf_and_webp_do_not_enter_ocr_queue(self):
        for media_type in ("application/pdf", "image/webp"):
            store = MagicMock()
            with (
                patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
                patch.object(web, "get_user", return_value=self.work_user()),
                patch.object(web, "payment_audit_store", store),
                patch.object(web, "_track_audit_task") as track,
            ):
                await web._handle_payment_message(
                    MagicMock(), "p1", FakeEvent("файл", media_type=media_type)
                )
            track.assert_not_called()

    async def test_forwarded_flag_reaches_ocr_worker(self):
        store = MagicMock()
        marker = object()
        worker = MagicMock(return_value=marker)
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "_audit_receipt_media", new=worker),
            patch.object(web, "_track_audit_task") as track,
        ):
            await web._handle_payment_message(
                MagicMock(), "p1",
                FakeEvent("чек", media_type="image/jpeg", forwarded=True),
            )

        worker.assert_called_once()
        self.assertTrue(worker.call_args.kwargs["is_forwarded"])
        track.assert_called_once_with(marker, ocr_pid="p1", priority=False)

    async def test_each_edit_version_has_a_distinct_event_key(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.side_effect = ("EVENT1", "EVENT2")
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(
                MagicMock(), "p1", FakeEvent("Скинул 1000 ₽"), source="edited"
            )
            await web._handle_payment_message(
                MagicMock(), "p1", FakeEvent("Не скинул 1000 ₽"), source="edited"
            )

        versions = [call.args[3] for call in store.event_key.call_args_list]
        self.assertNotEqual(versions[0], versions[1])

    async def test_edit_that_removes_payment_signal_retracts_existing_message(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.message_ref.return_value = "a" * 64
        store.event_key.return_value = "EDITED-EVENT"
        store.has_message.return_value = True
        event = FakeEvent("исправленный обычный текст")
        event.message.edit_date = datetime(2026, 7, 30, 10, 5, tzinfo=timezone.utc)
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(MagicMock(), "p1", event, source="edited")

        store.has_message.assert_called_once_with("u1", "p1", "CHATKEY", "a" * 64)
        kwargs = store.record_event.call_args.kwargs
        self.assertEqual(kwargs["source"], "edited")
        self.assertEqual(kwargs["analysis"]["event_status"], "retracted")
        self.assertEqual(kwargs["analysis"]["amounts"], [])
        self.assertFalse(kwargs["analysis"]["income_claim"])

    async def test_unrelated_edited_message_without_prior_signal_is_ignored(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.message_ref.return_value = "a" * 64
        store.has_message.return_value = False
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(
                MagicMock(), "p1", FakeEvent("исправленный обычный текст"), source="edited"
            )

        store.record_event.assert_not_called()

    async def test_tombstone_set_mid_callback_prevents_late_audit_write(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.message_ref.return_value = "a" * 64
        store.event_key.return_value = "EVENTKEY"

        def detect_then_delete(*_args, **_kwargs):
            web.state.audit_deleted_profiles.add("p1")
            return {
                "detected": True,
                "categories": ["transfer_completed"],
                "amounts": [{"value": 5000, "currency": "RUB"}],
                "confidence": 0.8,
                "success_claim": True,
                "event_status": "completed",
            }

        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "analyze_payment_signal", side_effect=detect_then_delete),
        ):
            await web._handle_payment_message(MagicMock(), "p1", FakeEvent())

        store.record_event.assert_not_called()

    async def test_negated_ocr_never_becomes_high_confidence_income(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        ocr_result = SimpleNamespace(
            text="Перевод не выполнен. Сумма 5 000 ₽",
            signals=SimpleNamespace(
                is_likely_payment=True,
                confidence="high",
                amounts=[SimpleNamespace(value="5000", currency="RUB")],
            ),
            exact_dedup_key="sha256:one",
            text_dedup_key="ocr-sha256:one",
            media_sha256="one",
        )
        client = MagicMock()
        client.download_media = AsyncMock(return_value=b"\xff\xd8\xffimage")
        with (
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "payment_audit_store", store),
            patch.object(web.receipt_ocr, "analyze_bytes_async", AsyncMock(return_value=ocr_result)),
        ):
            await web._audit_receipt_media(
                client,
                FakeEvent(media_type="image/jpeg"),
                owner="u1",
                pid="p1",
                chat_id=12345,
                direction="incoming",
                media_type="image/jpeg",
            )

        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertTrue(analysis["negated"])
        self.assertFalse(analysis["income_claim"])
        self.assertLessEqual(analysis["confidence"], 0.42)

    async def test_forwarded_ocr_is_capped_and_marked(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        ocr_result = SimpleNamespace(
            text="Перевод выполнен успешно. Сумма 5 000 ₽",
            signals=SimpleNamespace(
                is_likely_payment=True,
                confidence="high",
                amounts=[SimpleNamespace(value="5000", currency="RUB")],
            ),
            exact_dedup_key="sha256:two",
            text_dedup_key="ocr-sha256:two",
            media_sha256="two",
        )
        client = MagicMock()
        client.download_media = AsyncMock(return_value=b"\xff\xd8\xffimage")
        with (
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "payment_audit_store", store),
            patch.object(web.receipt_ocr, "analyze_bytes_async", AsyncMock(return_value=ocr_result)),
        ):
            await web._audit_receipt_media(
                client,
                FakeEvent(media_type="image/jpeg", forwarded=True),
                owner="u1",
                pid="p1",
                chat_id=12345,
                direction="incoming",
                media_type="image/jpeg",
                is_forwarded=True,
            )

        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertFalse(analysis["income_claim"])
        self.assertIn("forwarded_receipt", analysis["categories"])
        self.assertLessEqual(analysis["confidence"], 0.42)

    async def test_media_download_timeout_does_not_reach_ocr(self):
        async def never_finishes(*_args, **_kwargs):
            await asyncio.sleep(1)

        client = MagicMock()
        client.download_media = never_finishes
        worker = AsyncMock()
        with (
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "PAYMENT_AUDIT_DOWNLOAD_TIMEOUT", 0.01),
            patch.object(web.receipt_ocr, "analyze_bytes_async", worker),
        ):
            await web._audit_receipt_media(
                client,
                FakeEvent(media_type="image/jpeg"),
                owner="u1",
                pid="p1",
                chat_id=12345,
                direction="incoming",
                media_type="image/jpeg",
            )

        worker.assert_not_awaited()

    async def test_deleted_profile_tombstone_stops_queued_ocr(self):
        client = MagicMock()
        client.download_media = AsyncMock(return_value=b"\xff\xd8\xffimage")
        web.state.audit_deleted_profiles.add("p1")

        await web._audit_receipt_media(
            client,
            FakeEvent(media_type="image/jpeg"),
            owner="u1",
            pid="p1",
            chat_id=12345,
            direction="incoming",
            media_type="image/jpeg",
        )

        client.download_media.assert_not_awaited()

    async def test_priority_receipt_cancels_waiting_ordinary_images(self):
        blocker = asyncio.Event()

        async def wait_forever():
            await blocker.wait()

        tasks = [
            web._track_audit_task(wait_forever(), ocr_pid=f"p{index}", priority=False)
            for index in range(4)
        ]
        await asyncio.sleep(0)
        self.assertTrue(web._audit_ocr_queue_has_capacity("priority", priority=True))
        await asyncio.sleep(0)

        self.assertTrue(all(task.done() for task in tasks))
        self.assertEqual(web.state.audit_ocr_dropped["queue"], 4)

    async def test_ordinary_ocr_queue_is_fair_per_profile(self):
        blocker = asyncio.Event()

        async def wait_forever():
            await blocker.wait()

        tasks = [
            web._track_audit_task(wait_forever(), ocr_pid="same", priority=False)
            for _ in range(2)
        ]
        await asyncio.sleep(0)
        self.assertFalse(web._audit_ocr_queue_has_capacity("same", priority=False))
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_ordinary_images_cannot_consume_priority_quota_reserve(self):
        with patch.object(web, "PAYMENT_AUDIT_OCR_PER_HOUR", 8):
            self.assertTrue(all(web._audit_ocr_allowed("p1") for _ in range(5)))
            self.assertFalse(web._audit_ocr_allowed("p1"))
            self.assertTrue(web._audit_ocr_allowed("p1", priority=True))

    async def test_sqlite_write_does_not_block_asyncio_loop(self):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        store.message_ref.return_value = "a" * 64
        store.record_event.side_effect = lambda **_kwargs: time.sleep(0.2)
        started = time.monotonic()

        async def heartbeat():
            await asyncio.sleep(0.02)
            return time.monotonic() - started

        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            delay, _ = await asyncio.gather(
                heartbeat(),
                web._handle_payment_message(MagicMock(), "p1", FakeEvent()),
            )

        self.assertLess(delay, 0.1)

    async def test_edited_image_is_sent_to_versioned_ocr(self):
        store = MagicMock()
        marker = object()
        worker = MagicMock(return_value=marker)
        event = FakeEvent("чек", media_type="image/jpeg")
        event.message.edit_date = datetime(2026, 7, 30, 10, 5, tzinfo=timezone.utc)
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "_audit_receipt_media", new=worker),
            patch.object(web, "_track_audit_task") as track,
        ):
            await web._handle_payment_message(MagicMock(), "p1", event, source="edited")

        self.assertEqual(worker.call_args.kwargs["message_source"], "edited")
        track.assert_called_once()

    async def test_user_summary_uses_current_calendar_week(self):
        store = MagicMock()
        store.weekly_report.return_value = None
        store.recent_weekly_reports.return_value = []
        store.weekly_summary.return_value = {"pending": 0, "confirmed_total": 0}
        with (
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "_current_week_bounds", return_value=("2026-07-27", "2026-08-03")),
            patch.object(web, "_payment_ocr_available", new=AsyncMock(return_value=True)),
        ):
            result = await web.payment_audit_info(user=self.work_user())

        store.weekly_summary.assert_called_once_with(
            "u1", "2026-07-27", "2026-08-03",
            commission_rate=web.PAYMENT_COMMISSION_RATE,
        )
        self.assertTrue(result["ocr_available"])

    async def test_profile_delete_archives_audit_instead_of_erasing_it(self):
        store = MagicMock()
        profile = {"id": "p1", "owner": "u1"}
        with (
            patch.object(web, "_owned_profile", return_value=profile),
            patch.object(web, "payment_audit_store", store),
            patch.object(web, "_destroy_profile", new=AsyncMock()),
            patch.object(web, "load_profiles", return_value=[profile]),
            patch.object(web, "load_schedules", return_value=[]),
            patch.object(web, "load_packs", return_value=[]),
            patch.object(web, "save_profiles"),
            patch.object(web, "save_schedules"),
            patch.object(web, "save_packs"),
        ):
            result = await web.delete_profile("p1", user={"id": "u1"})

        self.assertEqual(result, {"ok": True})
        store.archive_profile.assert_called_once_with("p1")
        store.delete_profile.assert_not_called()

    async def test_admin_must_enter_confirmed_amount_instead_of_using_max(self):
        store = MagicMock()
        with patch.object(web, "payment_audit_store", store):
            response = await web.admin_payment_audit_review(
                "case",
                web.PaymentCaseReviewIn(status="confirmed", amount=None),
                admin={"id": "admin"},
            )

        self.assertEqual(response.status_code, 400)
        store.review.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class WeakMoneyTraceTests(unittest.IsolatedAsyncioTestCase):
    """Слабый денежный след сохраняется сразу — чат могут удалить в любой момент."""

    def work_user(self):
        return {"id": "u1", "status": "approved", "paid_until": "2099-01-01T00:00:00"}

    async def handle(self, text):
        store = MagicMock()
        store.chat_key.return_value = "CHATKEY"
        store.event_key.return_value = "EVENTKEY"
        store.message_ref.return_value = "b" * 64
        with (
            patch.object(web, "get_profile", return_value={"id": "p1", "owner": "u1"}),
            patch.object(web, "get_user", return_value=self.work_user()),
            patch.object(web, "payment_audit_store", store),
        ):
            await web._handle_payment_message(MagicMock(), "p1", FakeEvent(text))
        return store

    async def test_saves_money_talk_that_is_not_a_full_signal(self):
        store = await self.handle("скинул, проверяй")
        store.record_event.assert_called_once()
        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertIn("money_mentioned", analysis["categories"])
        self.assertFalse(analysis["income_claim"])
        self.assertLessEqual(analysis["confidence"], 0.25)
        self.assertTrue(store.record_event.call_args.kwargs["snippet"],
                        "в слабой карточке должна остаться улика")

    async def test_weak_trace_is_never_counted_as_income(self):
        store = await self.handle("жду оплату")
        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertFalse(analysis["success_claim"])
        self.assertFalse(analysis["income_claim"])
        self.assertEqual(analysis["event_status"], "possible")

    async def test_ordinary_chatter_is_still_not_saved(self):
        for text in ("привет, как дела", "скинул фотки с объекта", "проверь почту"):
            with self.subTest(text=text):
                store = await self.handle(text)
                store.record_event.assert_not_called()

    async def test_full_signal_still_wins_over_weak_trace(self):
        store = await self.handle("скинул 5000 на карту")
        analysis = store.record_event.call_args.kwargs["analysis"]
        self.assertNotIn("money_mentioned", analysis["categories"])
        self.assertTrue(analysis["income_claim"])
