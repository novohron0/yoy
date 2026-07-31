import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from payment_audit_store import PaymentAuditStore, mask_sensitive_text


class PaymentAuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PaymentAuditStore(
            os.path.join(self.tmp.name, "audit.sqlite3"),
            "test-secret",
            correlation_minutes=120,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def record(
        self,
        suffix,
        *,
        at=None,
        minute=0,
        direction="incoming",
        score=45,
        categories=None,
        amounts=None,
        media_hash="",
        source="message",
        message_id=None,
        event_status=None,
        income_claim=None,
        attribution="direct",
        negated=False,
        chat_id=123,
        chat_ref=None,
        message_ref=None,
        event_version=None,
        snippet=None,
    ):
        at = at or datetime(2026, 7, 30, 10, minute, tzinfo=timezone.utc)
        message_id = suffix if message_id is None else message_id
        analysis = {
            "score": score,
            "categories": ["payment_action"] if categories is None else categories,
            "amounts": [] if amounts is None else amounts,
            "attribution": attribution,
            "negated": negated,
        }
        if event_status is not None:
            analysis["event_status"] = event_status
        if income_claim is not None:
            analysis["income_claim"] = income_claim
        return self.store.record_event(
            event_key=self.store.event_key(
                "p1", chat_id, message_id, event_version or source
            ),
            owner="u1",
            profile_id="p1",
            chat_key=self.store.chat_key("p1", chat_id),
            observed_at=at,
            direction=direction,
            analysis=analysis,
            snippet=snippet if snippet is not None else (
                "Перевёл 5 000 ₽ на счёт 40817810099910004312, "
                "IBAN DE89 3704 0044 0532 0130 00, ivan@example.com"
            ),
            source=source,
            media_hash=media_hash,
            chat_ref=chat_ref,
            message_ref=message_ref,
        )

    def test_masks_financial_and_contact_identifiers_but_keeps_amount(self):
        original = (
            "Сумма 5000, карта 2200 7012 3456 7890, "
            "счёт 40817810099910004312, IBAN DE89 3704 0044 0532 0130 00, "
            "почта ivan.petrov@example.com"
        )
        masked = mask_sensitive_text(original)

        self.assertIn("5000", masked)
        self.assertNotIn("2200 7012 3456 7890", masked)
        self.assertNotIn("40817810099910004312", masked)
        self.assertNotIn("DE89 3704 0044 0532 0130 00", masked)
        self.assertNotIn("ivan.petrov@example.com", masked)
        self.assertIn("[email]", masked)

    def test_masks_cards_with_typographic_and_punctuation_separators(self):
        values = (
            "2200•7012•3456•7890",
            "2200·7012·3456·7890",
            "2200/7012/3456/7890",
            "2200.7012.3456.7890",
        )
        masked = mask_sensitive_text("; ".join(values))

        for value in values:
            self.assertNotIn(value, masked)

    def test_event_keys_share_message_ref_across_sources(self):
        text_key = self.store.event_key("p1", 123, 77, "message")
        ocr_key = self.store.event_key("p1", 123, 77, "ocr")

        self.assertNotEqual(text_key, ocr_key)
        self.assertEqual(text_key.split(":", 1)[0], ocr_key.split(":", 1)[0])

    def test_chat_ref_is_validated_and_message_ref_is_private(self):
        raw_message_ref = "p1:123:88"
        case = self.record(
            "private-ref",
            message_id=88,
            chat_ref="123456789",
            message_ref=raw_message_ref,
        )

        self.assertEqual(case["chat_ref"], 123456789)
        self.assertTrue(all("message_ref" not in item for item in case["evidence"]))
        with self.store._connection() as db:
            stored_ref = db.execute(
                "SELECT message_ref FROM payment_events WHERE case_id=?", (case["id"],)
            ).fetchone()[0]
        self.assertEqual(stored_ref, self.store.message_ref("p1", 123, 88))
        self.assertNotIn(raw_message_ref, stored_ref)

        for index, invalid in enumerate((True, 0, -1, "1e6", 1.5, 2**63)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.record(f"bad-chat-{index}", chat_ref=invalid)

    def test_event_key_collision_cannot_cross_owner_scope(self):
        event_key = self.store.event_key("p1", 123, 901, "message")
        self.record("scope", message_id=901)

        with self.assertRaises(ValueError):
            self.store.record_event(
                event_key=event_key,
                owner="u2",
                profile_id="p1",
                chat_key=self.store.chat_key("p1", 123),
                observed_at=datetime(2026, 7, 30, 10, 1, tzinfo=timezone.utc),
                direction="incoming",
                analysis={"score": 30, "categories": ["payment_intent"]},
            )

    def test_correlates_text_and_ocr_only_for_same_message(self):
        first = self.record(
            "text", message_id=77, source="message", score=60,
            categories=["transfer_completed"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        second = self.record(
            "ocr", message_id=77, source="ocr", score=75,
            categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            media_hash="abc", event_status="receipt", income_claim=False,
        )
        duplicate = self.record(
            "again", message_id=77, source="ocr", score=99,
            categories=["receipt_ocr"],
            event_status="receipt", income_claim=False,
        )

        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["id"], duplicate["id"])
        self.assertEqual(len(second["evidence"]), 2)
        self.assertEqual(second["event_status"], "completed")
        self.assertTrue(second["income_claim"])
        self.assertEqual(second["attribution"], "direct")

    def test_same_message_edit_replaces_current_signal_and_can_retract_it(self):
        message_id = 771
        message_ref = self.store.message_ref("p1", 123, message_id)
        original = self.record(
            "original", message_id=message_id, score=82,
            categories=["transfer_completed"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        self.assertTrue(self.store.has_message(
            "u1", "p1", self.store.chat_key("p1", 123), message_ref
        ))

        edited = self.record(
            "edit-one", message_id=message_id, source="edited", minute=5,
            event_version="edited:v1", score=61,
            categories=["payment_request"],
            amounts=[{"value": 7000, "currency": "RUB"}],
            event_status="requested", income_claim=False,
        )
        delayed_ocr = self.record(
            "old-ocr", message_id=message_id, source="ocr", minute=0,
            event_version="ocr:old", score=90, categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            media_hash="old-receipt", event_status="receipt", income_claim=False,
        )
        retracted = self.record(
            "edit-two", message_id=message_id, source="edited", minute=6,
            event_version="edited:v2", score=0, categories=[], amounts=[],
            event_status="retracted", income_claim=False, snippet="",
        )
        restored = self.record(
            "edit-three", message_id=message_id, source="edited", minute=7,
            event_version="edited:v3", score=80,
            categories=["transfer_completed"],
            amounts=[{"value": 9000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )

        self.assertEqual(original["id"], edited["id"])
        self.assertEqual(edited["amounts"], [{"value": 7000.0, "currency": "RUB"}])
        self.assertEqual(edited["categories"], ["payment_request"])
        self.assertEqual(delayed_ocr["amounts"], [{"value": 7000.0, "currency": "RUB"}])
        self.assertEqual(delayed_ocr["event_status"], "requested")
        self.assertEqual(retracted["id"], original["id"])
        self.assertEqual(retracted["event_status"], "retracted")
        self.assertEqual(retracted["amounts"], [])
        self.assertEqual(retracted["categories"], [])
        self.assertEqual(retracted["score"], 0)
        self.assertEqual(restored["event_status"], "completed")
        self.assertEqual(restored["amounts"], [{"value": 9000.0, "currency": "RUB"}])
        self.assertNotIn(5000.0, [item["value"] for item in restored["amounts"]])

    def test_separate_completed_messages_are_separate_payments(self):
        first = self.record(
            "one", minute=0, score=75, categories=["transfer_completed"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        same_amount_again = self.record(
            "two", minute=20, score=75, categories=["transfer_completed"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        different_amount = self.record(
            "three", minute=30, score=75, categories=["transfer_completed"],
            amounts=[{"value": 9000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )

        self.assertNotEqual(first["id"], same_amount_again["id"])
        self.assertNotEqual(same_amount_again["id"], different_amount["id"])

    def test_out_of_order_unrelated_event_does_not_merge_or_regress_time(self):
        newer = self.record(
            "new", at=datetime(2026, 7, 30, 13, 0, tzinfo=timezone.utc),
            event_status="intent", income_claim=False,
        )
        older = self.record(
            "old", at=datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc),
            event_status="intent", income_claim=False,
        )

        self.assertNotEqual(newer["id"], older["id"])
        self.assertEqual(newer["last_at"], "2026-07-30T13:00:00+00:00")

    def test_reviewed_cases_only_accept_updates_for_the_same_message(self):
        user_case = self.record(
            "user-message", minute=0, event_status="intent", income_claim=False,
        )
        self.store.respond(user_case["id"], "u1", "personal")
        same_user_message = self.record(
            "user-ocr", message_id="user-message", minute=0, source="ocr",
            event_status="receipt", income_claim=False,
        )
        later_user_message = self.record(
            "user-later", minute=5, event_status="intent", income_claim=False,
        )

        admin_case = self.record(
            "admin-message", chat_id=456, minute=20,
            event_status="intent", income_claim=False,
        )
        self.store.review(admin_case["id"], "admin", "confirmed", 0)
        same_admin_message = self.record(
            "admin-ocr", message_id="admin-message", chat_id=456, minute=20,
            source="ocr", event_status="receipt", income_claim=False,
        )
        later_admin_message = self.record(
            "admin-later", chat_id=456, minute=25,
            event_status="intent", income_claim=False,
        )

        self.assertEqual(user_case["id"], same_user_message["id"])
        self.assertNotEqual(user_case["id"], later_user_message["id"])
        self.assertEqual(admin_case["id"], same_admin_message["id"])
        self.assertNotEqual(admin_case["id"], later_admin_message["id"])

    def test_new_negative_lowers_score_and_older_ocr_cannot_restore_state(self):
        positive = self.record(
            "positive", message_id=1, minute=0, score=86,
            categories=["transfer_completed"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        negative = self.record(
            "negative", message_id=2, minute=10, score=62,
            categories=["payment_negation"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="failed_or_reversed", income_claim=False, negated=True,
        )
        delayed_ocr = self.record(
            "late-ocr", message_id=1, minute=0, source="ocr", score=90,
            categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            media_hash="receipt", event_status="receipt", income_claim=False,
        )

        self.assertEqual(positive["id"], negative["id"])
        self.assertEqual(negative["id"], delayed_ocr["id"])
        self.assertLess(negative["score"], positive["score"])
        self.assertLessEqual(delayed_ocr["score"], 39)
        self.assertEqual(delayed_ocr["event_status"], "failed_or_reversed")
        self.assertFalse(delayed_ocr["income_claim"])
        self.assertEqual(delayed_ocr["state_at"], "2026-07-30T10:10:00+00:00")
        self.assertEqual(delayed_ocr["last_at"], "2026-07-30T10:10:00+00:00")
        latest_negative = next(
            item for item in delayed_ocr["evidence"] if item["event_status"] == "failed_or_reversed"
        )
        self.assertFalse(latest_negative["income_claim"])
        self.assertEqual(latest_negative["attribution"], "direct")

    def test_failed_or_retracted_edit_reopens_confirmed_case_and_summary_excludes_it(self):
        stable = self.record(
            "stable-confirmed", chat_id=599, message_id=899, minute=10,
            score=85, categories=["transfer_completed"],
            amounts=[{"value": 4000, "currency": "RUB"}],
            event_status="completed", income_claim=True,
        )
        self.store.review(stable["id"], "admin", "confirmed", 4000)
        stale_negative = self.record(
            "stale-negative", chat_id=599, message_id=899, minute=0,
            source="ocr", event_version="ocr:stale-negative", score=30,
            categories=["payment_negation"], amounts=[],
            event_status="failed_or_reversed", income_claim=False,
            negated=True, snippet="",
        )
        self.assertEqual(stale_negative["event_status"], "completed")
        self.assertEqual(stale_negative["admin_status"], "confirmed")
        self.assertEqual(stale_negative["admin_amount"], 4000)

        changed_cases = []
        for offset, status in enumerate(("failed_or_reversed", "retracted")):
            chat_id = 600 + offset
            message_id = 900 + offset
            case = self.record(
                f"confirmed-{status}", chat_id=chat_id, message_id=message_id,
                score=85, categories=["transfer_completed"],
                amounts=[{"value": 5000 + offset, "currency": "RUB"}],
                event_status="completed", income_claim=True,
            )
            self.store.review(case["id"], "admin", "confirmed", 5000 + offset)
            changed = self.record(
                f"changed-{status}", chat_id=chat_id, message_id=message_id,
                source="edited", event_version=f"edited:{status}", score=30,
                categories=[] if status == "retracted" else ["payment_negation"],
                amounts=[], event_status=status, income_claim=False,
                negated=status == "failed_or_reversed", snippet="",
            )
            self.assertEqual(changed["admin_status"], "needs_info")
            self.assertIsNone(changed["admin_amount"])
            changed_cases.append(changed)

        with self.store._connection() as db:
            logs = db.execute(
                "SELECT action, old_value, new_value FROM payment_audit_log "
                "WHERE action='auto_reopen' ORDER BY id"
            ).fetchall()
            # Even a stale/manual DB state must not make a failed claim income.
            db.executemany(
                "UPDATE payment_cases SET admin_status='confirmed', admin_amount=9999 WHERE id=?",
                [(case["id"],) for case in changed_cases],
            )

        self.assertEqual(len(logs), 2)
        self.assertTrue(all(log["old_value"] == "confirmed" for log in logs))
        self.assertTrue(all(log["new_value"] == "needs_info" for log in logs))
        summary = self.store.owner_summary("u1", days=3650)
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(summary["confirmed_total"], 4000)

    def test_generic_bonus_cannot_promote_detector_medium_without_corroboration(self):
        for chat_id, confidence in ((710, 0.61), (711, 0.70)):
            case = self.record(
                f"medium-{chat_id}", chat_id=chat_id, score=confidence,
                categories=["payment_intent"],
                amounts=[{"value": 5000, "currency": "RUB"}],
                event_status="intent", income_claim=False,
            )
            self.assertEqual(case["level"], "medium")
            self.assertLessEqual(case["score"], 74)

        corroborated = self.record(
            "corroborated", chat_id=712, score=0.70,
            categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            media_hash="receipt-hash", event_status="receipt", income_claim=False,
        )
        self.assertEqual(corroborated["level"], "high")

        medium = self.record(
            "retained-medium", chat_id=713, score=0.70,
            categories=["payment_intent"],
            amounts=[{"value": 7000, "currency": "RUB"}],
            event_status="intent", income_claim=False,
        )
        with self.store._connection() as db:
            db.execute(
                "UPDATE payment_cases SET score=99, level='high' WHERE id=?",
                (medium["id"],),
            )
        reopened = PaymentAuditStore(self.store.path, "test-secret")
        migrated_medium = reopened.get_case(medium["id"])
        self.assertEqual(migrated_medium["level"], "medium")
        self.assertLessEqual(migrated_medium["score"], 74)

    def test_standalone_negative_signal_remains_visible_in_default_list(self):
        case = self.record(
            "negative-only",
            score=39,
            categories=["payment_negation"],
            amounts=[{"value": 5000, "currency": "RUB"}],
            event_status="failed_or_reversed",
            income_claim=False,
            negated=True,
        )

        visible_ids = {
            item["id"] for item in self.store.list_cases(owner="u1", days=3650)
        }
        self.assertGreaterEqual(case["score"], 20)
        self.assertIn(case["id"], visible_ids)

    def test_forwarded_completed_claim_is_not_income(self):
        case = self.record(
            "forward", score=90, categories=["transfer_completed"],
            event_status="completed", income_claim=True, attribution="forwarded",
        )

        self.assertFalse(case["income_claim"])
        self.assertEqual(case["attribution"], "forwarded")
        self.assertLessEqual(case["score"], 59)

    def test_repeated_low_events_do_not_inflate_score(self):
        first = self.record(
            "one", score=35, categories=["payment_intent"],
            amounts=[{"value": 3000, "currency": "RUB"}],
            event_status="intent", income_claim=False,
        )
        second = self.record(
            "two", minute=5, score=20, categories=["payment_intent"],
            amounts=[{"value": 3000, "currency": "RUB"}],
            event_status="intent", income_claim=False,
        )
        third = self.record(
            "three", minute=10, score=20, categories=["payment_intent"],
            amounts=[{"value": 3000, "currency": "RUB"}],
            event_status="intent", income_claim=False,
        )

        self.assertLessEqual(second["score"], first["score"])
        self.assertEqual(second["score"], third["score"])

    def test_reused_receipt_hash_is_marked_on_another_dialog(self):
        first = self.record(
            "one", score=75, categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}], media_hash="same-hash",
            event_status="receipt", income_claim=False,
        )
        second = self.record(
            "other", minute=10, chat_id=999, score=75, categories=["receipt_ocr"],
            amounts=[{"value": 5000, "currency": "RUB"}], media_hash="same-hash",
            event_status="receipt", income_claim=False,
        )

        self.assertNotEqual(first["id"], second["id"])
        self.assertIn("duplicate_receipt", second["categories"])

    def test_weekly_reports_keep_change_history_and_recent_weeks(self):
        first = self.store.submit_week("u1", "2026-07-20", 10_000, "первая сумма")
        changed = self.store.submit_week("u1", "2026-07-20", 8_000, "исправление")
        self.store.submit_week("u1", "2026-07-27", 12_000, "новая неделя")
        recent = self.store.recent_weekly_reports("u1", limit=2)

        self.assertEqual(first["amount"], 10_000)
        self.assertEqual(changed["amount"], 8_000)
        self.assertEqual(len(changed["history"]), 2)
        self.assertEqual(changed["history"][0]["old_amount"], 10_000)
        self.assertEqual(changed["history"][0]["new_amount"], 8_000)
        self.assertEqual([item["week_start"] for item in recent], ["2026-07-27", "2026-07-20"])
        self.assertEqual(len(recent[1]["history"]), 2)

    def test_weekly_summary_uses_monday_boundaries_and_has_no_500_case_cap(self):
        start = datetime(2026, 7, 27, tzinfo=timezone.utc)
        for index in range(501):
            self.record(
                f"week-{index}", at=start + timedelta(minutes=index),
                chat_id=10_000 + index, score=50,
                categories=["payment_intent"], event_status="intent",
                income_claim=False, snippet="",
            )
        self.record(
            "before-week", at=start - timedelta(seconds=1), chat_id=20_001,
            score=50, event_status="intent", income_claim=False, snippet="",
        )
        self.record(
            "next-week", at=start + timedelta(days=7), chat_id=20_002,
            score=50, event_status="intent", income_claim=False, snippet="",
        )

        summary = self.store.weekly_summary("u1", "2026-07-27", "2026-08-03")

        self.assertEqual(summary["cases"], 501)
        self.assertEqual(summary["pending"], 501)
        self.assertEqual(summary["week_start"], "2026-07-27")
        self.assertEqual(summary["week_end"], "2026-08-03")
        with self.assertRaises(ValueError):
            self.store.weekly_summary("u1", "2026-07-28", "2026-08-04")

    def test_cleanup_keeps_reports_longer_than_evidence_then_expires_them(self):
        old_case = self.record(
            "old", at=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
            score=75, event_status="completed", income_claim=True,
        )
        self.store.respond(old_case["id"], "u1", "income", "старый ответ")
        self.store.submit_week("u1", "2025-12-29", 5000, "старый отчёт")
        with self.store._connection() as db:
            db.execute(
                "UPDATE payment_weekly_reports SET submitted_at=?, updated_at=? WHERE owner=?",
                ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", "u1"),
            )
            db.execute(
                "UPDATE payment_weekly_report_log SET created_at=? WHERE owner=?",
                ("2026-01-01T00:00:00+00:00", "u1"),
            )

        removed = self.store.cleanup(datetime(2026, 4, 20, tzinfo=timezone.utc))

        self.assertEqual(removed, 1)
        self.assertEqual(self.store.get_case(old_case["id"]), {})
        self.assertIsNotNone(self.store.weekly_report("u1", "2025-12-29"))
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM payment_audit_log").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM payment_weekly_report_log").fetchone()[0], 1)

        self.store.cleanup(datetime(2027, 2, 10, tzinfo=timezone.utc))

        self.assertIsNone(self.store.weekly_report("u1", "2025-12-29"))
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM payment_weekly_report_log").fetchone()[0], 0)

    def test_every_operation_closes_its_connection(self):
        raw = sqlite3.connect(self.store.path)
        raw.row_factory = sqlite3.Row
        with patch.object(self.store, "_connect", return_value=raw):
            self.store.get_case("missing")

        with self.assertRaises(sqlite3.ProgrammingError):
            raw.execute("SELECT 1")

    def test_connect_closes_partially_configured_connection_on_error(self):
        class BrokenConnection:
            row_factory = None

            def __init__(self):
                self.closed = False

            def execute(self, *_args, **_kwargs):
                raise RuntimeError("pragma failed")

            def close(self):
                self.closed = True

        broken = BrokenConnection()
        with patch("payment_audit_store.sqlite3.connect", return_value=broken):
            with self.assertRaises(RuntimeError):
                self.store._connect()
        self.assertTrue(broken.closed)

    def test_database_and_parent_directory_permissions_are_private(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.tmp.name).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.store.path).st_mode), 0o600)

    def test_migrates_the_pre_state_schema_in_place(self):
        legacy_path = os.path.join(self.tmp.name, "legacy.sqlite3")
        db = sqlite3.connect(legacy_path)
        try:
            db.executescript(
                """
                CREATE TABLE payment_cases (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, profile_id TEXT NOT NULL,
                    chat_key TEXT NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL,
                    base_score INTEGER NOT NULL DEFAULT 0, score INTEGER NOT NULL DEFAULT 0,
                    level TEXT NOT NULL DEFAULT 'low', categories_json TEXT NOT NULL DEFAULT '[]',
                    amounts_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '[]',
                    directions_json TEXT NOT NULL DEFAULT '[]', media_hashes_json TEXT NOT NULL DEFAULT '[]',
                    user_status TEXT NOT NULL DEFAULT 'pending', user_note TEXT NOT NULL DEFAULT '',
                    user_responded_at TEXT, admin_status TEXT NOT NULL DEFAULT 'pending',
                    admin_note TEXT NOT NULL DEFAULT '', admin_amount REAL, admin_reviewed_at TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE payment_events (
                    event_key TEXT PRIMARY KEY, case_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL, source TEXT NOT NULL
                );
                """
            )
        finally:
            db.close()

        migrated = PaymentAuditStore(legacy_path, "secret")
        with migrated._connection() as db:
            case_columns = {row[1] for row in db.execute("PRAGMA table_info(payment_cases)")}
            event_columns = {row[1] for row in db.execute("PRAGMA table_info(payment_events)")}

        self.assertTrue({
            "chat_ref", "event_status", "income_claim", "state_at", "profile_active"
        } <= case_columns)
        self.assertTrue({"message_ref", "event_status", "income_claim"} <= event_columns)

    def test_user_response_admin_review_and_summary(self):
        case = self.record(
            "one", score=75, categories=["transfer_completed", "receipt_ocr"],
            amounts=[{"value": 8000, "currency": "RUB"}], media_hash="hash",
            event_status="completed", income_claim=True,
        )
        responded = self.store.respond(case["id"], "u1", "income", "Да, это заказ")
        reviewed = self.store.review(case["id"], "admin", "confirmed", 8000, "Сверено")
        summary = self.store.owner_summary("u1", days=3650)

        self.assertEqual(responded["user_status"], "income")
        self.assertEqual(reviewed["admin_status"], "confirmed")
        self.assertEqual(summary["confirmed_total"], 8000)
        self.assertEqual(summary["commission"], 1200)

    def test_cannot_respond_to_another_owners_case(self):
        case = self.record("one")
        with self.assertRaises(KeyError):
            self.store.respond(case["id"], "u2", "personal")

    def test_archive_profile_detaches_active_link_but_keeps_cases_until_owner_purge(self):
        message_id = 333
        message_ref = self.store.message_ref("p1", 123, message_id)
        case = self.record(
            "archive", message_id=message_id, chat_ref=123,
            message_ref=message_ref, score=75,
            event_status="completed", income_claim=True,
        )
        self.store.submit_week("u1", "2026-07-27", 5000)

        archived_count = self.store.archive_profile("p1")
        archived = self.store.get_case(case["id"])

        self.assertEqual(archived_count, 1)
        self.assertEqual(self.store.archive_profile("p1"), 0)
        self.assertFalse(archived["profile_active"])
        self.assertIsNone(archived["profile_id"])
        self.assertIsNone(archived["chat_ref"])
        self.assertFalse(self.store.has_message(
            "u1", "p1", self.store.chat_key("p1", 123), message_ref
        ))
        with self.store._connection() as db:
            internal_profile = db.execute(
                "SELECT profile_id FROM payment_cases WHERE id=?", (case["id"],)
            ).fetchone()[0]
        self.assertTrue(internal_profile.startswith("archived:"))

        self.store.delete_owner("u1")

        self.assertEqual(self.store.get_case(case["id"]), {})
        self.assertIsNone(self.store.weekly_report("u1", "2026-07-27"))


if __name__ == "__main__":
    unittest.main()
