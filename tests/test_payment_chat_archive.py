import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from payment_chat_archive import PaymentChatArchive, PaymentChatArchiveError


class PaymentChatArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.archive = PaymentChatArchive(
            self.tmp.name,
            "a" * 64,
            max_messages=5,
            max_media_items=2,
            max_media_bytes=1024,
            max_total_media_bytes=2048,
        )

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def message(mid, text, **extra):
        return {
            "id": mid,
            "direction": extra.pop("direction", "incoming"),
            "text": text,
            "at": "2026-08-01T10:00:00+00:00",
            **extra,
        }

    def test_merges_same_chat_without_dropping_deleted_or_revised_messages(self):
        self.archive.merge(
            "u1", "p1", "CHAT1",
            [self.message(1, "старая реплика"), self.message(2, "перевёл 5000 ₽")],
        )
        self.archive.merge(
            "u1", "p1", "CHAT1",
            [self.message(2, "сообщение изменено"), self.message(3, "спасибо")],
        )

        saved = self.archive.load("u1", "p1", "CHAT1")

        self.assertEqual([row["id"] for row in saved["messages"]], [1, 2, 3])
        self.assertEqual(saved["messages"][0]["text"], "старая реплика")
        self.assertEqual(saved["messages"][1]["text"], "сообщение изменено")
        self.assertEqual(saved["messages"][1]["revisions"][0]["text"], "перевёл 5000 ₽")

    def test_original_text_survives_more_than_three_edits(self):
        self.archive.merge("u1", "p1", "CHAT", [self.message(9, "перевёл 5000 ₽")])
        for index in range(1, 6):
            self.archive.merge(
                "u1", "p1", "CHAT", [self.message(9, f"редакция {index}")]
            )

        row = self.archive.load("u1", "p1", "CHAT")["messages"][0]

        self.assertEqual(row["text"], "редакция 5")
        self.assertEqual(row["original_text"], "перевёл 5000 ₽")
        self.assertLessEqual(len(row["revisions"]), 3)

    def test_scopes_from_different_profiles_never_mix(self):
        # Real chat keys already include the profile id in their HMAC.
        self.archive.merge("u1", "p1", "CHAT-P1", [self.message(1, "первый")])
        self.archive.merge("u1", "p2", "CHAT-P2", [self.message(2, "второй")])

        first = self.archive.load("u1", "p1", "CHAT-P1")
        second = self.archive.load("u1", "p2", "CHAT-P2")

        self.assertEqual([row["text"] for row in first["messages"]], ["первый"])
        self.assertEqual([row["text"] for row in second["messages"]], ["второй"])
        profile_id, found = self.archive.find_chat("u1", "CHAT-P2")
        self.assertEqual(profile_id, "p2")
        self.assertEqual(found["owner"], "u1")

    def test_rejects_short_or_empty_encryption_keys(self):
        for key in (b"", b"too-short", "", "short-passphrase", "x" * 64):
            with self.subTest(key=key), self.assertRaises(ValueError):
                PaymentChatArchive(Path(self.tmp.name) / "bad-key", key)

    def test_key_marker_rejects_another_key_without_hiding_ciphertext(self):
        root = Path(self.tmp.name) / "keyed"
        original = PaymentChatArchive(root, "d" * 64, min_free_bytes=0)
        original.merge("u1", "p1", "CHAT", [self.message(1, "оплата")])
        scope_dirs = {path.name for path in root.iterdir() if path.is_dir()}

        with self.assertRaises(PaymentChatArchiveError):
            PaymentChatArchive(root, "e" * 64, min_free_bytes=0)

        self.assertEqual({path.name for path in root.iterdir() if path.is_dir()}, scope_dirs)
        self.assertEqual(original.load("u1", "p1", "CHAT")["messages"][0]["id"], 1)

    def test_manifest_and_media_are_encrypted_and_media_can_be_read(self):
        image = b"\xff\xd8\xff" + b"x" * 64
        self.archive.merge(
            "u1", "p1", "CHAT",
            [self.message(7, "секретный текст", has_media=True)],
            media=[{"message_id": 7, "mime": "image/jpeg", "data": image}],
        )
        saved = self.archive.load("u1", "p1", "CHAT")
        file_id = saved["media"][0]["file_id"]
        restored, mime = self.archive.read_media("u1", "p1", "CHAT", file_id)
        raw_files = b"".join(path.read_bytes() for path in Path(self.tmp.name).rglob("*") if path.is_file())

        self.assertEqual(restored, image)
        self.assertEqual(mime, "image/jpeg")
        self.assertNotIn("секретный текст".encode("utf-8"), raw_files)
        self.assertNotIn(image, raw_files)

    def test_changed_receipt_keeps_both_encrypted_versions(self):
        first = b"\xff\xd8\xff" + b"first" * 10
        second = b"\xff\xd8\xff" + b"second" * 10
        message = self.message(7, "чек", has_media=True)
        self.archive.merge(
            "u1", "p1", "CHAT", [message],
            media=[{"message_id": 7, "mime": "image/jpeg", "data": first}],
        )
        self.archive.merge(
            "u1", "p1", "CHAT", [message],
            media=[{"message_id": 7, "mime": "image/jpeg", "data": second}],
        )

        saved = self.archive.load("u1", "p1", "CHAT")
        restored = {
            self.archive.read_media("u1", "p1", "CHAT", row["file_id"])[0]
            for row in saved["media"]
        }

        self.assertEqual(len(saved["media"]), 2)
        self.assertEqual(restored, {first, second})

    def test_purge_leaves_only_tombstone_and_new_signal_reopens_archive(self):
        self.archive.merge("u1", "p1", "CHAT", [self.message(1, "оплата")])

        purged = self.archive.purge("u1", "p1", "CHAT")

        self.assertEqual(purged["status"], "purged")
        self.assertEqual(purged["message_count"], 0)
        self.archive.merge("u1", "p1", "CHAT", [self.message(2, "устаревшая загрузка")])
        self.assertEqual(self.archive.summary("u1", "p1", "CHAT")["status"], "purged")
        self.archive.merge(
            "u1", "p1", "CHAT", [self.message(2, "новая оплата")],
            reopen_purged=True,
            reopen_at=datetime.now(timezone.utc) + timedelta(seconds=1),
        )
        reopened = self.archive.load("u1", "p1", "CHAT")
        self.assertEqual(reopened["status"], "ready")
        self.assertEqual([row["id"] for row in reopened["messages"]], [2])

    def test_owner_quota_keeps_a_minimal_trigger_and_marks_partial(self):
        limited = PaymentChatArchive(
            Path(self.tmp.name) / "limited",
            "b" * 64,
            max_owner_bytes=1,
            max_global_bytes=0,
            min_free_bytes=0,
        )

        summary = limited.merge(
            "u1", "p1", "CHAT",
            [self.message(1, "старое"), self.message(2, "новый сигнал оплаты")],
        )
        saved = limited.load("u1", "p1", "CHAT")

        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["last_error"], "storage_quota")
        self.assertEqual([row["id"] for row in saved["messages"]], [2])

    def test_quota_rollback_keeps_media_referenced_by_original_manifest(self):
        root = Path(self.tmp.name) / "rollback"
        limited = PaymentChatArchive(
            root,
            "f" * 64,
            max_messages=1,
            max_owner_bytes=0,
            max_global_bytes=0,
            min_free_bytes=0,
        )
        receipt = b"\xff\xd8\xff" + b"receipt" * 20
        limited.merge(
            "u1", "p1", "CHAT",
            [self.message(1, "первая оплата", has_media=True)],
            media=[{"message_id": 1, "mime": "image/jpeg", "data": receipt}],
        )
        limited.max_owner_bytes = limited.usage("u1")["owner_bytes"]

        limited.merge("u1", "p1", "CHAT", [self.message(2, "новая " * 200)])

        saved = limited.load("u1", "p1", "CHAT")
        self.assertEqual([row["id"] for row in saved["messages"]], [1])
        self.assertEqual(len(saved["media"]), 1)
        restored, mime = limited.read_media(
            "u1", "p1", "CHAT", saved["media"][0]["file_id"]
        )
        self.assertEqual((restored, mime), (receipt, "image/jpeg"))

    def test_quota_usage_cache_scans_once_and_tracks_scope_mutations(self):
        with patch.object(
            self.archive,
            "_iter_manifests",
            wraps=self.archive._iter_manifests,
        ) as scans:
            self.archive.merge(
                "u1", "p1", "CHAT-ONE", [self.message(1, "первый")]
            )
            first = self.archive.usage("u1")
            self.archive.merge(
                "u1", "p1", "CHAT-ONE", [self.message(2, "второй")]
            )
            self.archive.merge(
                "u2", "p2", "CHAT-TWO", [self.message(3, "третий")]
            )
            cached = self.archive.usage("u1")

            # merge() asks for both global and owner quota on every call, but
            # only the first call may enumerate/decrypt every stored manifest.
            self.assertEqual(scans.call_count, 1)
            self.assertEqual(first["scopes"], 1)
            self.assertEqual(cached["scopes"], 2)
            self.assertEqual(cached["owner_scopes"], 1)
            u1_scope = self.archive._scope_id("u1", "p1", "CHAT-ONE")
            actual_global = sum(
                path.stat().st_size
                for scope in Path(self.tmp.name).iterdir()
                if scope.is_dir() and len(scope.name) == 32
                for path in scope.iterdir()
                if path.is_file()
            )
            self.assertEqual(
                cached["owner_bytes"], self.archive._scope_stored_size(u1_scope)
            )
            self.assertEqual(cached["global_bytes"], actual_global)

            self.archive.purge("u1", "p1", "CHAT-ONE", tombstone=False)
            after_purge = self.archive.usage("u1")
            self.assertEqual(scans.call_count, 1)
            self.assertEqual(after_purge["scopes"], 1)
            self.assertEqual(after_purge["owner_scopes"], 0)
            self.assertEqual(after_purge["owner_bytes"], 0)

            refreshed = self.archive.usage("u2", refresh=True)
            self.assertEqual(scans.call_count, 2)
            self.assertEqual(refreshed["scopes"], 1)
            self.assertEqual(refreshed["owner_scopes"], 1)

    def test_limits_mark_archive_truncated_without_dropping_existing_rows(self):
        self.archive.merge(
            "u1", "p1", "CHAT",
            [self.message(mid, f"m{mid}") for mid in range(1, 6)],
        )

        summary = self.archive.merge(
            "u1", "p1", "CHAT",
            [self.message(6, "new trigger")],
        )

        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["message_count"], 5)
        self.assertIn(6, [row["id"] for row in self.archive.load("u1", "p1", "CHAT")["messages"]])

    def test_lists_pending_and_cleans_old_archives(self):
        self.archive.mark_status("u1", "p1", "CHAT", "pending")
        self.assertEqual(len(self.archive.list_statuses(("pending",))), 1)

        removed = self.archive.cleanup(
            1,
            now=datetime.now(timezone.utc) + timedelta(days=2),
        )

        self.assertEqual(removed, 1)
        self.assertEqual(self.archive.summary("u1", "p1", "CHAT")["status"], "missing")


if __name__ == "__main__":
    unittest.main()
