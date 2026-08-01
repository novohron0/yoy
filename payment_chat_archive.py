"""Encrypted, filesystem-backed snapshots of payment-related private chats.

One archive belongs to one opaque ``(owner, profile_id, chat_key)`` scope and
is shared by every payment case from that chat.  Full chat text and images are
kept outside the audit SQLite database so an administrator can remove the
heavy evidence while leaving compact payment facts and decisions intact.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_SAFE_FILE_RE = re.compile(r"[0-9a-f]{24}\.bin")
_VALID_STATUSES = {"pending", "ready", "error", "purged"}
_IMAGE_MAGIC = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
)


class PaymentChatArchiveError(RuntimeError):
    pass


def _utc_iso(value=None) -> str:
    if value is None:
        result = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc).isoformat(timespec="seconds")


def _key_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("payment archive key must contain exactly 32 bytes")
        return value
    else:
        text = str(value or "").strip()
        if re.fullmatch(r"[0-9a-fA-F]{64}", text):
            return bytes.fromhex(text)
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except Exception as exc:
            raise ValueError("payment archive key must be 32 bytes") from exc
        if len(raw) != 32:
            raise ValueError("payment archive key must be 32 bytes")
        return raw


def _image_mime(data: bytes, declared: str = "") -> str | None:
    for magic, mime in _IMAGE_MAGIC:
        if data.startswith(magic):
            return mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


class PaymentChatArchive:
    """Store encrypted manifests and raster media with atomic updates."""

    def __init__(
        self,
        root: str | os.PathLike,
        key: bytes | str,
        *,
        max_messages: int = 5000,
        max_text_bytes: int = 10 * 1024 * 1024,
        max_media_items: int = 50,
        max_media_bytes: int = 10 * 1024 * 1024,
        max_total_media_bytes: int = 50 * 1024 * 1024,
        max_owner_bytes: int = 512 * 1024 * 1024,
        max_global_bytes: int = 2 * 1024 * 1024 * 1024,
        min_free_bytes: int = 512 * 1024 * 1024,
    ):
        self.root = Path(root).resolve()
        self.key = _key_bytes(key)
        self.aes = AESGCM(self.key)
        self.max_messages = max(1, min(50_000, int(max_messages)))
        self.max_text_bytes = max(1024, int(max_text_bytes))
        self.max_media_items = max(0, min(500, int(max_media_items)))
        self.max_media_bytes = max(1024, int(max_media_bytes))
        self.max_total_media_bytes = max(self.max_media_bytes, int(max_total_media_bytes))
        self.max_owner_bytes = max(0, int(max_owner_bytes))
        self.max_global_bytes = max(0, int(max_global_bytes))
        self.min_free_bytes = max(0, int(min_free_bytes))
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        # Quota accounting is process-local.  A re-entrant lock is intentional:
        # merge() serialises quota decisions and calls usage(), which lazily
        # initialises the same cache on its first invocation.
        self._quota_lock = threading.RLock()
        self._usage_cache_ready = False
        self._usage_scopes: dict[str, tuple[str, int]] = {}
        self._usage_global_bytes = 0
        self._usage_owner_bytes: dict[str, int] = {}
        self._usage_owner_scopes: dict[str, int] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._ensure_key_check()

    def _ensure_key_check(self) -> None:
        """Fail closed when an existing archive is opened with another key."""
        marker = self.root / ".key-check-v1"
        expected = b"PCK1" + hmac.new(
            self.key,
            b"payment-chat-archive:key-check:v1",
            hashlib.sha256,
        ).digest()
        if not marker.exists():
            # One-time upgrade from the pre-marker format is safe only if this
            # key decrypts every existing scope. A wrong key fails before the
            # marker is published and cannot hide old ciphertext from quotas.
            entries = list(self.root.iterdir())
            if entries:
                scopes = [
                    path for path in entries
                    if path.is_dir() and re.fullmatch(r"[0-9a-f]{32}", path.name)
                ]
                if len(scopes) != len(entries) or not scopes:
                    raise PaymentChatArchiveError("archive key marker missing")
                try:
                    if any(self._read_manifest_id(path.name) is None for path in scopes):
                        raise PaymentChatArchiveError("archive key marker missing")
                except PaymentChatArchiveError:
                    raise
                except Exception as exc:
                    raise PaymentChatArchiveError("archive key marker missing") from exc
            fd, tmp_name = tempfile.mkstemp(prefix=".key-check-tmp-", dir=str(self.root))
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(expected)
                    handle.flush()
                    os.fsync(handle.fileno())
                fd = -1
                try:
                    os.link(tmp_name, marker)
                except FileExistsError:
                    pass
            finally:
                if fd >= 0:
                    os.close(fd)
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
        try:
            actual = marker.read_bytes()
            os.chmod(marker, 0o600)
        except OSError as exc:
            raise PaymentChatArchiveError("cannot read archive key marker") from exc
        if not hmac.compare_digest(actual, expected):
            raise PaymentChatArchiveError("payment archive key mismatch")

    def _scope_id(self, owner: str, profile_id: str, chat_key: str) -> str:
        owner = str(owner or "")
        chat_key = str(chat_key or "")
        if not owner or not chat_key:
            raise ValueError("invalid archive scope")
        # chat_key is already an HMAC over profile + Telegram peer. Keeping the
        # directory derivable from owner/chat_key lets deletion purge a corrupt
        # archive even after the Telegram profile itself was detached.
        raw = f"{owner}\0{chat_key}".encode("utf-8")
        return hmac.new(self.key, b"payment-chat\0" + raw, hashlib.sha256).hexdigest()[:32]

    def _scope_dir(self, scope_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", scope_id):
            raise ValueError("invalid archive path")
        result = (self.root / scope_id).resolve()
        if result.parent != self.root:
            raise ValueError("invalid archive path")
        return result

    def _lock(self, scope_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope_id, threading.Lock())

    def _scope_stored_size(self, scope_id: str) -> int:
        """Return bytes stored in one scope without reading archive contents."""
        scope_dir = self._scope_dir(scope_id)
        if not scope_dir.is_dir():
            return 0
        try:
            return sum(
                path.stat().st_size
                for path in scope_dir.iterdir()
                if path.is_file()
            )
        except OSError:
            return 0

    def _cache_remove_scope_locked(self, scope_id: str) -> None:
        old = self._usage_scopes.pop(scope_id, None)
        if old is None:
            return
        owner, size = old
        self._usage_global_bytes = max(0, self._usage_global_bytes - size)
        owner_size = max(0, self._usage_owner_bytes.get(owner, 0) - size)
        owner_scopes = max(0, self._usage_owner_scopes.get(owner, 0) - 1)
        if owner_size:
            self._usage_owner_bytes[owner] = owner_size
        else:
            self._usage_owner_bytes.pop(owner, None)
        if owner_scopes:
            self._usage_owner_scopes[owner] = owner_scopes
        else:
            self._usage_owner_scopes.pop(owner, None)

    def _cache_set_scope_locked(self, scope_id: str, owner: str, size: int) -> None:
        self._cache_remove_scope_locked(scope_id)
        size = max(0, int(size))
        owner = str(owner or "")
        self._usage_scopes[scope_id] = (owner, size)
        self._usage_global_bytes += size
        self._usage_owner_bytes[owner] = self._usage_owner_bytes.get(owner, 0) + size
        self._usage_owner_scopes[owner] = self._usage_owner_scopes.get(owner, 0) + 1

    def _ensure_usage_cache_locked(self, *, refresh: bool = False) -> None:
        if self._usage_cache_ready and not refresh:
            return
        scopes: dict[str, tuple[str, int]] = {}
        global_bytes = 0
        owner_bytes: dict[str, int] = {}
        owner_scopes: dict[str, int] = {}
        for scope_id, item in self._iter_manifests():
            owner = str(item.get("owner") or "")
            size = self._scope_stored_size(scope_id)
            scopes[scope_id] = (owner, size)
            global_bytes += size
            owner_bytes[owner] = owner_bytes.get(owner, 0) + size
            owner_scopes[owner] = owner_scopes.get(owner, 0) + 1
        self._usage_scopes = scopes
        self._usage_global_bytes = global_bytes
        self._usage_owner_bytes = owner_bytes
        self._usage_owner_scopes = owner_scopes
        self._usage_cache_ready = True

    def _refresh_scope_usage_locked(self, scope_id: str, owner: str) -> None:
        """Update one cached scope after a successful filesystem mutation."""
        if not self._usage_cache_ready:
            return
        manifest_path = self._scope_dir(scope_id) / "manifest.bin"
        if not manifest_path.is_file():
            self._cache_remove_scope_locked(scope_id)
            return
        self._cache_set_scope_locked(
            scope_id,
            str(owner or ""),
            self._scope_stored_size(scope_id),
        )

    def _aad(self, scope_id: str, kind: str) -> bytes:
        return f"payment-chat-archive:v1:{scope_id}:{kind}".encode("ascii")

    def _encrypt(self, scope_id: str, kind: str, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return b"PCA1" + nonce + self.aes.encrypt(nonce, data, self._aad(scope_id, kind))

    def _decrypt(self, scope_id: str, kind: str, data: bytes) -> bytes:
        if not data.startswith(b"PCA1") or len(data) < 32:
            raise PaymentChatArchiveError("invalid encrypted archive")
        try:
            return self.aes.decrypt(data[4:16], data[16:], self._aad(scope_id, kind))
        except Exception as exc:
            raise PaymentChatArchiveError("cannot decrypt archive") from exc

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            os.chmod(path, 0o600)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _empty(self, owner: str, profile_id: str, chat_key: str) -> dict:
        now = _utc_iso()
        return {
            "version": 1,
            "owner": str(owner),
            "profile_id": str(profile_id),
            "chat_key": str(chat_key),
            "status": "pending",
            "messages": [],
            "media": [],
            "truncated": False,
            "last_error": "",
            "created_at": now,
            "captured_at": "",
            "updated_at": now,
        }

    def _read_manifest_id(self, scope_id: str) -> dict | None:
        path = self._scope_dir(scope_id) / "manifest.bin"
        if not path.exists():
            return None
        try:
            raw = self._decrypt(scope_id, "manifest", path.read_bytes())
            result = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise PaymentChatArchiveError("corrupt archive manifest") from exc
        if not isinstance(result, dict) or int(result.get("version") or 0) != 1:
            raise PaymentChatArchiveError("unsupported archive manifest")
        return result

    def _write_manifest_id(self, scope_id: str, manifest: dict) -> None:
        raw = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = self._encrypt(scope_id, "manifest", raw)
        self._atomic_write(self._scope_dir(scope_id) / "manifest.bin", encrypted)

    @staticmethod
    def _manifest_stored_size(manifest: dict) -> int:
        raw = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return len(raw) + 32  # PCA1 + nonce + AES-GCM tag

    def _checked_manifest(self, owner: str, profile_id: str, chat_key: str) -> tuple[str, dict | None]:
        scope_id = self._scope_id(owner, profile_id, chat_key)
        manifest = self._read_manifest_id(scope_id)
        if manifest is not None and (
            manifest.get("owner") != str(owner)
            or manifest.get("profile_id") != str(profile_id)
            or manifest.get("chat_key") != str(chat_key)
        ):
            raise PaymentChatArchiveError("archive scope mismatch")
        return scope_id, manifest

    @staticmethod
    def _message(item: dict, now: str) -> dict | None:
        if not isinstance(item, dict):
            return None
        try:
            message_id = int(item.get("id") or item.get("message_id") or 0)
        except (TypeError, ValueError):
            return None
        if message_id <= 0:
            return None
        text = str(item.get("text") or "").strip()[:16_000]
        if not text and not item.get("has_media"):
            return None
        direction = "outgoing" if item.get("direction") == "outgoing" else "incoming"
        revisions = []
        for revision in list(item.get("revisions") or [])[-3:]:
            if not isinstance(revision, dict):
                continue
            old_text = str(revision.get("text") or "").strip()[:16_000]
            if old_text:
                revisions.append({
                    "text": old_text,
                    "captured_at": str(revision.get("captured_at") or now)[:40],
                })
        original_text = str(item.get("original_text") or text).strip()[:16_000]
        return {
            "id": message_id,
            "direction": direction,
            "text": text,
            "at": str(item.get("at") or "")[:40],
            "edited_at": str(item.get("edited_at") or "")[:40],
            "has_media": bool(item.get("has_media")),
            "media_type": str(item.get("media_type") or "")[:80],
            "media_saved": bool(item.get("media_saved")),
            "first_captured_at": str(item.get("first_captured_at") or now)[:40],
            "last_seen_at": now,
            "original_text": original_text,
            "original_captured_at": str(
                item.get("original_captured_at") or item.get("first_captured_at") or now
            )[:40],
            "revisions": revisions,
        }

    @staticmethod
    def _text_size(item: dict) -> int:
        values = [str(item.get("text") or ""), str(item.get("original_text") or "")]
        values.extend(
            str(revision.get("text") or "")
            for revision in (item.get("revisions") or [])
            if isinstance(revision, dict)
        )
        unique = []
        seen = set()
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            unique.append(value)
        return sum(len(value.encode("utf-8")) for value in unique)

    def mark_status(
        self,
        owner: str,
        profile_id: str,
        chat_key: str,
        status: str,
        *,
        error: str = "",
        truncated: bool | None = None,
        reset_truncated: bool = False,
        reopen_purged: bool = False,
    ) -> dict:
        if status not in _VALID_STATUSES:
            raise ValueError("invalid archive status")
        scope_id = self._scope_id(owner, profile_id, chat_key)
        with ExitStack() as stack:
            stack.enter_context(self._quota_lock)
            stack.enter_context(self._lock(scope_id))
            manifest = self._read_manifest_id(scope_id) or self._empty(owner, profile_id, chat_key)
            if manifest.get("status") != "purged" or status == "purged" or reopen_purged:
                if manifest.get("status") == "purged" and reopen_purged:
                    manifest = self._empty(owner, profile_id, chat_key)
                manifest["status"] = status
                clean_error = re.sub(r"[^a-zA-Z0-9_.:-]", "", str(error or ""))[:80]
                if reset_truncated:
                    manifest["truncated"] = bool(truncated)
                elif truncated is not None:
                    manifest["truncated"] = bool(manifest.get("truncated") or truncated)
                if clean_error or reset_truncated or not manifest.get("truncated"):
                    manifest["last_error"] = clean_error
                manifest["updated_at"] = _utc_iso()
                if status == "ready":
                    manifest["captured_at"] = manifest["updated_at"]
                self._write_manifest_id(scope_id, manifest)
                self._refresh_scope_usage_locked(scope_id, str(owner))
        return self.summary(owner, profile_id, chat_key)

    def merge(
        self,
        owner: str,
        profile_id: str,
        chat_key: str,
        messages,
        *,
        media=None,
        status: str = "ready",
        truncated: bool = False,
        captured_at=None,
        error: str = "",
        reopen_purged: bool = False,
        reopen_at=None,
        case_outbox: dict | None = None,
    ) -> dict:
        if status not in _VALID_STATUSES:
            raise ValueError("invalid archive status")
        scope_id = self._scope_id(owner, profile_id, chat_key)
        now = _utc_iso(captured_at)
        with ExitStack() as stack:
            stack.enter_context(self._quota_lock)
            stack.enter_context(self._lock(scope_id))
            manifest_path = self._scope_dir(scope_id) / "manifest.bin"
            manifest_existed = manifest_path.is_file()
            manifest = self._read_manifest_id(scope_id) or self._empty(owner, profile_id, chat_key)
            original_manifest = copy.deepcopy(manifest)
            usage = self.usage(str(owner))
            owner_usage = int(usage["owner_bytes"])
            global_usage = int(usage["global_bytes"])
            try:
                free_bytes = int(shutil.disk_usage(self.root).free)
            except OSError:
                free_bytes = 0
            if manifest.get("status") == "purged":
                newer_event = False
                if reopen_at is not None:
                    try:
                        newer_event = _utc_iso(reopen_at) > _utc_iso(
                            manifest.get("purged_at")
                            or manifest.get("captured_at")
                            or manifest.get("updated_at")
                        )
                    except Exception:
                        newer_event = False
                if not reopen_purged or not newer_event:
                    manifest = None
                else:
                    manifest = self._empty(owner, profile_id, chat_key)
            if manifest is None:
                # A stale capture must never recreate data after the administrator
                # chose «Оставить только оплаты».
                pass
            else:
                if case_outbox is not None:
                    if not isinstance(case_outbox, dict):
                        raise ValueError("invalid case outbox")
                    encoded_outbox = json.dumps(
                        case_outbox, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")
                    if len(encoded_outbox) > 128 * 1024:
                        raise ValueError("case outbox too large")
                    manifest["case_outbox"] = copy.deepcopy(case_outbox)
                existing = {int(row["id"]): row for row in manifest.get("messages") or [] if row.get("id")}
                text_bytes = sum(self._text_size(row) for row in existing.values())
                evicted_ids: set[int] = set()
                incoming = []
                for item in messages or []:
                    clean = self._message(item, now)
                    if clean is not None:
                        incoming.append(clean)
                # Newest-first ensures a new trigger is never displaced by an old backlog.
                for clean in sorted(incoming, key=lambda row: row["id"], reverse=True):
                    previous = existing.get(clean["id"])
                    if previous is not None:
                        old_text = str(previous.get("text") or "")
                        new_text = str(clean.get("text") or "")
                        revisions = list(previous.get("revisions") or [])
                        if old_text and new_text and old_text != new_text:
                            revisions.append({"text": old_text, "captured_at": previous.get("last_seen_at") or now})
                        clean["revisions"] = revisions[-3:]
                        clean["first_captured_at"] = previous.get("first_captured_at") or now
                        clean["original_text"] = previous.get("original_text") or old_text or new_text
                        clean["original_captured_at"] = (
                            previous.get("original_captured_at")
                            or previous.get("first_captured_at")
                            or now
                        )
                        text_bytes -= self._text_size(previous)

                    new_size = self._text_size(clean)
                    # Prefer the newest trigger/revision: when a safety limit is full,
                    # evict the oldest context instead of silently dropping the signal.
                    while existing and (
                        (previous is None and len(existing) >= self.max_messages)
                        or text_bytes + new_size > self.max_text_bytes
                    ):
                        candidates = [message_id for message_id in existing if message_id != clean["id"]]
                        if not candidates:
                            break
                        oldest_id = min(candidates)
                        oldest = existing.pop(oldest_id)
                        evicted_ids.add(oldest_id)
                        text_bytes -= self._text_size(oldest)
                        truncated = True
                    if text_bytes + new_size > self.max_text_bytes:
                        # A single Telegram message cannot normally hit this branch,
                        # but keep the previous version intact if an invalid input does.
                        if previous is not None:
                            text_bytes += self._text_size(previous)
                        truncated = True
                        continue
                    existing[clean["id"]] = clean
                    text_bytes += new_size

                media_rows = {str(row.get("file_id")): row for row in manifest.get("media") or [] if row.get("file_id")}
                for file_id, row in list(media_rows.items()):
                    if int(row.get("message_id") or 0) not in evicted_ids:
                        continue
                    media_rows.pop(file_id, None)
                total_media = sum(int(row.get("size") or 0) for row in media_rows.values())
                quota_hit = False
                new_media_file_ids: set[str] = set()
                for item in media or []:
                    if not isinstance(item, dict):
                        continue
                    try:
                        message_id = int(item.get("message_id") or item.get("id") or 0)
                    except (TypeError, ValueError):
                        continue
                    raw = item.get("data")
                    if message_id <= 0 or not isinstance(raw, (bytes, bytearray)):
                        continue
                    data = bytes(raw)
                    mime = _image_mime(data, str(item.get("mime") or ""))
                    if not mime or not data or len(data) > self.max_media_bytes:
                        truncated = True
                        continue
                    file_id = hashlib.sha256(f"{message_id}:{mime}".encode("ascii") + data).hexdigest()[:24] + ".bin"
                    if file_id in media_rows:
                        if message_id in existing:
                            existing[message_id]["has_media"] = True
                            existing[message_id]["media_saved"] = True
                            existing[message_id]["media_type"] = mime
                        continue
                    if len(media_rows) >= self.max_media_items:
                        truncated = True
                        continue
                    if total_media + len(data) > self.max_total_media_bytes:
                        truncated = True
                        continue
                    encrypted = self._encrypt(scope_id, f"media:{file_id}", data)
                    stored_size = len(encrypted)
                    if (
                        (self.max_owner_bytes and owner_usage + stored_size > self.max_owner_bytes)
                        or (self.max_global_bytes and global_usage + stored_size > self.max_global_bytes)
                        or (self.min_free_bytes and free_bytes and free_bytes - stored_size < self.min_free_bytes)
                    ):
                        truncated = True
                        quota_hit = True
                        continue
                    self._atomic_write(self._scope_dir(scope_id) / file_id, encrypted)
                    new_media_file_ids.add(file_id)
                    row = {
                        "file_id": file_id,
                        "message_id": message_id,
                        "mime": mime,
                        "size": len(data),
                        "captured_at": now,
                    }
                    media_rows[file_id] = row
                    total_media += len(data)
                    owner_usage += stored_size
                    global_usage += stored_size
                    if free_bytes:
                        free_bytes = max(0, free_bytes - stored_size)
                    if message_id in existing:
                        existing[message_id]["has_media"] = True
                        existing[message_id]["media_saved"] = True
                        existing[message_id]["media_type"] = mime

                manifest["messages"] = [existing[key] for key in sorted(existing)]
                manifest["media"] = sorted(
                    media_rows.values(),
                    key=lambda row: (
                        int(row.get("message_id") or 0),
                        str(row.get("captured_at") or ""),
                        str(row.get("file_id") or ""),
                    ),
                )
                manifest["status"] = status
                manifest["truncated"] = bool(manifest.get("truncated") or truncated)
                clean_error = re.sub(r"[^a-zA-Z0-9_.:-]", "", str(error or ""))[:80]
                if clean_error:
                    manifest["last_error"] = clean_error
                elif quota_hit:
                    manifest["last_error"] = "storage_quota"
                manifest["updated_at"] = now
                if status == "ready":
                    manifest["captured_at"] = now

                old_manifest_size = manifest_path.stat().st_size if manifest_existed else 0
                candidate_size = self._manifest_stored_size(manifest)
                positive_delta = max(0, candidate_size - old_manifest_size)
                manifest_quota_hit = bool(
                    (self.max_owner_bytes and owner_usage + positive_delta > self.max_owner_bytes)
                    or (self.max_global_bytes and global_usage + positive_delta > self.max_global_bytes)
                )
                if manifest_quota_hit:
                    if case_outbox is not None and manifest.get("messages"):
                        newest = max(
                            manifest["messages"], key=lambda row: int(row.get("id") or 0)
                        )
                        newest_id = int(newest.get("id") or 0)
                        newest_media = [
                            row for row in manifest.get("media") or []
                            if int(row.get("message_id") or 0) == newest_id
                        ]
                        manifest = self._empty(owner, profile_id, chat_key)
                        manifest["messages"] = [newest]
                        manifest["media"] = newest_media
                        manifest["case_outbox"] = copy.deepcopy(case_outbox)
                    elif manifest_existed and original_manifest.get("status") != "purged":
                        manifest = original_manifest
                    else:
                        newest = max(
                            (self._message(item, now) for item in (messages or [])),
                            key=lambda row: row.get("id", 0) if row else 0,
                            default=None,
                        )
                        manifest = self._empty(owner, profile_id, chat_key)
                        manifest["messages"] = [newest] if newest else []
                        manifest["media"] = []
                    manifest["status"] = status
                    manifest["truncated"] = True
                    manifest["last_error"] = "storage_quota"
                    manifest["updated_at"] = now
                    if status == "ready":
                        manifest["captured_at"] = now
                    candidate_size = self._manifest_stored_size(manifest)
                    positive_delta = max(0, candidate_size - old_manifest_size)
                if (
                    self.min_free_bytes
                    and free_bytes
                    and free_bytes - positive_delta < self.min_free_bytes
                ):
                    for file_id in new_media_file_ids:
                        path = self._scope_dir(scope_id) / file_id
                        if path.is_file():
                            path.unlink()
                    raise PaymentChatArchiveError("archive storage reserve reached")
                try:
                    self._write_manifest_id(scope_id, manifest)
                except BaseException:
                    for file_id in new_media_file_ids:
                        path = self._scope_dir(scope_id) / file_id
                        if path.is_file():
                            path.unlink()
                    raise
                referenced_media = {
                    str(row.get("file_id") or "") for row in manifest.get("media") or []
                }
                for path in self._scope_dir(scope_id).iterdir():
                    if (
                        path.is_file()
                        and _SAFE_FILE_RE.fullmatch(path.name)
                        and path.name not in referenced_media
                    ):
                        path.unlink()
                self._refresh_scope_usage_locked(scope_id, str(owner))
        return self.summary(owner, profile_id, chat_key)

    def clear_case_outbox(self, owner: str, profile_id: str, chat_key: str) -> dict:
        scope_id = self._scope_id(owner, profile_id, chat_key)
        with ExitStack() as stack:
            stack.enter_context(self._quota_lock)
            stack.enter_context(self._lock(scope_id))
            manifest = self._read_manifest_id(scope_id)
            if manifest is not None and "case_outbox" in manifest:
                manifest.pop("case_outbox", None)
                manifest["updated_at"] = _utc_iso()
                self._write_manifest_id(scope_id, manifest)
                self._refresh_scope_usage_locked(scope_id, str(owner))
        return self.summary(owner, profile_id, chat_key)

    def list_case_outboxes(self) -> list[dict]:
        result = []
        for _scope_id, manifest in self._iter_manifests():
            outbox = manifest.get("case_outbox")
            if not isinstance(outbox, dict):
                continue
            result.append({
                "owner": manifest.get("owner"),
                "profile_id": manifest.get("profile_id"),
                "chat_key": manifest.get("chat_key"),
                "outbox": copy.deepcopy(outbox),
            })
        return result

    def load(self, owner: str, profile_id: str, chat_key: str) -> dict | None:
        scope_id = self._scope_id(owner, profile_id, chat_key)
        with self._lock(scope_id):
            _scope_id, manifest = self._checked_manifest(owner, profile_id, chat_key)
            return manifest

    def summary(self, owner: str, profile_id: str, chat_key: str) -> dict:
        scope_id = self._scope_id(owner, profile_id, chat_key)
        try:
            with self._lock(scope_id):
                _scope_id, manifest = self._checked_manifest(owner, profile_id, chat_key)
                size = 0
                scope_dir = self._scope_dir(scope_id)
                if scope_dir.is_dir():
                    size = sum(path.stat().st_size for path in scope_dir.iterdir() if path.is_file())
        except PaymentChatArchiveError:
            return {
                "status": "error", "message_count": 0, "media_count": 0,
                "captured_at": "", "truncated": False, "last_error": "archive_corrupt",
                "size_bytes": 0,
            }
        if manifest is None:
            return {
                "status": "missing", "message_count": 0, "media_count": 0,
                "captured_at": "", "truncated": False, "last_error": "", "size_bytes": 0,
            }
        return {
            "status": str(manifest.get("status") or "missing"),
            "message_count": len(manifest.get("messages") or []),
            "media_count": len(manifest.get("media") or []),
            "captured_at": str(manifest.get("captured_at") or manifest.get("updated_at") or ""),
            "truncated": bool(manifest.get("truncated")),
            "last_error": str(manifest.get("last_error") or "")[:80],
            "size_bytes": int(size),
        }

    def read_media(self, owner: str, profile_id: str, chat_key: str, file_id: str) -> tuple[bytes, str]:
        if not _SAFE_FILE_RE.fullmatch(str(file_id or "")):
            raise KeyError("media not found")
        scope_id = self._scope_id(owner, profile_id, chat_key)
        with self._lock(scope_id):
            _scope_id, manifest = self._checked_manifest(owner, profile_id, chat_key)
            if manifest is None:
                raise KeyError("media not found")
            row = next((item for item in manifest.get("media") or [] if item.get("file_id") == file_id), None)
            if row is None:
                raise KeyError("media not found")
            path = self._scope_dir(scope_id) / file_id
            if path.parent != self._scope_dir(scope_id) or not path.is_file():
                raise KeyError("media not found")
            raw = self._decrypt(scope_id, f"media:{file_id}", path.read_bytes())
            mime = _image_mime(raw, str(row.get("mime") or ""))
            if not mime:
                raise PaymentChatArchiveError("invalid archived media")
            return raw, mime

    def purge(self, owner: str, profile_id: str, chat_key: str, *, tombstone: bool = True) -> dict:
        scope_id = self._scope_id(owner, profile_id, chat_key)
        with ExitStack() as stack:
            stack.enter_context(self._quota_lock)
            stack.enter_context(self._lock(scope_id))
            scope_dir = self._scope_dir(scope_id)
            previous = None
            try:
                previous = self._read_manifest_id(scope_id)
            except PaymentChatArchiveError:
                previous = None
            purged_max = max(
                (int(row.get("id") or 0) for row in (previous or {}).get("messages") or []),
                default=0,
            )
            if scope_dir.exists():
                shutil.rmtree(scope_dir)
            if tombstone:
                manifest = self._empty(owner, profile_id, chat_key)
                purged_at = _utc_iso()
                manifest.update({
                    "status": "purged",
                    "messages": [],
                    "media": [],
                    "captured_at": purged_at,
                    "purged_at": purged_at,
                    "purged_max_message_id": purged_max,
                })
                self._write_manifest_id(scope_id, manifest)
            self._refresh_scope_usage_locked(scope_id, str(owner))
        return self.summary(owner, profile_id, chat_key)

    def _iter_manifests(self):
        if not self.root.exists():
            return
        for path in self.root.iterdir():
            if not path.is_dir() or not re.fullmatch(r"[0-9a-f]{32}", path.name):
                continue
            try:
                manifest = self._read_manifest_id(path.name)
            except PaymentChatArchiveError:
                continue
            if manifest is not None:
                yield path.name, manifest

    def list_statuses(self, statuses=("pending", "error")) -> list[dict]:
        allowed = set(statuses or ())
        return [
            {
                "owner": item.get("owner"), "profile_id": item.get("profile_id"),
                "chat_key": item.get("chat_key"), "status": item.get("status"),
                "updated_at": item.get("updated_at"), "last_error": item.get("last_error"),
            }
            for _scope_id, item in self._iter_manifests()
            if item.get("status") in allowed
        ]

    def find_chat(self, owner: str, chat_key: str) -> tuple[str, dict] | None:
        """Find an archive after its Telegram profile has been detached."""
        owner = str(owner or "")
        chat_key = str(chat_key or "")
        if not owner or not chat_key:
            return None
        # Directory identity deliberately ignores profile_id because chat_key
        # already contains it. This makes a detached lookup O(1) and keeps old
        # evidence readable without decrypting every other user's manifest.
        scope_id = self._scope_id(owner, "", chat_key)
        with self._lock(scope_id):
            item = self._read_manifest_id(scope_id)
        if item is None:
            return None
        if item.get("owner") != owner or item.get("chat_key") != chat_key:
            raise PaymentChatArchiveError("archive scope mismatch")
        return str(item.get("profile_id") or ""), item

    def usage(self, owner: str | None = None, *, refresh: bool = False) -> dict:
        """Return encrypted on-disk usage without repeatedly scanning archives.

        The first call builds a per-instance cache.  Every mutation performed
        through this instance updates only the affected scope.  ``refresh`` is
        available for operators that deliberately changed archive files using
        another process.
        """
        owner = str(owner or "")
        with self._quota_lock:
            self._ensure_usage_cache_locked(refresh=bool(refresh))
            return {
                "global_bytes": int(self._usage_global_bytes),
                "owner_bytes": int(self._usage_owner_bytes.get(owner, 0)) if owner else 0,
                "scopes": len(self._usage_scopes),
                "owner_scopes": int(self._usage_owner_scopes.get(owner, 0)) if owner else 0,
            }

    def _purge_matching(self, predicate) -> int:
        with self._quota_lock:
            targets = [scope_id for scope_id, item in self._iter_manifests() if predicate(item)]
            for scope_id in targets:
                with self._lock(scope_id):
                    scope_dir = self._scope_dir(scope_id)
                    if scope_dir.exists():
                        shutil.rmtree(scope_dir)
                    if self._usage_cache_ready:
                        self._cache_remove_scope_locked(scope_id)
        return len(targets)

    def purge_owner(self, owner: str) -> int:
        return self._purge_matching(lambda item: item.get("owner") == str(owner))

    def purge_profile(self, owner: str, profile_id: str) -> int:
        return self._purge_matching(
            lambda item: item.get("owner") == str(owner) and item.get("profile_id") == str(profile_id)
        )

    def cleanup(self, retention_days: int, now=None) -> int:
        cutoff = datetime.fromisoformat(_utc_iso(now)) - timedelta(days=max(1, int(retention_days)))

        def stale(item):
            try:
                changed = datetime.fromisoformat(str(item.get("updated_at") or item.get("created_at")))
                if changed.tzinfo is None:
                    changed = changed.replace(tzinfo=timezone.utc)
                return changed < cutoff
            except Exception:
                return True

        return self._purge_matching(stale)
