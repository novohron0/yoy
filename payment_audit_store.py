"""SQLite storage for consent-based payment audit signals.

The store deliberately keeps only short, masked evidence fragments. Telegram
media is never stored here; callers may pass a content hash for deduplication.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


USER_CASE_STATUSES = {
    "pending",
    "income",
    "not_received",
    "personal",
    "refund",
    "duplicate",
    "disputed",
}
ADMIN_CASE_STATUSES = {"pending", "confirmed", "dismissed", "needs_info"}

_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE)
_NUMBER_SEPARATOR = r"\s\-•·/."
_IBAN_RE = re.compile(
    rf"(?<![A-Z0-9])[A-Z]{{2}}\d{{2}}(?:[{_NUMBER_SEPARATOR}]?[A-Z0-9]){{11,30}}(?![A-Z0-9])",
    re.IGNORECASE,
)
_LONG_NUMBER_RE = re.compile(
    rf"(?<!\d)\d(?:[{_NUMBER_SEPARATOR}]?\d){{6,33}}(?!\d)"
)
_SPACE_RE = re.compile(r"\s+")

_EVENT_STATUSES = {
    "possible", "intent", "requested", "receipt", "completed",
    "failed_or_reversed", "retracted", "none",
}
_ATTRIBUTIONS = {"direct", "forwarded", "quote", "forwarded_quote", "unknown"}
_STATE_PRIORITY = {
    "none": 0,
    "possible": 1,
    "intent": 2,
    "requested": 3,
    "receipt": 4,
    "completed": 5,
    "failed_or_reversed": 6,
    "retracted": 7,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_event_time(value: str | datetime | None) -> str:
    if isinstance(value, datetime):
        dt = value
    elif value:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def mask_sensitive_text(text: str, limit: int = 240) -> str:
    """Collapse whitespace and hide common financial/contact identifiers."""

    def hide(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return f"••••{digits[-4:]}" if len(digits) >= 4 else "••••"

    def hide_iban(match: re.Match) -> str:
        compact = re.sub(rf"[{_NUMBER_SEPARATOR}]", "", match.group(0))
        return f"IBAN ••••{compact[-4:]}"

    clean = _SPACE_RE.sub(" ", (text or "").strip())
    clean = _EMAIL_RE.sub("[email]", clean)
    clean = _IBAN_RE.sub(hide_iban, clean)
    clean = _LONG_NUMBER_RE.sub(hide, clean)
    return clean[: max(0, int(limit))]


def normalize_chat_context(context, *, limit: int = 5, snippet_limit: int = 120) -> list[dict]:
    """Keep a short masked window of surrounding chat lines for quick review."""
    rows: list[dict] = []
    seen: set[str] = set()
    for item in context or []:
        if not isinstance(item, dict):
            continue
        snippet = mask_sensitive_text(str(item.get("snippet") or ""), snippet_limit)
        if not snippet:
            continue
        direction = "outgoing" if item.get("direction") == "outgoing" else "incoming"
        key = f"{direction}:{snippet.casefold()}"
        if key in seen:
            continue
        seen.add(key)
        rows.append({"direction": direction, "snippet": snippet})
    return rows[-max(1, int(limit)):]


class PaymentAuditStore:
    """Small transactional store; a fresh SQLite connection is used per call."""

    def __init__(self, path: str, secret: str, *, retention_days: int = 60,
                 report_retention_days: int = 370,
                 correlation_minutes: int = 120):
        self.path = str(path)
        self.secret = (secret or "payment-audit").encode("utf-8")
        requested_retention = int(retention_days)
        self.retention_days = 0 if requested_retention <= 0 else max(7, requested_retention)
        self.report_retention_days = max(
            self.retention_days, 7, int(report_retention_days)
        )
        self.correlation_minutes = max(15, int(correlation_minutes))
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=5000")
            return db
        except BaseException:
            db.close()
            raise

    @contextmanager
    def _connection(self):
        """Yield one transaction and always close its SQLite connection."""
        db = self._connect()
        try:
            yield db
            if db.in_transaction:
                db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()
            # WAL/SHM can contain the same sensitive rows as the main database.
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.chmod(self.path + suffix, 0o600)
                except OSError:
                    pass

    def _init_db(self) -> None:
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_cases (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_active INTEGER NOT NULL DEFAULT 1,
                    chat_key TEXT NOT NULL,
                    chat_ref INTEGER,
                    first_at TEXT NOT NULL,
                    last_at TEXT NOT NULL,
                    base_score INTEGER NOT NULL DEFAULT 0,
                    score INTEGER NOT NULL DEFAULT 0,
                    level TEXT NOT NULL DEFAULT 'low',
                    categories_json TEXT NOT NULL DEFAULT '[]',
                    amounts_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    directions_json TEXT NOT NULL DEFAULT '[]',
                    media_hashes_json TEXT NOT NULL DEFAULT '[]',
                    event_status TEXT NOT NULL DEFAULT 'possible',
                    income_claim INTEGER NOT NULL DEFAULT 0,
                    attribution TEXT NOT NULL DEFAULT 'unknown',
                    state_at TEXT,
                    state_message_ref TEXT NOT NULL DEFAULT '',
                    user_status TEXT NOT NULL DEFAULT 'pending',
                    user_note TEXT NOT NULL DEFAULT '',
                    user_responded_at TEXT,
                    admin_status TEXT NOT NULL DEFAULT 'pending',
                    admin_note TEXT NOT NULL DEFAULT '',
                    admin_amount REAL,
                    admin_reviewed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_cases_owner_time
                    ON payment_cases(owner, last_at DESC);
                CREATE INDEX IF NOT EXISTS idx_payment_cases_profile_chat
                    ON payment_cases(profile_id, chat_key, last_at DESC);

                CREATE TABLE IF NOT EXISTS payment_events (
                    event_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    message_ref TEXT NOT NULL DEFAULT '',
                    observed_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_status TEXT NOT NULL DEFAULT 'possible',
                    income_claim INTEGER NOT NULL DEFAULT 0,
                    attribution TEXT NOT NULL DEFAULT 'unknown',
                    FOREIGN KEY(case_id) REFERENCES payment_cases(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_payment_events_case
                    ON payment_events(case_id);

                CREATE TABLE IF NOT EXISTS payment_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    old_value TEXT NOT NULL DEFAULT '',
                    new_value TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS payment_weekly_reports (
                    owner TEXT NOT NULL,
                    week_start TEXT NOT NULL,
                    amount REAL NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    submitted_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(owner, week_start)
                );

                CREATE TABLE IF NOT EXISTS payment_weekly_report_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner TEXT NOT NULL,
                    week_start TEXT NOT NULL,
                    old_amount REAL,
                    new_amount REAL NOT NULL,
                    old_note TEXT NOT NULL DEFAULT '',
                    new_note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_week_log_owner_week
                    ON payment_weekly_report_log(owner, week_start, id DESC);
                """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(payment_cases)")}
            case_migrations = {
                "base_score": "INTEGER NOT NULL DEFAULT 0",
                "event_status": "TEXT NOT NULL DEFAULT 'possible'",
                "income_claim": "INTEGER NOT NULL DEFAULT 0",
                "attribution": "TEXT NOT NULL DEFAULT 'unknown'",
                "state_at": "TEXT",
                "state_message_ref": "TEXT NOT NULL DEFAULT ''",
                "chat_ref": "INTEGER",
                "profile_active": "INTEGER NOT NULL DEFAULT 1",
            }
            for name, definition in case_migrations.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE payment_cases ADD COLUMN {name} {definition}")
            if "base_score" not in columns:
                db.execute("UPDATE payment_cases SET base_score=score")
            db.execute("UPDATE payment_cases SET state_at=last_at WHERE state_at IS NULL")

            event_columns = {row[1] for row in db.execute("PRAGMA table_info(payment_events)")}
            event_migrations = {
                "message_ref": "TEXT NOT NULL DEFAULT ''",
                "event_status": "TEXT NOT NULL DEFAULT 'possible'",
                "income_claim": "INTEGER NOT NULL DEFAULT 0",
                "attribution": "TEXT NOT NULL DEFAULT 'unknown'",
            }
            for name, definition in event_migrations.items():
                if name not in event_columns:
                    db.execute(f"ALTER TABLE payment_events ADD COLUMN {name} {definition}")

            # Older builds stored the raw ``profile:chat:message`` correlation
            # value. Keep correlation working while replacing it in place with
            # a one-way reference and preserving only the numeric private-chat id.
            for event in db.execute(
                "SELECT event_key, case_id, message_ref FROM payment_events "
                "WHERE message_ref<>''"
            ).fetchall():
                raw_ref = str(event["message_ref"])
                safe_ref = self._message_ref(event["event_key"], raw_ref)
                if safe_ref != raw_ref:
                    parts = raw_ref.rsplit(":", 2)
                    if len(parts) == 3:
                        try:
                            legacy_chat_ref = self._normalize_chat_ref(parts[1])
                        except ValueError:
                            legacy_chat_ref = None
                        if legacy_chat_ref is not None:
                            db.execute(
                                "UPDATE payment_cases SET chat_ref=COALESCE(chat_ref, ?) WHERE id=?",
                                (legacy_chat_ref, event["case_id"]),
                            )
                    db.execute(
                        "UPDATE payment_events SET message_ref=? WHERE event_key=?",
                        (safe_ref, event["event_key"]),
                    )

            for case in db.execute(
                "SELECT id, state_message_ref, evidence_json FROM payment_cases"
            ).fetchall():
                updates = {}
                state_ref = str(case["state_message_ref"] or "")
                if state_ref:
                    safe_state_ref = self._message_ref("", state_ref)
                    if safe_state_ref != state_ref:
                        updates["state_message_ref"] = safe_state_ref
                evidence = self._loads(case["evidence_json"], [])
                redacted_evidence = []
                evidence_changed = False
                for item in evidence if isinstance(evidence, list) else []:
                    if not isinstance(item, dict):
                        redacted_evidence.append(item)
                        continue
                    clean_item = dict(item)
                    if "message_ref" in clean_item:
                        clean_item.pop("message_ref", None)
                        evidence_changed = True
                    redacted_evidence.append(clean_item)
                if evidence_changed:
                    updates["evidence_json"] = json.dumps(
                        redacted_evidence, ensure_ascii=False
                    )
                if updates:
                    assignments = ", ".join(f"{name}=?" for name in updates)
                    db.execute(
                        f"UPDATE payment_cases SET {assignments} WHERE id=?",
                        (*updates.values(), case["id"]),
                    )

            # Apply the current tier/corroboration policy to retained cases too;
            # otherwise a pre-upgrade generic 0.70 signal could remain "high".
            for case in db.execute(
                """SELECT id, base_score, categories_json, amounts_json,
                          directions_json, media_hashes_json, event_status,
                          income_claim, score, level
                   FROM payment_cases"""
            ).fetchall():
                recalculated = self._case_score(
                    int(case["base_score"] or 0),
                    set(self._loads(case["categories_json"], [])),
                    self._amount_values(self._loads(case["amounts_json"], [])),
                    set(self._loads(case["directions_json"], [])),
                    set(self._loads(case["media_hashes_json"], [])),
                    str(case["event_status"] or "possible"),
                    bool(case["income_claim"]),
                )
                level = self._level(recalculated)
                if recalculated != case["score"] or level != case["level"]:
                    db.execute(
                        "UPDATE payment_cases SET score=?, level=? WHERE id=?",
                        (recalculated, level, case["id"]),
                    )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_payment_events_message_ref "
                "ON payment_events(message_ref)"
            )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def chat_key(self, profile_id: str, chat_id: int | str) -> str:
        raw = f"{profile_id}:{chat_id}".encode("utf-8")
        return hmac.new(self.secret, raw, hashlib.sha256).hexdigest()[:12].upper()

    @staticmethod
    def message_ref(profile_id: str, chat_id: int | str, message_id: int | str) -> str:
        raw = f"{profile_id}:{chat_id}:{message_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def event_key(profile_id: str, chat_id: int | str, message_id: int | str,
                  source: str = "message") -> str:
        message_ref = PaymentAuditStore.message_ref(profile_id, chat_id, message_id)
        source_ref = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:16]
        return f"{message_ref}:{source_ref}"

    @staticmethod
    def _message_ref(event_key: str, explicit: str | None = None) -> str:
        if explicit:
            value = str(explicit).strip()
            if re.fullmatch(r"[0-9a-fA-F]{64}", value):
                return value.lower()
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
        prefix, separator, _suffix = str(event_key).partition(":")
        if separator and re.fullmatch(r"[0-9a-f]{64}", prefix):
            return prefix
        return ""

    @staticmethod
    def _normalize_chat_ref(value: int | str | None) -> int | None:
        """Accept only a positive Telegram user id that SQLite can store."""
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            raise ValueError("invalid chat_ref")
        if isinstance(value, int):
            result = value
        elif isinstance(value, str) and re.fullmatch(r"[1-9]\d{0,18}", value.strip()):
            result = int(value.strip())
        else:
            raise ValueError("invalid chat_ref")
        if result <= 0 or result > 9_223_372_036_854_775_807:
            raise ValueError("invalid chat_ref")
        return result

    def has_message(
        self,
        owner: str,
        profile_id: str,
        chat_key: str,
        message_ref: str,
    ) -> bool:
        """Return whether an active profile already contributed this message."""
        safe_ref = self._message_ref("", message_ref)
        if not safe_ref:
            return False
        with self._connection() as db:
            return db.execute(
                """SELECT 1
                   FROM payment_events e JOIN payment_cases c ON c.id=e.case_id
                   WHERE e.message_ref=? AND c.owner=? AND c.profile_id=?
                     AND c.profile_active=1 AND c.chat_key=?
                   LIMIT 1""",
                (safe_ref, owner, profile_id, chat_key),
            ).fetchone() is not None

    @staticmethod
    def _event_state(analysis: dict, categories: set[str]) -> tuple[str, bool, str]:
        status = str(analysis.get("event_status") or "").strip().lower()
        negated = bool(analysis.get("negated")) or "negated" in categories
        if negated:
            status = "failed_or_reversed"
        elif status not in _EVENT_STATUSES:
            if categories & {"transfer_completed", "payment_confirmation", "payment_received", "transfer_sent"}:
                status = "completed"
            elif categories & {"receipt", "receipt_ocr"}:
                status = "receipt"
            elif "payment_request" in categories:
                status = "requested"
            elif categories & {"payment_intent", "purchase_intent"}:
                status = "intent"
            else:
                status = "possible"

        attribution = str(analysis.get("attribution") or "direct").strip().lower()
        if attribution not in _ATTRIBUTIONS:
            attribution = "unknown"
        income_claim = bool(analysis.get("income_claim", analysis.get("success_claim", False)))
        if "income_claim" not in analysis and "success_claim" not in analysis:
            income_claim = status == "completed"
        if (
            analysis.get("attributable") is False
            or attribution != "direct"
            or status in {"failed_or_reversed", "retracted"}
        ):
            income_claim = False
        return status, income_claim, attribution

    @staticmethod
    def _is_positive_event(status: str, income_claim: bool) -> bool:
        return bool(income_claim or status in {"completed", "receipt"})

    @staticmethod
    def _state_should_advance(old_at: str, old_status: str, new_at: str, new_status: str) -> bool:
        if not old_at:
            return True
        if new_at > old_at:
            return True
        if new_at < old_at:
            return False
        return _STATE_PRIORITY.get(new_status, 0) >= _STATE_PRIORITY.get(old_status, 0)

    @staticmethod
    def _loads(value: str, default):
        try:
            return json.loads(value)
        except Exception:
            return default

    @staticmethod
    def _amount_values(items) -> list[dict]:
        out: list[dict] = []
        seen = set()
        for item in items or []:
            if isinstance(item, (int, float)):
                item = {"value": float(item), "currency": "RUB"}
            if not isinstance(item, dict):
                continue
            try:
                value = round(float(item.get("value")), 2)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value) or value <= 0 or value > 100_000_000:
                continue
            currency = str(item.get("currency") or "RUB").upper()[:8]
            key = (value, currency)
            if key in seen:
                continue
            seen.add(key)
            out.append({"value": value, "currency": currency})
        return out[:12]

    @staticmethod
    def _level(score: int) -> str:
        if score >= 75:
            return "high"
        if score >= 48:
            return "medium"
        return "low"

    @staticmethod
    def _case_score(base: int, categories: set[str], amounts: list[dict],
                    directions: set[str], media_hashes: set[str],
                    event_status: str = "possible", income_claim: bool = False) -> int:
        score = max(0, min(100, int(base or 0)))
        action = bool(categories & {
            "transfer_sent", "payment_action", "payment_received",
            "purchase_intent", "receipt", "receipt_ocr", "transfer_completed",
            "payment_confirmation", "payment_intent", "payment_request",
        })
        has_amount_action = bool(amounts and action)
        bidirectional = directions >= {"incoming", "outgoing"}
        media_amount = bool(media_hashes and amounts)
        paired_claim = bool(
            ("payment_received" in categories and "transfer_sent" in categories)
            or (
                "payment_confirmation" in categories
                and "transfer_completed" in categories
            )
        )
        if has_amount_action:
            score += 8
        if bidirectional:
            score += 8
        if media_amount:
            score += 12
        if paired_claim:
            score += 10
        if "negated" in categories:
            score -= 20
        if "duplicate_receipt" in categories:
            score -= 10
        if not (bidirectional or media_amount or paired_claim):
            # Generic store bonuses must not promote the detector's own tier.
            # The detector's thresholds are low=30, medium=48 and high=75.
            if base < 30:
                score = min(score, 29)
            elif base < 48:
                score = min(score, 47)
            elif base < 75:
                score = min(score, 74)
        if event_status == "retracted":
            score = 0
        elif event_status == "failed_or_reversed":
            # A later failure/refund remains reviewable but must not stay a high
            # confidence income case merely because an older message was positive.
            score = min(max(score, 20), 39)
        elif not income_claim and event_status == "completed":
            # A completed-looking forward/quote is a claim, not attributable income.
            score = min(score, 59)
        return max(0, min(100, score))

    def record_event(
        self,
        *,
        event_key: str,
        owner: str,
        profile_id: str,
        chat_key: str,
        observed_at: str | datetime | None,
        direction: str,
        analysis: dict,
        snippet: str = "",
        source: str = "message",
        media_hash: str = "",
        message_ref: str | None = None,
        chat_ref: int | str | None = None,
        context: list | None = None,
    ) -> dict:
        """Insert one event and conservatively correlate it with an open case.

        Text and OCR for the same Telegram message share ``message_ref`` and are
        always one case. Separate completed/receipt messages are never merged:
        without an order or provider transaction id they may be distinct income.
        """
        at = normalize_event_time(observed_at)
        now = utc_now_iso()
        categories = {str(x)[:48] for x in analysis.get("categories", []) if x}
        if analysis.get("negated"):
            categories.add("negated")
        event_status, income_claim, attribution = self._event_state(analysis, categories)
        amounts = self._amount_values(analysis.get("amounts"))
        new_hashes = {str(x)[:96] for x in analysis.get("dedup_hashes", []) if x}
        if media_hash:
            new_hashes.add(str(media_hash)[:96])
        raw_score = analysis.get("score", analysis.get("confidence", 0)) or 0
        try:
            raw_score = float(raw_score)
        except (TypeError, ValueError):
            raw_score = 0
        if not math.isfinite(raw_score):
            raw_score = 0
        base_score = round(raw_score * 100) if 0 < raw_score <= 1 else round(raw_score)
        base_score = max(0, min(100, base_score))
        direction = "outgoing" if direction == "outgoing" else "incoming"
        source = str(source)[:24]
        message_ref = self._message_ref(event_key, message_ref)
        chat_ref = self._normalize_chat_ref(chat_ref)

        event_dt = datetime.fromisoformat(at)
        cutoff = (event_dt - timedelta(minutes=self.correlation_minutes)).isoformat(timespec="seconds")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            duplicate = db.execute(
                """SELECT e.case_id, c.owner, c.profile_id, c.profile_active,
                          c.chat_key, c.chat_ref
                   FROM payment_events e JOIN payment_cases c ON c.id=e.case_id
                   WHERE e.event_key=?""",
                (event_key,),
            ).fetchone()
            if duplicate:
                if (
                    duplicate["owner"] != owner
                    or duplicate["profile_id"] != profile_id
                    or not bool(duplicate["profile_active"])
                    or duplicate["chat_key"] != chat_key
                    or (
                        duplicate["chat_ref"] is not None
                        and chat_ref is not None
                        and int(duplicate["chat_ref"]) != chat_ref
                    )
                ):
                    raise ValueError("event key belongs to another audit scope")
                row = db.execute("SELECT * FROM payment_cases WHERE id=?", (duplicate["case_id"],)).fetchone()
                db.commit()
                return self._row(row) if row else {}

            same_message = False
            row = None
            if message_ref:
                linked = db.execute(
                    """SELECT e.case_id
                       FROM payment_events e JOIN payment_cases c ON c.id=e.case_id
                       WHERE e.message_ref=? AND c.owner=? AND c.profile_id=?
                         AND c.profile_active=1 AND c.chat_key=?
                       ORDER BY e.observed_at DESC LIMIT 1""",
                    (message_ref, owner, profile_id, chat_key),
                ).fetchone()
                if linked:
                    row = db.execute(
                        "SELECT * FROM payment_cases WHERE id=?", (linked["case_id"],)
                    ).fetchone()
                    same_message = row is not None

            if row is None:
                # Один собеседник — одна карточка. Владелец проверяет людей, а не
                # разрозненные сигналы: все события чата собираются в один случай
                # независимо от паузы между ними и от того, отвечали ли на него.
                row = db.execute(
                    """
                    SELECT * FROM payment_cases
                    WHERE owner=? AND profile_id=? AND profile_active=1 AND chat_key=?
                      AND (chat_ref IS NULL OR ? IS NULL OR chat_ref=?)
                    ORDER BY last_at DESC LIMIT 1
                    """,
                    (owner, profile_id, chat_key, chat_ref, chat_ref),
                ).fetchone()

            if row is not None and not same_message:
                old_categories_for_gate = set(self._loads(row["categories_json"], []))
                old_amounts_for_gate = self._amount_values(self._loads(row["amounts_json"], []))
                has_positive_event = bool(
                    row["income_claim"]
                    or row["event_status"] in {"completed", "receipt"}
                    or old_categories_for_gate & {
                        "transfer_completed", "payment_confirmation", "payment_received",
                        "transfer_sent", "receipt", "receipt_ocr",
                    }
                )
                new_negative = event_status in {"failed_or_reversed", "retracted"}
                new_positive = self._is_positive_event(event_status, income_claim)
                existing_amount_keys = {
                    (item["value"], item["currency"]) for item in old_amounts_for_gate
                }
                new_amount_keys = {(item["value"], item["currency"]) for item in amounts}
                different_amount = bool(
                    existing_amount_keys and new_amount_keys
                    and existing_amount_keys.isdisjoint(new_amount_keys)
                )

                # Раньше каждый новый платёж в том же чате заводил отдельную
                # карточку. Теперь всё остаётся в одной: суммы копятся списком,
                # а решение принимает владелец, глядя на весь диалог целиком.
                del has_positive_event, new_negative, new_positive, different_amount

            case_id_hint = row["id"] if row else None
            duplicate_media = False
            for digest in new_hashes:
                prior = db.execute(
                    "SELECT id FROM payment_cases WHERE media_hashes_json LIKE ? ORDER BY last_at DESC LIMIT 1",
                    (f'%"{digest}"%',),
                ).fetchone()
                if prior and prior["id"] != case_id_hint:
                    duplicate_media = True
                    break
            if duplicate_media:
                categories.add("duplicate_receipt")

            context_rows = normalize_chat_context(context)
            evidence = {
                "at": at,
                "direction": direction,
                "source": source,
                "snippet": mask_sensitive_text(snippet),
                "categories": sorted(categories),
                "amounts": amounts,
                "event_status": event_status,
                "income_claim": income_claim,
                "attribution": attribution,
            }
            if context_rows:
                evidence["context"] = context_rows

            if row:
                case_id = row["id"]
                is_message_revision = bool(
                    same_message and (source == "edited" or event_status == "retracted")
                )
                row_state_at = str(row["state_at"] or row["last_at"] or "")
                stale_event = bool(row_state_at and at < row_state_at)
                old_categories = set(self._loads(row["categories_json"], []))
                old_amounts = self._amount_values(self._loads(row["amounts_json"], []))
                old_evidence = self._loads(row["evidence_json"], [])
                old_directions = set(self._loads(row["directions_json"], []))
                old_media = set(self._loads(row["media_hashes_json"], []))
                if stale_event and not is_message_revision:
                    # A delayed OCR/text result is historical evidence only. It
                    # must not put a superseded amount back into the live API.
                    categories = old_categories
                    amounts = old_amounts
                    directions = old_directions
                    media_hashes = old_media
                elif not is_message_revision:
                    categories |= old_categories
                    amounts = self._amount_values(old_amounts + amounts)
                    directions = old_directions | {direction}
                    media_hashes = old_media | new_hashes
                else:
                    directions = old_directions | {direction}
                    media_hashes = old_media | new_hashes
                    if event_status == "retracted":
                        # Признаки оплаты убрали правкой сообщения. Сумму и
                        # категории НЕ стираем: для сверки это красный флаг, а
                        # не пустая карточка.
                        categories |= old_categories
                        amounts = old_amounts
                if (
                    evidence["snippet"]
                    or evidence["categories"]
                    or evidence["amounts"]
                    or event_status == "retracted"
                    or source == "edited"
                ):
                    old_evidence.append(evidence)
                old_evidence.sort(key=lambda item: str(item.get("at") or ""))
                evidence_rows = old_evidence[-10:]

                current_status = str(row["event_status"] or "possible")
                current_income = bool(row["income_claim"])
                current_attribution = str(row["attribution"] or "unknown")
                current_state_at = str(row["state_at"] or row["last_at"] or "")
                current_state_ref = str(row["state_message_ref"] or "")
                current_base = int(row["base_score"] or 0)
                current_chat_ref = row["chat_ref"] if row["chat_ref"] is not None else chat_ref
                if row["chat_ref"] is not None and chat_ref is not None:
                    if int(row["chat_ref"]) != chat_ref:
                        raise ValueError("chat_ref does not match correlated case")
                revision_controls_state = bool(
                    is_message_revision
                    and (not current_state_ref or current_state_ref == message_ref)
                    and (not current_state_at or at >= current_state_at)
                )
                advance_state = revision_controls_state or self._state_should_advance(
                    current_state_at, current_status, at, event_status
                )
                if advance_state:
                    current_status = event_status
                    current_income = income_claim
                    current_attribution = attribution
                    current_state_at = max(current_state_at, at) if current_state_at else at
                    current_state_ref = message_ref
                    current_base = base_score

                auto_reopen = bool(
                    same_message
                    and advance_state
                    and row["admin_status"] == "confirmed"
                    and event_status in {"failed_or_reversed", "retracted"}
                )
                admin_status = "needs_info" if auto_reopen else row["admin_status"]
                admin_amount = None if auto_reopen else row["admin_amount"]
                admin_reviewed_at = None if auto_reopen else row["admin_reviewed_at"]

                score = self._case_score(
                    current_base, categories, amounts, directions, media_hashes,
                    current_status, current_income,
                )
                if current_status == "retracted":
                    # Правка сообщения не должна прятать случай из списка —
                    # заметность остаётся не ниже прежней.
                    score = max(score, int(row["score"] or 0))
                first_at = min(str(row["first_at"]), at)
                last_at = max(str(row["last_at"]), at)
                db.execute(
                    """
                    UPDATE payment_cases SET first_at=?, last_at=?, base_score=?, score=?, level=?,
                        categories_json=?, amounts_json=?, evidence_json=?,
                        directions_json=?, media_hashes_json=?, event_status=?,
                        income_claim=?, attribution=?, state_at=?, state_message_ref=?,
                        chat_ref=?, admin_status=?, admin_amount=?, admin_reviewed_at=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (
                        first_at, last_at, current_base, score, self._level(score),
                        json.dumps(sorted(categories), ensure_ascii=False),
                        json.dumps(amounts, ensure_ascii=False),
                        json.dumps(evidence_rows, ensure_ascii=False),
                        json.dumps(sorted(directions), ensure_ascii=False),
                        json.dumps(sorted(media_hashes), ensure_ascii=False),
                        current_status, int(current_income), current_attribution,
                        current_state_at, current_state_ref, current_chat_ref,
                        admin_status, admin_amount, admin_reviewed_at, now, case_id,
                    ),
                )
                if auto_reopen:
                    db.execute(
                        """INSERT INTO payment_audit_log(
                           case_id, actor, actor_id, action, old_value,
                           new_value, note, created_at
                           ) VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            case_id, "system", "payment-audit", "auto_reopen",
                            "confirmed", "needs_info",
                            "Подтверждённый сигнал изменён или отозван", now,
                        ),
                    )
            else:
                case_id = secrets.token_hex(8)
                directions = {direction}
                media_hashes = new_hashes
                score = self._case_score(
                    base_score, categories, amounts, directions, media_hashes,
                    event_status, income_claim,
                )
                evidence_rows = [evidence] if (
                    evidence["snippet"] or categories or amounts
                    or event_status == "retracted" or source == "edited"
                ) else []
                db.execute(
                    """
                    INSERT INTO payment_cases(
                        id, owner, profile_id, profile_active, chat_key, chat_ref,
                        first_at, last_at,
                        base_score, score, level, categories_json, amounts_json, evidence_json,
                        directions_json, media_hashes_json, event_status, income_claim,
                        attribution, state_at, state_message_ref, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        case_id, owner, profile_id, 1, chat_key, chat_ref, at, at,
                        base_score, score, self._level(score),
                        json.dumps(sorted(categories), ensure_ascii=False),
                        json.dumps(amounts, ensure_ascii=False),
                        json.dumps(evidence_rows, ensure_ascii=False),
                        json.dumps(sorted(directions), ensure_ascii=False),
                        json.dumps(sorted(media_hashes), ensure_ascii=False),
                        event_status, int(income_claim), attribution, at, message_ref, now, now,
                    ),
                )

            db.execute(
                """INSERT INTO payment_events(
                   event_key, case_id, message_ref, observed_at, source,
                   event_status, income_claim, attribution
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (event_key, case_id, message_ref, at, source,
                 event_status, int(income_claim), attribution),
            )
            row = db.execute("SELECT * FROM payment_cases WHERE id=?", (case_id,)).fetchone()
            db.commit()
        return self._row(row)

    def _row(self, row: sqlite3.Row | None) -> dict:
        if row is None:
            return {}
        out = dict(row)
        for src, dst in (
            ("categories_json", "categories"),
            ("amounts_json", "amounts"),
            ("evidence_json", "evidence"),
            ("directions_json", "directions"),
        ):
            out[dst] = self._loads(out.pop(src, "[]"), [])
        out["evidence"] = [
            {key: value for key, value in item.items() if key != "message_ref"}
            if isinstance(item, dict) else item
            for item in out.get("evidence", [])
        ]
        out.pop("media_hashes_json", None)
        out.pop("base_score", None)
        out.pop("state_message_ref", None)
        out["income_claim"] = bool(out.get("income_claim"))
        out["profile_active"] = bool(out.get("profile_active", True))
        if not out["profile_active"]:
            out["profile_id"] = None
        out["chat_label"] = f"Диалог #{out.get('chat_key', '')[-6:]}"
        context_rows: list[dict] = []
        seen_context: set[str] = set()
        for item in out.get("evidence") or []:
            if not isinstance(item, dict):
                continue
            for row in item.get("context") or []:
                if not isinstance(row, dict):
                    continue
                snippet = str(row.get("snippet") or "").strip()
                if not snippet:
                    continue
                direction = "outgoing" if row.get("direction") == "outgoing" else "incoming"
                key = f"{direction}:{snippet.casefold()}"
                if key in seen_context:
                    continue
                seen_context.add(key)
                context_rows.append({"direction": direction, "snippet": snippet})
        out["context"] = context_rows[-5:]
        # В карточку продолжают падать новые сообщения и после решения владельца.
        # Помечаем такие, чтобы проверенный диалог с новой активностью не потерялся.
        last_at = str(out.get("last_at") or "")
        reviewed_at = str(out.get("admin_reviewed_at") or "")
        answered_at = str(out.get("user_responded_at") or "")
        out["has_new_after_review"] = bool(reviewed_at and last_at > reviewed_at)
        out["has_new_after_answer"] = bool(answered_at and last_at > answered_at)
        out["signal_count"] = len(out.get("evidence") or [])
        return out

    def merge_duplicate_chat_cases(self) -> int:
        """Сводит ранее разделённые карточки одного чата в одну.

        До перехода на «один собеседник — одна карточка» каждый новый платёж в
        том же диалоге заводил отдельный случай. Здесь они склеиваются: улики,
        суммы и события переносятся в самую раннюю карточку, решения владельца
        не теряются, лишние строки удаляются. Повторный вызов ничего не меняет.
        """
        merged = 0
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            groups = db.execute(
                """SELECT owner, profile_id, chat_key, COUNT(*) AS n
                   FROM payment_cases WHERE profile_active=1
                   GROUP BY owner, profile_id, chat_key HAVING n > 1"""
            ).fetchall()
            for group in groups:
                rows = db.execute(
                    """SELECT * FROM payment_cases
                       WHERE owner=? AND profile_id=? AND chat_key=? AND profile_active=1
                       ORDER BY first_at ASC""",
                    (group["owner"], group["profile_id"], group["chat_key"]),
                ).fetchall()
                if len(rows) < 2:
                    continue
                keep, extras = rows[0], rows[1:]
                categories: set[str] = set(self._loads(keep["categories_json"], []))
                amounts = self._amount_values(self._loads(keep["amounts_json"], []))
                evidence = list(self._loads(keep["evidence_json"], []))
                directions: set[str] = set(self._loads(keep["directions_json"], []))
                media: set[str] = set(self._loads(keep["media_hashes_json"], []))
                first_at, last_at = str(keep["first_at"]), str(keep["last_at"])
                base = int(keep["base_score"] or 0)
                status, income = str(keep["event_status"]), bool(keep["income_claim"])
                state_at = str(keep["state_at"] or "")
                user_status, user_note = str(keep["user_status"]), str(keep["user_note"] or "")
                user_at = keep["user_responded_at"]
                admin_status, admin_note = str(keep["admin_status"]), str(keep["admin_note"] or "")
                admin_amount, admin_at = keep["admin_amount"], keep["admin_reviewed_at"]
                chat_ref = keep["chat_ref"]

                for row in extras:
                    categories |= set(self._loads(row["categories_json"], []))
                    amounts = self._amount_values(
                        amounts + self._amount_values(self._loads(row["amounts_json"], []))
                    )
                    evidence.extend(self._loads(row["evidence_json"], []))
                    directions |= set(self._loads(row["directions_json"], []))
                    media |= set(self._loads(row["media_hashes_json"], []))
                    first_at = min(first_at, str(row["first_at"]))
                    last_at = max(last_at, str(row["last_at"]))
                    base = max(base, int(row["base_score"] or 0))
                    if str(row["state_at"] or "") > state_at:
                        state_at = str(row["state_at"] or "")
                        status, income = str(row["event_status"]), bool(row["income_claim"])
                    # Ответ и решение владельца важнее пустого «ждёт ответа».
                    if user_status == "pending" and row["user_status"] != "pending":
                        user_status = str(row["user_status"])
                        user_note, user_at = str(row["user_note"] or ""), row["user_responded_at"]
                    if admin_status == "pending" and row["admin_status"] != "pending":
                        admin_status = str(row["admin_status"])
                        admin_note, admin_at = str(row["admin_note"] or ""), row["admin_reviewed_at"]
                    if admin_amount is None and row["admin_amount"] is not None:
                        admin_amount = row["admin_amount"]
                    if chat_ref is None and row["chat_ref"] is not None:
                        chat_ref = row["chat_ref"]
                    db.execute("UPDATE payment_events SET case_id=? WHERE case_id=?",
                               (keep["id"], row["id"]))
                    db.execute("UPDATE payment_audit_log SET case_id=? WHERE case_id=?",
                               (keep["id"], row["id"]))
                    db.execute("DELETE FROM payment_cases WHERE id=?", (row["id"],))
                    merged += 1

                evidence.sort(key=lambda item: str((item or {}).get("at") or ""))
                score = self._case_score(base, categories, amounts, directions, media, status, income)
                db.execute(
                    """UPDATE payment_cases SET first_at=?, last_at=?, base_score=?, score=?,
                       level=?, categories_json=?, amounts_json=?, evidence_json=?,
                       directions_json=?, media_hashes_json=?, event_status=?, income_claim=?,
                       state_at=?, chat_ref=?, user_status=?, user_note=?, user_responded_at=?,
                       admin_status=?, admin_note=?, admin_amount=?, admin_reviewed_at=?,
                       updated_at=? WHERE id=?""",
                    (
                        first_at, last_at, base, score, self._level(score),
                        json.dumps(sorted(categories), ensure_ascii=False),
                        json.dumps(amounts, ensure_ascii=False),
                        json.dumps(evidence[-10:], ensure_ascii=False),
                        json.dumps(sorted(directions), ensure_ascii=False),
                        json.dumps(sorted(media), ensure_ascii=False),
                        status, int(income), state_at or None, chat_ref,
                        user_status, user_note, user_at,
                        admin_status, admin_note, admin_amount, admin_at,
                        utc_now_iso(), keep["id"],
                    ),
                )
            db.commit()
        return merged

    def get_case(self, case_id: str) -> dict:
        with self._connection() as db:
            return self._row(db.execute("SELECT * FROM payment_cases WHERE id=?", (case_id,)).fetchone())

    def list_chat_cases(self, owner: str, chat_key: str) -> list[dict]:
        """Return all retained payment facts that belong to one opaque chat."""
        owner = str(owner or "")
        chat_key = str(chat_key or "")
        if not owner or not chat_key:
            return []
        with self._connection() as db:
            rows = db.execute(
                """SELECT * FROM payment_cases
                   WHERE owner=? AND chat_key=?
                   ORDER BY first_at ASC, id ASC""",
                (owner, chat_key),
            ).fetchall()
        return [self._row(row) for row in rows]

    def owner_chat_keys(self, owner: str) -> list[str]:
        """Return every archive scope before destructive owner deletion."""
        owner = str(owner or "")
        if not owner:
            return []
        with self._connection() as db:
            rows = db.execute(
                "SELECT DISTINCT chat_key FROM payment_cases WHERE owner=? AND chat_key<>''",
                (owner,),
            ).fetchall()
        return [str(row["chat_key"]) for row in rows if row["chat_key"]]

    def chat_message_refs(self, owner: str, chat_key: str) -> set[str]:
        """Return one-way Telegram message references for every case in a chat."""
        owner = str(owner or "")
        chat_key = str(chat_key or "")
        if not owner or not chat_key:
            return set()
        with self._connection() as db:
            rows = db.execute(
                """SELECT DISTINCT e.message_ref
                   FROM payment_events e
                   JOIN payment_cases c ON c.id=e.case_id
                   WHERE c.owner=? AND c.chat_key=? AND e.message_ref<>''""",
                (owner, chat_key),
            ).fetchall()
        return {str(row["message_ref"]) for row in rows if row["message_ref"]}

    def compact_chat(self, owner: str, chat_key: str, actor_id: str = "") -> int:
        """Discard stored snippets/context while retaining payment facts and decisions."""
        owner = str(owner or "")
        chat_key = str(chat_key or "")
        if not owner or not chat_key:
            raise ValueError("invalid chat scope")
        now = utc_now_iso()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            case_ids = [
                row["id"] for row in db.execute(
                    "SELECT id FROM payment_cases WHERE owner=? AND chat_key=?",
                    (owner, chat_key),
                ).fetchall()
            ]
            if not case_ids:
                return 0
            db.execute(
                """UPDATE payment_cases SET evidence_json='[]', updated_at=?
                   WHERE owner=? AND chat_key=?""",
                (now, owner, chat_key),
            )
            db.executemany(
                """INSERT INTO payment_audit_log(
                   case_id, actor, actor_id, action, old_value,
                   new_value, note, created_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                [
                    (
                        case_id,
                        "admin",
                        str(actor_id or "admin"),
                        "compact_chat",
                        "full-evidence",
                        "payment-facts-only",
                        "",
                        now,
                    )
                    for case_id in case_ids
                ],
            )
            return len(case_ids)

    def list_cases(self, *, owner: str | None = None, days: int = 7,
                   limit: int = 100, min_score: int = 20,
                   offset: int = 0) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))).isoformat(timespec="seconds")
        sql = "SELECT * FROM payment_cases WHERE last_at>=? AND score>=?"
        args: list = [cutoff, max(0, int(min_score))]
        if owner is not None:
            sql += " AND owner=?"
            args.append(owner)
        sql += " ORDER BY last_at DESC, id DESC LIMIT ? OFFSET ?"
        args.extend([
            max(1, min(5000, int(limit))),
            max(0, min(10_000_000, int(offset))),
        ])
        with self._connection() as db:
            return [self._row(row) for row in db.execute(sql, args).fetchall()]

    def respond(self, case_id: str, owner: str, status: str, note: str = "") -> dict:
        if status not in USER_CASE_STATUSES - {"pending"}:
            raise ValueError("invalid user status")
        now = utc_now_iso()
        note = mask_sensitive_text(note, 500)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT user_status FROM payment_cases WHERE id=? AND owner=?", (case_id, owner)
            ).fetchone()
            if not row:
                raise KeyError(case_id)
            db.execute(
                "UPDATE payment_cases SET user_status=?, user_note=?, user_responded_at=?, updated_at=? WHERE id=?",
                (status, note, now, now, case_id),
            )
            db.execute(
                """INSERT INTO payment_audit_log(case_id, actor, actor_id, action,
                   old_value, new_value, note, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (case_id, "user", owner, "respond", row["user_status"], status, note, now),
            )
            result = db.execute("SELECT * FROM payment_cases WHERE id=?", (case_id,)).fetchone()
            db.commit()
        return self._row(result)

    def review(self, case_id: str, admin_id: str, status: str,
               amount: float | None = None, note: str = "") -> dict:
        if status not in ADMIN_CASE_STATUSES - {"pending"}:
            raise ValueError("invalid admin status")
        if amount is not None:
            amount = round(float(amount), 2)
            if not math.isfinite(amount) or amount < 0 or amount > 100_000_000:
                raise ValueError("invalid amount")
        now = utc_now_iso()
        note = mask_sensitive_text(note, 500)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT admin_status FROM payment_cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise KeyError(case_id)
            db.execute(
                """UPDATE payment_cases SET admin_status=?, admin_note=?, admin_amount=?,
                   admin_reviewed_at=?, updated_at=? WHERE id=?""",
                (status, note, amount, now, now, case_id),
            )
            db.execute(
                """INSERT INTO payment_audit_log(case_id, actor, actor_id, action,
                   old_value, new_value, note, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (case_id, "admin", admin_id, "review", row["admin_status"], status, note, now),
            )
            result = db.execute("SELECT * FROM payment_cases WHERE id=?", (case_id,)).fetchone()
            db.commit()
        return self._row(result)

    def submit_week(self, owner: str, week_start: str, amount: float, note: str = "") -> dict:
        try:
            datetime.strptime(week_start, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("invalid week") from exc
        amount = round(float(amount), 2)
        if not math.isfinite(amount) or amount < 0 or amount > 100_000_000:
            raise ValueError("invalid amount")
        now = utc_now_iso()
        note = mask_sensitive_text(note, 500)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT amount, note FROM payment_weekly_reports WHERE owner=? AND week_start=?",
                (owner, week_start),
            ).fetchone()
            db.execute(
                """
                INSERT INTO payment_weekly_reports(owner, week_start, amount, note, submitted_at, updated_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(owner, week_start) DO UPDATE SET
                    amount=excluded.amount, note=excluded.note, updated_at=excluded.updated_at
                """,
                (owner, week_start, amount, note, now, now),
            )
            db.execute(
                """INSERT INTO payment_weekly_report_log(
                   owner, week_start, old_amount, new_amount, old_note, new_note, created_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    owner, week_start,
                    previous["amount"] if previous else None,
                    amount,
                    previous["note"] if previous else "",
                    note,
                    now,
                ),
            )
        return self.weekly_report(owner, week_start)

    def weekly_report(self, owner: str, week_start: str) -> dict | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM payment_weekly_reports WHERE owner=? AND week_start=?",
                (owner, week_start),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            result["history"] = [
                dict(item) for item in db.execute(
                    """SELECT old_amount, new_amount, old_note, new_note, created_at
                       FROM payment_weekly_report_log
                       WHERE owner=? AND week_start=? ORDER BY id DESC LIMIT 50""",
                    (owner, week_start),
                ).fetchall()
            ]
            return result

    def recent_weekly_reports(self, owner: str, limit: int = 12) -> list[dict]:
        """Return recent declarations, including their immutable change history."""
        limit = max(1, min(52, int(limit)))
        with self._connection() as db:
            rows = db.execute(
                """SELECT * FROM payment_weekly_reports
                   WHERE owner=? ORDER BY week_start DESC LIMIT ?""",
                (owner, limit),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["history"] = [
                    dict(log) for log in db.execute(
                        """SELECT old_amount, new_amount, old_note, new_note, created_at
                           FROM payment_weekly_report_log
                           WHERE owner=? AND week_start=? ORDER BY id DESC LIMIT 50""",
                        (owner, row["week_start"]),
                    ).fetchall()
                ]
                result.append(item)
            return result

    @staticmethod
    def _summary_for_cases(cases: list[dict], commission_rate: float) -> dict:
        confirmed = [
            case for case in cases
            if case["admin_status"] == "confirmed"
            and case.get("event_status") not in {"failed_or_reversed", "retracted"}
        ]
        confirmed_total = round(sum(float(c.get("admin_amount") or 0) for c in confirmed), 2)
        pending = [c for c in cases if c["admin_status"] in ("pending", "needs_info")]
        possible_total = 0.0
        for case in pending:
            values = [float(a.get("value") or 0) for a in case.get("amounts", []) if a.get("currency") == "RUB"]
            possible_total += max(values, default=0.0)
        return {
            "cases": len(cases),
            "pending": len(pending),
            "high": sum(1 for c in pending if c.get("level") == "high"),
            "confirmed": len(confirmed),
            "confirmed_total": confirmed_total,
            "possible_total": round(possible_total, 2),
            "commission": round(confirmed_total * float(commission_rate), 2),
        }

    def owner_summary(self, owner: str, *, days: int = 7,
                      commission_rate: float = 0.15) -> dict:
        cases = self.list_cases(owner=owner, days=days, limit=500, min_score=20)
        return self._summary_for_cases(cases, commission_rate)

    def weekly_summary(
        self,
        owner: str,
        week_start: str,
        week_end: str,
        *,
        commission_rate: float = 0.15,
    ) -> dict:
        """Summarize one UTC calendar week without the list API's 500-row cap.

        ``week_start`` is the inclusive Monday and ``week_end`` is the exclusive
        following Monday. Both are ISO calendar dates (``YYYY-MM-DD``).
        """
        try:
            start_date = datetime.strptime(week_start, "%Y-%m-%d")
            end_date = datetime.strptime(week_end, "%Y-%m-%d")
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid week boundaries") from exc
        if start_date.weekday() != 0 or end_date - start_date != timedelta(days=7):
            raise ValueError("week must run Monday to Monday")
        start_at = start_date.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        end_at = end_date.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        with self._connection() as db:
            rows = db.execute(
                """SELECT * FROM payment_cases
                   WHERE owner=? AND last_at>=? AND last_at<? AND score>=20
                   ORDER BY last_at DESC""",
                (owner, start_at, end_at),
            ).fetchall()
        result = self._summary_for_cases([self._row(row) for row in rows], commission_rate)
        result["week_start"] = week_start
        result["week_end"] = week_end
        return result

    def cleanup(self, now: str | datetime | None = None) -> int:
        current = datetime.fromisoformat(normalize_event_time(now))
        report_cutoff = (
            current - timedelta(days=self.report_retention_days)
        ).isoformat(timespec="seconds")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            removed = 0
            if self.retention_days > 0:
                cutoff = (
                    current - timedelta(days=self.retention_days)
                ).isoformat(timespec="seconds")
                cur = db.execute("DELETE FROM payment_cases WHERE last_at<?", (cutoff,))
                removed = int(cur.rowcount or 0)
                db.execute(
                    """DELETE FROM payment_audit_log
                       WHERE created_at<? OR case_id NOT IN (SELECT id FROM payment_cases)""",
                    (cutoff,),
                )
            else:
                db.execute(
                    "DELETE FROM payment_audit_log WHERE case_id NOT IN (SELECT id FROM payment_cases)"
                )
            db.execute(
                "DELETE FROM payment_weekly_reports WHERE updated_at<?", (report_cutoff,)
            )
            db.execute(
                """DELETE FROM payment_weekly_report_log
                   WHERE created_at<? OR NOT EXISTS (
                       SELECT 1 FROM payment_weekly_reports r
                       WHERE r.owner=payment_weekly_report_log.owner
                         AND r.week_start=payment_weekly_report_log.week_start
                   )""",
                (report_cutoff,),
            )
            return removed

    def delete_owner(self, owner: str) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM payment_audit_log WHERE case_id IN (SELECT id FROM payment_cases WHERE owner=?)",
                (owner,),
            )
            db.execute("DELETE FROM payment_cases WHERE owner=?", (owner,))
            db.execute("DELETE FROM payment_weekly_report_log WHERE owner=?", (owner,))
            db.execute("DELETE FROM payment_weekly_reports WHERE owner=?", (owner,))

    def archive_profile(self, profile_id: str) -> int:
        """Detach a deleted profile while retaining its audit cases temporarily."""
        profile_id = str(profile_id or "")
        if not profile_id:
            raise ValueError("invalid profile_id")
        archived_ref = "archived:" + hmac.new(
            self.secret,
            f"archived-profile:{profile_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:24]
        now = utc_now_iso()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            case_ids = [
                row["id"] for row in db.execute(
                    "SELECT id FROM payment_cases WHERE profile_id=? AND profile_active=1",
                    (profile_id,),
                ).fetchall()
            ]
            if not case_ids:
                return 0
            db.execute(
                """UPDATE payment_cases
                   SET profile_id=?, profile_active=0, chat_ref=NULL, updated_at=?
                   WHERE profile_id=? AND profile_active=1""",
                (archived_ref, now, profile_id),
            )
            db.executemany(
                """INSERT INTO payment_audit_log(
                   case_id, actor, actor_id, action, old_value,
                   new_value, note, created_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                [
                    (
                        case_id, "system", "payment-audit", "archive_profile",
                        "active", "archived", "", now,
                    )
                    for case_id in case_ids
                ],
            )
            return len(case_ids)

    def delete_profile(self, profile_id: str) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM payment_audit_log WHERE case_id IN (SELECT id FROM payment_cases WHERE profile_id=?)",
                (profile_id,),
            )
            db.execute("DELETE FROM payment_cases WHERE profile_id=?", (profile_id,))
