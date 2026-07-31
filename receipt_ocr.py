"""Bounded OCR helpers for possible payment receipts.

The module deliberately has no Telegram or storage dependencies.  Callers pass
media bytes in and decide what (if anything) to persist.  Raster/PDF data only
touches a private ``TemporaryDirectory`` which is removed on success, failure,
or timeout.

Runtime dependencies are intentionally small and explicit:

* Pillow (Python package) for safe raster decoding and metadata stripping;
* ``tesseract`` with the Russian and English language packs;
* ``pdftoppm`` (Poppler) only when PDF input is accepted.

``RemoteReceiptOcr`` speaks only to the optional isolated sidecar.  No external
OCR provider is used, and protocol errors never include receipt text.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence


class ReceiptOcrError(RuntimeError):
    """Base error raised for a rejected or failed local OCR operation."""


class OcrUnavailableError(ReceiptOcrError):
    """The local OCR runtime is not installed or is incomplete."""


class UnsupportedMediaError(ReceiptOcrError):
    """The supplied bytes are not a supported image or PDF."""


class MediaLimitError(ReceiptOcrError):
    """The media exceeds a configured byte, pixel, page, or output limit."""


class OcrTimeoutError(ReceiptOcrError):
    """The bounded OCR operation did not finish in time."""


@dataclass(frozen=True)
class OcrLimits:
    """Resource limits suitable for Telegram screenshots and short receipts."""

    max_media_bytes: int = 10 * 1024 * 1024
    max_pixels: int = 20_000_000
    max_dimension: int = 4096
    max_pdf_pages: int = 3
    command_timeout_seconds: float = 15.0
    total_timeout_seconds: float = 30.0
    max_ocr_chars: int = 24_000

    def __post_init__(self) -> None:
        numeric_values = (
            self.max_media_bytes,
            self.max_pixels,
            self.max_dimension,
            self.max_pdf_pages,
            self.command_timeout_seconds,
            self.total_timeout_seconds,
            self.max_ocr_chars,
        )
        if any(value <= 0 for value in numeric_values):
            raise ValueError("OCR limits must all be positive")


@dataclass(frozen=True)
class PaymentAmount:
    """A normalized amount found next to a currency or amount label."""

    value: str
    currency: str | None
    raw: str


@dataclass(frozen=True)
class PaymentSignals:
    """Conservative signals extracted from OCR or ordinary message text."""

    terms: tuple[str, ...]
    amounts: tuple[PaymentAmount, ...]
    confidence: str
    is_likely_payment: bool


@dataclass(frozen=True)
class ReceiptOcrResult:
    """OCR output plus hashes that callers can use for deduplication."""

    media_sha256: str
    text_sha256: str | None
    media_kind: str
    text: str
    signals: PaymentSignals

    @property
    def exact_dedup_key(self) -> str:
        """Stable key for byte-identical uploads."""

        return f"sha256:{self.media_sha256}"

    @property
    def text_dedup_key(self) -> str | None:
        """Advisory key for recompressed screenshots with identical OCR text."""

        if self.text_sha256 is None:
            return None
        return f"ocr-sha256:{self.text_sha256}"


@dataclass(frozen=True)
class OcrRuntimeStatus:
    pillow_available: bool
    tesseract_path: str | None
    pdftoppm_path: str | None
    languages_available: bool = False

    @property
    def images_available(self) -> bool:
        return (
            self.pillow_available
            and self.tesseract_path is not None
            and self.languages_available
        )

    @property
    def pdf_available(self) -> bool:
        return self.images_available and self.pdftoppm_path is not None


@dataclass(frozen=True)
class RemoteOcrHealth:
    """Non-sensitive capability response returned by the isolated sidecar."""

    ready: bool
    protocol: int
    formats: tuple[str, ...]
    max_media_bytes: int
    languages_available: bool


_PAYMENT_TERM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "transfer",
        re.compile(
            r"\b(?:перевод\w*|перев[её]л\w*|перевела\w*|перевести|транзакци\w*)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "payment",
        re.compile(r"\b(?:плат[её]ж\w*|оплат\w*|заплат\w*)\b", re.IGNORECASE),
    ),
    (
        "completed",
        re.compile(
            r"\b(?:успешн\w*|выполнен\w*|исполнен\w*|зачислен\w*|списан\w*)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sent",
        re.compile(
            r"\b(?:скинул\w*|скинула\w*|отправил\w*|отправила\w*|закинул\w*|закинула\w*)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "purchase",
        re.compile(r"\b(?:покупаю\w*|куплю\w*|беру)\b", re.IGNORECASE),
    ),
    (
        "fast_payment_system",
        re.compile(r"\b(?:сбп|систем\w+\s+быстр\w+\s+платеж\w*)\b", re.IGNORECASE),
    ),
    (
        "receipt",
        re.compile(r"\b(?:чек\w*|квитанци\w*)\b", re.IGNORECASE),
    ),
    (
        "recipient",
        re.compile(r"\b(?:получател\w*|кому)\b", re.IGNORECASE),
    ),
    (
        "sender",
        re.compile(r"\b(?:отправител\w*|от кого)\b", re.IGNORECASE),
    ),
    (
        "operation",
        re.compile(r"\b(?:операци\w*|номер\s+(?:операции|транзакции))\b", re.IGNORECASE),
    ),
)

_NUMBER = r"(?:\d{1,3}(?:[ \u00a0\u202f.,]\d{3})+|\d{1,9})(?:[.,]\d{1,2})?"
_CURRENCY = r"(?:₽|р\.?|руб(?:л(?:ь|я|ей))?\.?|rub|₴|грн\.?|uah|₸|тенге|kzt|\$|usd|€|eur)"
_AMOUNT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"(?P<number>{_NUMBER})\s*(?P<currency>{_CURRENCY})(?!\w)",
        re.IGNORECASE,
    ),
    re.compile(
        rf"(?P<currency>{_CURRENCY})\s*(?P<number>{_NUMBER})(?!\d)",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:сумма|итого|к\s+оплате|сумма\s+перевода)\s*[:\-]?\s*"
        rf"(?P<number>{_NUMBER})(?:\s*(?P<currency>{_CURRENCY}))?",
        re.IGNORECASE,
    ),
)

_CURRENCY_NAMES = {
    "₽": "RUB",
    "р": "RUB",
    "руб": "RUB",
    "рубл": "RUB",
    "рубль": "RUB",
    "рубля": "RUB",
    "рублей": "RUB",
    "rub": "RUB",
    "₴": "UAH",
    "грн": "UAH",
    "uah": "UAH",
    "₸": "KZT",
    "тенге": "KZT",
    "kzt": "KZT",
    "$": "USD",
    "usd": "USD",
    "€": "EUR",
    "eur": "EUR",
}


def _normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "").replace("ё", "е").replace("Ё", "Е")
    return " ".join(text.casefold().split())


def _normalize_currency(raw: str | None) -> str | None:
    if not raw:
        return None
    key = raw.casefold().strip().rstrip(".")
    return _CURRENCY_NAMES.get(key)


def _normalize_number(raw: str) -> str | None:
    compact = re.sub(r"[ \u00a0\u202f]", "", raw)
    if not compact:
        return None

    if "." in compact and "," in compact:
        decimal_mark = "." if compact.rfind(".") > compact.rfind(",") else ","
        grouping_mark = "," if decimal_mark == "." else "."
        compact = compact.replace(grouping_mark, "")
        compact = compact.replace(decimal_mark, ".")
    elif "," in compact or "." in compact:
        mark = "," if "," in compact else "."
        head, tail = compact.rsplit(mark, 1)
        # Three trailing digits almost always mean a thousands separator in a
        # bank receipt; one or two digits mean kopecks/cents.
        if len(tail) == 3:
            compact = compact.replace(mark, "")
        else:
            compact = head.replace(mark, "") + "." + tail

    try:
        amount = Decimal(compact)
    except InvalidOperation:
        return None
    if amount <= 0 or amount > Decimal("1000000000"):
        return None
    normalized = format(amount.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized


def extract_payment_signals(text: str) -> PaymentSignals:
    """Extract conservative payment evidence without claiming it is proof.

    A trigger word alone is never considered a likely payment.  At least one
    amount and one payment-related term must be present.  This keeps phrases
    such as "отправил фото" in the review-only/low-confidence bucket.
    """

    normalized = unicodedata.normalize("NFKC", text or "")
    terms = tuple(name for name, pattern in _PAYMENT_TERM_PATTERNS if pattern.search(normalized))

    amounts: list[PaymentAmount] = []
    seen_amounts: set[tuple[int, int, str, str | None]] = set()
    for pattern in _AMOUNT_PATTERNS:
        for match in pattern.finditer(normalized):
            value = _normalize_number(match.group("number"))
            if value is None:
                continue
            currency = _normalize_currency(match.groupdict().get("currency"))
            dedup = (match.start("number"), match.end("number"), value, currency)
            if dedup in seen_amounts:
                continue
            seen_amounts.add(dedup)
            amounts.append(PaymentAmount(value=value, currency=currency, raw=match.group(0).strip()))

    strong_terms = {"transfer", "payment", "completed", "fast_payment_system", "receipt", "operation"}
    score = min(len(terms), 3)
    if amounts:
        score += 2
    if strong_terms.intersection(terms):
        score += 1
    if "completed" in terms and ({"transfer", "payment"} & set(terms)):
        score += 2

    likely = bool(amounts and terms)
    if likely and score >= 6:
        confidence = "high"
    elif likely and score >= 3:
        confidence = "medium"
    else:
        confidence = "low"
    return PaymentSignals(
        terms=terms,
        amounts=tuple(amounts),
        confidence=confidence,
        is_likely_payment=likely,
    )


def detect_media_kind(data: bytes) -> str:
    """Detect supported content by magic bytes, never by client MIME alone."""

    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if data.startswith(b"\xff\xd8\xff"):
        return "image"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "image"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image"
    raise UnsupportedMediaError("supported formats are JPEG, PNG, TIFF, WEBP, and PDF")


def detect_safe_raster_mime(data: bytes) -> str:
    """Return the only two media types accepted by the isolated sidecar."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    raise UnsupportedMediaError("isolated OCR accepts only JPEG and PNG")


def receipt_result_to_dict(result: ReceiptOcrResult) -> dict[str, Any]:
    """Serialize a result for the private sidecar protocol."""

    return {
        "media_sha256": result.media_sha256,
        "text_sha256": result.text_sha256,
        "media_kind": result.media_kind,
        "text": result.text,
        "signals": {
            "terms": list(result.signals.terms),
            "amounts": [
                {"value": item.value, "currency": item.currency, "raw": item.raw}
                for item in result.signals.amounts
            ],
            "confidence": result.signals.confidence,
            "is_likely_payment": result.signals.is_likely_payment,
        },
    }


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def receipt_result_from_dict(
    payload: Any,
    *,
    expected_media_sha256: str | None = None,
    max_text_chars: int = 24_000,
) -> ReceiptOcrResult:
    """Strictly decode an isolated sidecar result without echoing bad data."""

    try:
        if not isinstance(payload, dict):
            raise ValueError
        media_sha256 = payload["media_sha256"]
        text_sha256 = payload.get("text_sha256")
        media_kind = payload["media_kind"]
        text = payload["text"]
        raw_signals = payload["signals"]
        if not _valid_sha256(media_sha256):
            raise ValueError
        if expected_media_sha256 is not None and not hmac.compare_digest(
            media_sha256, expected_media_sha256
        ):
            raise ValueError
        if media_kind != "image" or not isinstance(text, str) or len(text) > max_text_chars:
            raise ValueError

        normalized_text = _normalize_text(text)
        expected_text_sha256 = (
            hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
            if normalized_text
            else None
        )
        if text_sha256 != expected_text_sha256:
            raise ValueError
        if not isinstance(raw_signals, dict):
            raise ValueError

        raw_terms = raw_signals["terms"]
        raw_amounts = raw_signals["amounts"]
        confidence = raw_signals["confidence"]
        likely = raw_signals["is_likely_payment"]
        if (
            not isinstance(raw_terms, list)
            or len(raw_terms) > 32
            or not all(isinstance(term, str) and len(term) <= 48 for term in raw_terms)
            or not isinstance(raw_amounts, list)
            or len(raw_amounts) > 32
            or confidence not in {"low", "medium", "high"}
            or not isinstance(likely, bool)
        ):
            raise ValueError

        amounts: list[PaymentAmount] = []
        for item in raw_amounts:
            if not isinstance(item, dict):
                raise ValueError
            value = item.get("value")
            currency = item.get("currency")
            raw = item.get("raw")
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 32
                or (currency is not None and (not isinstance(currency, str) or len(currency) > 8))
                or not isinstance(raw, str)
                or len(raw) > 160
            ):
                raise ValueError
            amounts.append(PaymentAmount(value=value, currency=currency, raw=raw))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReceiptOcrError("invalid isolated OCR response") from exc

    return ReceiptOcrResult(
        media_sha256=media_sha256,
        text_sha256=text_sha256,
        media_kind=media_kind,
        text=text,
        signals=PaymentSignals(
            terms=tuple(raw_terms),
            amounts=tuple(amounts),
            confidence=confidence,
            is_likely_payment=likely,
        ),
    )


@lru_cache(maxsize=1)
def runtime_status() -> OcrRuntimeStatus:
    """Return a side-effect-free view of installed local OCR components."""

    try:
        import PIL  # noqa: F401
    except ImportError:
        pillow_available = False
    else:
        pillow_available = True
    tesseract_path = shutil.which("tesseract")
    languages_available = False
    if tesseract_path:
        try:
            listed = subprocess.run(
                [tesseract_path, "--list-langs"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
            ).stdout.decode("utf-8", errors="replace").splitlines()
            languages = {line.strip() for line in listed}
            languages_available = {"rus", "eng"}.issubset(languages)
        except (OSError, subprocess.SubprocessError):
            languages_available = False
    return OcrRuntimeStatus(
        pillow_available=pillow_available,
        tesseract_path=tesseract_path,
        pdftoppm_path=shutil.which("pdftoppm"),
        languages_available=languages_available,
    )


class RemoteReceiptOcr:
    """Async client for the private, isolated OCR sidecar protocol."""

    protocol_version = 1

    def __init__(
        self,
        base_url: str = "http://ocr:8080",
        *,
        uds_path: str | os.PathLike[str] | None = None,
        limits: OcrLimits | None = None,
        timeout_seconds: float = 35.0,
        client: Any | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.base_url = base_url.rstrip("/")
        self.limits = limits or OcrLimits(max_pdf_pages=1)
        self._owns_client = client is None
        self._client = client
        self._uds_path = os.fspath(uds_path) if uds_path is not None else None
        self._timeout_seconds = timeout_seconds

    def _get_client(self):
        """Create httpx lazily so an optional OCR failure cannot block app boot."""
        if self._client is not None:
            return self._client
        try:
            import httpx
        except Exception as exc:
            raise OcrUnavailableError("httpx is required for isolated OCR") from exc
        try:
            transport = (
                httpx.AsyncHTTPTransport(uds=self._uds_path)
                if self._uds_path is not None
                else None
            )
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                transport=transport,
                timeout=httpx.Timeout(
                    self._timeout_seconds,
                    connect=min(5.0, self._timeout_seconds),
                ),
                follow_redirects=False,
                # Never route private receipt bytes through HTTP(S)_PROXY from
                # the scheduler environment; OCR lives on an internal network.
                trust_env=False,
            )
        except Exception as exc:
            raise OcrUnavailableError("httpx is required for isolated OCR") from exc
        return self._client

    async def __aenter__(self) -> RemoteReceiptOcr:
        return self

    async def __aexit__(self, _exc_type, _exc, _traceback) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def health(self) -> RemoteOcrHealth:
        try:
            response = await self._get_client().get(self._url("/healthz"))
        except Exception as exc:
            raise OcrUnavailableError("isolated OCR health request failed") from exc
        if response.status_code not in {200, 503}:
            raise OcrUnavailableError("isolated OCR health request failed")
        try:
            if len(response.content) > 16_384:
                raise ValueError
            payload = response.json()
            ready = payload["ready"]
            protocol = payload["protocol"]
            formats = payload["formats"]
            max_media_bytes = payload["max_media_bytes"]
            languages_available = payload["languages_available"]
            if (
                not isinstance(ready, bool)
                or protocol != self.protocol_version
                or not isinstance(formats, list)
                or not formats
                or not all(item in {"image/jpeg", "image/png"} for item in formats)
                or not isinstance(max_media_bytes, int)
                or max_media_bytes <= 0
                or max_media_bytes > 10 * 1024 * 1024
                or not isinstance(languages_available, bool)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise ReceiptOcrError("invalid isolated OCR health response") from exc
        return RemoteOcrHealth(
            ready=ready and response.status_code == 200,
            protocol=protocol,
            formats=tuple(formats),
            max_media_bytes=max_media_bytes,
            languages_available=languages_available,
        )

    async def analyze(self, data: bytes, *, filename: str = "") -> ReceiptOcrResult:
        return await self.analyze_bytes_async(data, filename=filename)

    async def analyze_bytes_async(self, data: bytes, *, filename: str = "") -> ReceiptOcrResult:
        del filename  # The sidecar validates magic bytes, never a client filename.
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not data:
            raise UnsupportedMediaError("empty media")
        if len(data) > self.limits.max_media_bytes:
            raise MediaLimitError("media exceeds max_media_bytes")
        media_type = detect_safe_raster_mime(data)
        expected_hash = hashlib.sha256(data).hexdigest()
        try:
            response = await self._get_client().post(
                self._url("/v1/ocr"),
                content=data,
                headers={
                    "Content-Type": media_type,
                    "Accept": "application/json",
                    "X-Rita-OCR-Protocol": str(self.protocol_version),
                },
            )
        except Exception as exc:
            raise OcrUnavailableError("isolated OCR request failed") from exc

        if response.status_code == 413:
            raise MediaLimitError("isolated OCR rejected media size")
        if response.status_code == 415:
            raise UnsupportedMediaError("isolated OCR rejected media format")
        if response.status_code == 503:
            raise OcrUnavailableError("isolated OCR is unavailable")
        if response.status_code in {408, 504}:
            raise OcrTimeoutError("isolated OCR timed out")
        if response.status_code != 200:
            raise ReceiptOcrError(f"isolated OCR failed with HTTP {response.status_code}")
        if len(response.content) > 256 * 1024:
            raise MediaLimitError("isolated OCR response is too large")
        try:
            payload = response.json()
        except Exception as exc:
            raise ReceiptOcrError("invalid isolated OCR response") from exc
        return receipt_result_from_dict(
            payload,
            expected_media_sha256=expected_hash,
            max_text_chars=self.limits.max_ocr_chars,
        )


class LocalReceiptOcr:
    """Run Tesseract/Poppler locally with strict input and wall-clock limits."""

    def __init__(
        self,
        *,
        limits: OcrLimits | None = None,
        languages: str = "rus+eng",
        tesseract_command: str = "tesseract",
        pdftoppm_command: str = "pdftoppm",
        temp_root: str | os.PathLike[str] | None = None,
        max_parallel_jobs: int = 1,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_+\-]+", languages):
            raise ValueError("invalid Tesseract language expression")
        if max_parallel_jobs <= 0:
            raise ValueError("max_parallel_jobs must be positive")
        self.limits = limits or OcrLimits()
        self.languages = languages
        self.tesseract_command = tesseract_command
        self.pdftoppm_command = pdftoppm_command
        self.temp_root = os.fspath(temp_root) if temp_root is not None else None
        # One shared worker instance should be kept by the application.  The
        # conservative default prevents a burst of screenshots from exhausting
        # a small VPS with concurrent Tesseract processes.
        self._concurrency_gate = threading.BoundedSemaphore(max_parallel_jobs)

    async def analyze_bytes_async(self, data: bytes, *, filename: str = "") -> ReceiptOcrResult:
        """Offload blocking local OCR so an asyncio web loop stays responsive."""

        return await asyncio.to_thread(self.analyze_bytes, data, filename=filename)

    def analyze_bytes(self, data: bytes, *, filename: str = "") -> ReceiptOcrResult:
        """OCR supported media bytes and delete all temporary artifacts."""

        del filename  # Content is deliberately detected by magic bytes.
        deadline = time.monotonic() + self.limits.total_timeout_seconds
        if not self._concurrency_gate.acquire(timeout=self.limits.total_timeout_seconds):
            raise OcrTimeoutError("local OCR queue wait timed out")
        try:
            return self._analyze_bytes(data, deadline)
        finally:
            self._concurrency_gate.release()

    def _analyze_bytes(self, data: bytes, deadline: float) -> ReceiptOcrResult:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not data:
            raise UnsupportedMediaError("empty media")
        if len(data) > self.limits.max_media_bytes:
            raise MediaLimitError("media exceeds max_media_bytes")

        media_kind = detect_media_kind(data)
        media_sha256 = hashlib.sha256(data).hexdigest()

        with tempfile.TemporaryDirectory(prefix="rita-receipt-ocr-", dir=self.temp_root) as tmp:
            workspace = Path(tmp)
            if media_kind == "pdf":
                source = workspace / "source.pdf"
                self._write_private(source, data)
                raster_paths = self._render_pdf(source, workspace, deadline)
            else:
                raster = workspace / "source.png"
                self._prepare_raster(data, raster)
                raster_paths = [raster]

            chunks = [self._ocr_raster(path, deadline) for path in raster_paths]

        text = "\n\n".join(chunk.strip() for chunk in chunks if chunk.strip()).strip()
        if len(text) > self.limits.max_ocr_chars:
            raise MediaLimitError("OCR output exceeds max_ocr_chars")
        normalized_text = _normalize_text(text)
        text_sha256 = (
            hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
            if normalized_text
            else None
        )
        return ReceiptOcrResult(
            media_sha256=media_sha256,
            text_sha256=text_sha256,
            media_kind=media_kind,
            text=text,
            signals=extract_payment_signals(text),
        )

    @staticmethod
    def _write_private(path: Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def _prepare_raster(self, data: bytes, destination: Path) -> None:
        try:
            from PIL import Image, ImageOps, UnidentifiedImageError
        except ImportError as exc:
            raise OcrUnavailableError("Pillow is required for raster OCR") from exc

        try:
            with Image.open(io.BytesIO(data)) as image:
                image.seek(0)
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > self.limits.max_pixels:
                    raise MediaLimitError("image exceeds max_pixels")
                image.load()
                image = ImageOps.exif_transpose(image)
                if max(image.size) > self.limits.max_dimension:
                    image.thumbnail(
                        (self.limits.max_dimension, self.limits.max_dimension),
                        Image.Resampling.LANCZOS,
                    )
                # Convert to a metadata-free, bounded raster before invoking an
                # external binary.  A white background keeps transparent PNGs legible.
                if image.mode in ("RGBA", "LA") or "transparency" in image.info:
                    rgba = image.convert("RGBA")
                    background = Image.new("RGBA", rgba.size, "white")
                    background.alpha_composite(rgba)
                    safe_image = background.convert("RGB")
                else:
                    safe_image = image.convert("RGB")
                safe_image.save(destination, format="PNG", optimize=False)
                os.chmod(destination, 0o600)
        except MediaLimitError:
            raise
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise UnsupportedMediaError("invalid or corrupt raster image") from exc

    def _render_pdf(self, source: Path, workspace: Path, deadline: float) -> list[Path]:
        command = self._resolve_command(self.pdftoppm_command, "pdftoppm")
        prefix = workspace / "page"
        self._run_command(
            (
                command,
                "-f",
                "1",
                "-l",
                str(self.limits.max_pdf_pages),
                "-scale-to",
                str(self.limits.max_dimension),
                "-jpeg",
                str(source),
                str(prefix),
            ),
            deadline,
        )
        rendered = sorted(workspace.glob("page-*.jpg"))[: self.limits.max_pdf_pages]
        if not rendered:
            raise UnsupportedMediaError("PDF contains no renderable pages")

        safe_pages: list[Path] = []
        for index, page in enumerate(rendered, start=1):
            page_data = page.read_bytes()
            if len(page_data) > self.limits.max_media_bytes:
                raise MediaLimitError("rendered PDF page exceeds max_media_bytes")
            safe_page = workspace / f"safe-page-{index}.png"
            self._prepare_raster(page_data, safe_page)
            safe_pages.append(safe_page)
        return safe_pages

    def _ocr_raster(self, path: Path, deadline: float) -> str:
        command = self._resolve_command(self.tesseract_command, "tesseract")
        output = self._run_command(
            (
                command,
                str(path),
                "stdout",
                "-l",
                self.languages,
                "--psm",
                "6",
            ),
            deadline,
        )
        try:
            return output.decode("utf-8", errors="replace")
        except AttributeError as exc:
            raise ReceiptOcrError("unexpected OCR command output") from exc

    @staticmethod
    def _resolve_command(configured: str, label: str) -> str:
        resolved = shutil.which(configured)
        if not resolved:
            raise OcrUnavailableError(f"{label} is not installed")
        return resolved

    def _run_command(self, args: Sequence[str], deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        timeout = min(self.limits.command_timeout_seconds, remaining)
        if timeout <= 0:
            raise OcrTimeoutError("total OCR timeout exceeded")

        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "OMP_THREAD_LIMIT": "1",
        }
        if os.environ.get("TESSDATA_PREFIX"):
            environment["TESSDATA_PREFIX"] = os.environ["TESSDATA_PREFIX"]
        process = subprocess.Popen(
            list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        try:
            stdout, _stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                process.kill()
            process.communicate()
            raise OcrTimeoutError("local OCR command timed out") from exc

        if process.returncode != 0:
            # Do not include stderr: Poppler/Tesseract may echo sensitive paths
            # or fragments from a receipt.
            raise ReceiptOcrError(f"local OCR command failed with exit code {process.returncode}")
        if len(stdout) > self.limits.max_ocr_chars * 4:
            raise MediaLimitError("local OCR command output is too large")
        return stdout


__all__ = [
    "LocalReceiptOcr",
    "MediaLimitError",
    "OcrLimits",
    "OcrRuntimeStatus",
    "OcrTimeoutError",
    "OcrUnavailableError",
    "PaymentAmount",
    "PaymentSignals",
    "RemoteOcrHealth",
    "RemoteReceiptOcr",
    "ReceiptOcrError",
    "ReceiptOcrResult",
    "UnsupportedMediaError",
    "detect_media_kind",
    "detect_safe_raster_mime",
    "extract_payment_signals",
    "receipt_result_from_dict",
    "receipt_result_to_dict",
    "runtime_status",
]
