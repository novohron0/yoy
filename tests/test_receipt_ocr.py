import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from receipt_ocr import (
    LocalReceiptOcr,
    MediaLimitError,
    OcrLimits,
    OcrRuntimeStatus,
    OcrTimeoutError,
    PaymentAmount,
    PaymentSignals,
    ReceiptOcrError,
    ReceiptOcrResult,
    RemoteReceiptOcr,
    UnsupportedMediaError,
    detect_media_kind,
    detect_safe_raster_mime,
    extract_payment_signals,
    receipt_result_to_dict,
)


class PaymentSignalTests(unittest.TestCase):
    def test_bank_receipt_is_high_confidence_and_amount_is_normalized(self):
        result = extract_payment_signals(
            "Перевод выполнен успешно\nСумма перевода: 12 500,50 ₽\nПолучатель: И. И."
        )

        self.assertTrue(result.is_likely_payment)
        self.assertEqual(result.confidence, "high")
        self.assertIn("transfer", result.terms)
        self.assertIn("completed", result.terms)
        self.assertIn("recipient", result.terms)
        self.assertEqual(result.amounts[0].value, "12500.5")
        self.assertEqual(result.amounts[0].currency, "RUB")

    def test_chat_trigger_with_amount_is_reviewable_not_proof(self):
        result = extract_payment_signals("Я скинул 5 000 рублей, проверь")

        self.assertTrue(result.is_likely_payment)
        self.assertEqual(result.confidence, "medium")
        self.assertIn("sent", result.terms)
        self.assertEqual(result.amounts[0].value, "5000")

    def test_trigger_without_amount_is_low_confidence(self):
        result = extract_payment_signals("Отправил тебе фотографию")

        self.assertFalse(result.is_likely_payment)
        self.assertEqual(result.confidence, "low")
        self.assertEqual(result.amounts, ())

    def test_date_and_time_are_not_mistaken_for_amount(self):
        result = extract_payment_signals("Встреча 29.07.2026 в 12:30")

        self.assertFalse(result.is_likely_payment)
        self.assertEqual(result.amounts, ())


class LocalReceiptOcrTests(unittest.TestCase):
    def test_magic_bytes_drive_media_detection(self):
        self.assertEqual(detect_media_kind(b"%PDF-1.7\n"), "pdf")
        self.assertEqual(detect_media_kind(b"\xff\xd8\xfffake"), "image")
        with self.assertRaises(UnsupportedMediaError):
            detect_media_kind(b"invoice.jpg but not really")

    def test_media_limit_is_checked_before_ocr(self):
        worker = LocalReceiptOcr(limits=OcrLimits(max_media_bytes=8))

        with self.assertRaises(MediaLimitError):
            worker.analyze_bytes(b"\xff\xd8\xff" + b"x" * 20)

    def test_hashes_signals_and_temp_cleanup_on_success(self):
        media = b"\xff\xd8\xfffake-jpeg"
        with tempfile.TemporaryDirectory() as temp_root:
            worker = LocalReceiptOcr(temp_root=temp_root)

            def fake_prepare(_data: bytes, destination: Path) -> None:
                destination.write_bytes(b"safe")

            with (
                patch.object(worker, "_prepare_raster", side_effect=fake_prepare),
                patch.object(
                    worker,
                    "_ocr_raster",
                    return_value="Перевод выполнен. Сумма 2 000 ₽",
                ),
            ):
                result = worker.analyze_bytes(media)

            self.assertEqual(os.listdir(temp_root), [])

        self.assertEqual(result.media_sha256, hashlib.sha256(media).hexdigest())
        self.assertEqual(result.exact_dedup_key, f"sha256:{result.media_sha256}")
        self.assertTrue(result.signals.is_likely_payment)
        self.assertEqual(result.signals.amounts[0].value, "2000")

    def test_temp_cleanup_on_ocr_failure(self):
        media = b"\x89PNG\r\n\x1a\nfake"
        with tempfile.TemporaryDirectory() as temp_root:
            worker = LocalReceiptOcr(temp_root=temp_root)

            def fake_prepare(_data: bytes, destination: Path) -> None:
                destination.write_bytes(b"safe")

            with (
                patch.object(worker, "_prepare_raster", side_effect=fake_prepare),
                patch.object(worker, "_ocr_raster", side_effect=OcrTimeoutError("timeout")),
                self.assertRaises(OcrTimeoutError),
            ):
                worker.analyze_bytes(media)

            self.assertEqual(os.listdir(temp_root), [])

    def test_text_hash_ignores_case_and_whitespace(self):
        worker = LocalReceiptOcr()
        outputs = iter(("  ПЕРЕВОД   ВЫПОЛНЕН  ", "перевод выполнен"))
        hashes = []

        def fake_prepare(_data: bytes, destination: Path) -> None:
            destination.write_bytes(b"safe")

        with (
            patch.object(worker, "_prepare_raster", side_effect=fake_prepare),
            patch.object(worker, "_ocr_raster", side_effect=lambda *_args: next(outputs)),
        ):
            for suffix in (b"one", b"two"):
                hashes.append(worker.analyze_bytes(b"\xff\xd8\xff" + suffix).text_sha256)

        self.assertEqual(hashes[0], hashes[1])

    def test_empty_ocr_text_has_no_cross_media_text_dedup_key(self):
        worker = LocalReceiptOcr()

        def fake_prepare(_data: bytes, destination: Path) -> None:
            destination.write_bytes(b"safe")

        with (
            patch.object(worker, "_prepare_raster", side_effect=fake_prepare),
            patch.object(worker, "_ocr_raster", return_value="   \n"),
        ):
            result = worker.analyze_bytes(b"\xff\xd8\xffblank")

        self.assertIsNone(result.text_sha256)
        self.assertIsNone(result.text_dedup_key)


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.content = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def json(self):
        return self._payload


class FakeAsyncClient:
    def __init__(self, *, post_response=None, get_response=None):
        self.post_response = post_response
        self.get_response = get_response
        self.post_calls = []
        self.get_calls = []
        self.closed = False

    async def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return self.post_response

    async def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return self.get_response

    async def aclose(self):
        self.closed = True


def sample_result(media: bytes) -> ReceiptOcrResult:
    text = "перевод выполнен 2 000 ₽"
    return ReceiptOcrResult(
        media_sha256=hashlib.sha256(media).hexdigest(),
        text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        media_kind="image",
        text=text,
        signals=PaymentSignals(
            terms=("transfer", "completed"),
            amounts=(PaymentAmount(value="2000", currency="RUB", raw="2 000 ₽"),),
            confidence="high",
            is_likely_payment=True,
        ),
    )


class RemoteReceiptOcrTests(unittest.IsolatedAsyncioTestCase):
    async def test_protocol_roundtrip_uses_raw_body_without_network(self):
        media = b"\xff\xd8\xffprivate-image"
        expected = sample_result(media)
        client = FakeAsyncClient(post_response=FakeResponse(200, receipt_result_to_dict(expected)))
        worker = RemoteReceiptOcr("http://ocr", client=client)

        result = await worker.analyze_bytes_async(media, filename="do-not-send.jpg")

        self.assertEqual(result, expected)
        self.assertEqual(len(client.post_calls), 1)
        url, request = client.post_calls[0]
        self.assertEqual(url, "http://ocr/v1/ocr")
        self.assertEqual(request["content"], media)
        self.assertEqual(request["headers"]["Content-Type"], "image/jpeg")
        self.assertEqual(request["headers"]["X-Rita-OCR-Protocol"], "1")
        self.assertNotIn("do-not-send.jpg", repr(request))

    async def test_remote_rejects_pdf_before_any_request(self):
        client = FakeAsyncClient()
        worker = RemoteReceiptOcr("http://ocr", client=client)

        with self.assertRaises(UnsupportedMediaError):
            await worker.analyze_bytes_async(b"%PDF-1.7\nprivate")

        self.assertEqual(client.post_calls, [])

    async def test_remote_error_does_not_echo_response_body(self):
        media = b"\x89PNG\r\n\x1a\nprivate"
        client = FakeAsyncClient(
            post_response=FakeResponse(422, {"detail": "card 2200701234567890"})
        )
        worker = RemoteReceiptOcr("http://ocr", client=client)

        with self.assertRaises(ReceiptOcrError) as raised:
            await worker.analyze_bytes_async(media)

        self.assertNotIn("2200701234567890", str(raised.exception))

    async def test_remote_health_decodes_only_capabilities(self):
        client = FakeAsyncClient(
            get_response=FakeResponse(
                200,
                {
                    "ready": True,
                    "protocol": 1,
                    "formats": ["image/jpeg", "image/png"],
                    "max_media_bytes": 10 * 1024 * 1024,
                    "languages_available": True,
                },
            )
        )
        worker = RemoteReceiptOcr("http://ocr", client=client)

        health = await worker.health()

        self.assertTrue(health.ready)
        self.assertEqual(health.formats, ("image/jpeg", "image/png"))


class FakeRequest:
    def __init__(self, chunks, *, headers=None):
        self._chunks = chunks
        self.headers = headers or {}

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


class OcrSidecarProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_sidecar_accepts_jpeg_magic_and_returns_protocol_result(self):
        import ocr_service

        media = b"\xff\xd8\xffprivate-image"
        expected = sample_result(media)
        request = FakeRequest(
            [media],
            headers={
                "content-type": "image/jpeg",
                "content-length": str(len(media)),
                "x-rita-ocr-protocol": "1",
            },
        )
        with patch.object(
            ocr_service.local_ocr,
            "analyze_bytes_async",
            new=AsyncMock(return_value=expected),
        ) as analyze:
            response = await ocr_service.analyze_receipt(request)

        analyze.assert_awaited_once_with(media)
        self.assertEqual(response, receipt_result_to_dict(expected))

    async def test_sidecar_rejects_pdf_magic_without_calling_ocr(self):
        import ocr_service

        request = FakeRequest(
            [b"%PDF-1.7\nprivate"],
            headers={"content-type": "image/png", "x-rita-ocr-protocol": "1"},
        )
        with patch.object(
            ocr_service.local_ocr,
            "analyze_bytes_async",
            new=AsyncMock(),
        ) as analyze:
            with self.assertRaises(HTTPException) as raised:
                await ocr_service.analyze_receipt(request)

        self.assertEqual(raised.exception.status_code, 415)
        analyze.assert_not_awaited()

    async def test_sidecar_rejects_oversized_content_length_before_reading(self):
        import ocr_service

        request = FakeRequest(
            [],
            headers={
                "content-type": "image/jpeg",
                "content-length": str(ocr_service.MAX_MEDIA_BYTES + 1),
                "x-rita-ocr-protocol": "1",
            },
        )
        with self.assertRaises(HTTPException) as raised:
            await ocr_service.analyze_receipt(request)

        self.assertEqual(raised.exception.status_code, 413)

    async def test_sidecar_health_reports_language_readiness(self):
        import ocr_service

        ready = OcrRuntimeStatus(
            pillow_available=True,
            tesseract_path="/usr/bin/tesseract",
            pdftoppm_path=None,
            languages_available=True,
        )
        with patch.object(ocr_service, "runtime_status", return_value=ready):
            response = await ocr_service.healthz()

        self.assertTrue(response["ready"])
        self.assertEqual(response["formats"], ["image/jpeg", "image/png"])


class SafeRasterDetectionTests(unittest.TestCase):
    def test_sidecar_magic_accepts_only_jpeg_and_png(self):
        self.assertEqual(detect_safe_raster_mime(b"\xff\xd8\xffx"), "image/jpeg")
        self.assertEqual(detect_safe_raster_mime(b"\x89PNG\r\n\x1a\nx"), "image/png")
        for media in (b"%PDF-1.7\n", b"RIFF1234WEBP", b"II*\x00"):
            with self.subTest(media=media), self.assertRaises(UnsupportedMediaError):
                detect_safe_raster_mime(media)


if __name__ == "__main__":
    unittest.main()
