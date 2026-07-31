"""Private OCR sidecar for bounded JPEG/PNG receipt recognition.

The service accepts a raw request body and returns structured JSON.  It has no
Telegram, audit-store, user, or secret dependencies and should run without the
main application's environment or volumes.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from receipt_ocr import (
    LocalReceiptOcr,
    MediaLimitError,
    OcrLimits,
    OcrTimeoutError,
    OcrUnavailableError,
    ReceiptOcrError,
    UnsupportedMediaError,
    detect_safe_raster_mime,
    receipt_result_to_dict,
    runtime_status,
)


PROTOCOL_VERSION = 1
MAX_MEDIA_BYTES = 10 * 1024 * 1024
BODY_READ_TIMEOUT_SECONDS = 10
SAFE_FORMATS = ("image/jpeg", "image/png")

app = FastAPI(
    title="Rita isolated OCR",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
local_ocr = LocalReceiptOcr(
    limits=OcrLimits(max_media_bytes=MAX_MEDIA_BYTES, max_pdf_pages=1),
    max_parallel_jobs=1,
)
_ocr_gate = asyncio.Semaphore(1)
_log = logging.getLogger("rita.ocr")


async def _read_limited_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid content length") from exc
        if declared_size < 0:
            raise HTTPException(status_code=400, detail="invalid content length")
        if declared_size > MAX_MEDIA_BYTES:
            raise HTTPException(status_code=413, detail="media too large")

    body = bytearray()
    async for chunk in request.stream():
        if not chunk:
            continue
        if len(body) + len(chunk) > MAX_MEDIA_BYTES:
            raise HTTPException(status_code=413, detail="media too large")
        body.extend(chunk)
    return bytes(body)


@app.get("/healthz")
async def healthz():
    status = runtime_status()
    payload = {
        "ready": status.images_available,
        "protocol": PROTOCOL_VERSION,
        "formats": list(SAFE_FORMATS),
        "max_media_bytes": MAX_MEDIA_BYTES,
        "languages_available": status.languages_available,
    }
    if not status.images_available:
        return JSONResponse(payload, status_code=503)
    return payload


@app.post("/v1/ocr")
async def analyze_receipt(request: Request):
    if request.headers.get("x-rita-ocr-protocol") != str(PROTOCOL_VERSION):
        raise HTTPException(status_code=400, detail="unsupported protocol")

    declared_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if declared_type and declared_type not in SAFE_FORMATS:
        raise HTTPException(status_code=415, detail="unsupported media")

    # Acquire before reading so concurrent requests cannot each retain a 10 MiB
    # body while waiting for the single Tesseract process.
    async with _ocr_gate:
        try:
            async with asyncio.timeout(BODY_READ_TIMEOUT_SECONDS):
                data = await _read_limited_body(request)
        except TimeoutError as exc:
            raise HTTPException(status_code=408, detail="request body timeout") from exc
        try:
            detected_type = detect_safe_raster_mime(data)
        except (TypeError, UnsupportedMediaError) as exc:
            raise HTTPException(status_code=415, detail="unsupported media") from exc
        if declared_type and declared_type != detected_type:
            raise HTTPException(status_code=415, detail="unsupported media")

        try:
            result = await local_ocr.analyze_bytes_async(data)
        except MediaLimitError as exc:
            raise HTTPException(status_code=413, detail="media too large") from exc
        except UnsupportedMediaError as exc:
            raise HTTPException(status_code=415, detail="unsupported media") from exc
        except OcrTimeoutError as exc:
            raise HTTPException(status_code=504, detail="OCR timeout") from exc
        except OcrUnavailableError as exc:
            raise HTTPException(status_code=503, detail="OCR unavailable") from exc
        except ReceiptOcrError as exc:
            # Never include exception text: native tools may mention private paths.
            _log.warning("OCR request failed: %s", type(exc).__name__)
            raise HTTPException(status_code=422, detail="OCR failed") from exc
        except Exception as exc:
            _log.error("OCR request failed: %s", type(exc).__name__)
            raise HTTPException(status_code=500, detail="OCR failed") from exc
        finally:
            data = None

    return receipt_result_to_dict(result)
