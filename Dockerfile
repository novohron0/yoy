FROM python:3.12-slim

# Основной сервис не содержит OCR-движок: изображения обрабатывает отдельный
# изолированный контейнер без Telegram-сессий и секретов.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY web.py userbot.py payment_audit.py payment_audit_store.py receipt_ocr.py ./
COPY static ./static

# profiles/ (сессии + расписания) монтируется как volume в compose
EXPOSE 8000

CMD ["uvicorn", "web:app", "--host", "0.0.0.0", "--port", "8000"]
