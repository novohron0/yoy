FROM python:3.12-slim

# tzdata — чтобы расписания срабатывали по нужному часовому поясу (TZ задаётся в compose)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY web.py userbot.py ./
COPY static ./static

# profiles/ (сессии + расписания) монтируется как volume в compose
EXPOSE 8000

CMD ["uvicorn", "web:app", "--host", "0.0.0.0", "--port", "8000"]
