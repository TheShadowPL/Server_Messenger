FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production
ENV FLASK_APP=server.py

RUN useradd -m appuser && \
    mkdir -p /home/appuser/app && \
    chown -R appuser:appuser /home/appuser/app

WORKDIR /home/appuser/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

COPY . .

RUN chown -R appuser:appuser .

USER appuser

EXPOSE 5000

# Zmienione, aby używać server:app zamiast app:app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "server:app"]