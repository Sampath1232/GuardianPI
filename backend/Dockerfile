# Guardian Pi Backend
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN groupadd -r guardian && useradd -r -g guardian -s /bin/false guardian
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
RUN chown -R guardian:guardian /app
USER guardian
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/api/v1/health/live').raise_for_status()"
CMD ["gunicorn", "backend.app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
