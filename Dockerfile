FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    EVE_HOST=0.0.0.0 \
    EVE_PORT=8000

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY eve ./eve
COPY frontend ./frontend

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

CMD ["python", "-m", "eve"]
