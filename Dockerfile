FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The trained model is bundled; rebuilding the container does not fetch data
# or trigger a training run.

# Run as a non-root user rather than default root.
RUN useradd --create-home --uid 1000 cybersentinel \
    && mkdir -p /app/reports /app/data \
    && chown -R cybersentinel:cybersentinel /app
USER cybersentinel

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
