FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 artifacts
COPY --chown=artifacts:artifacts registry.py ./
COPY --chown=artifacts:artifacts bin ./bin
COPY --chown=artifacts:artifacts data ./data
COPY --chown=artifacts:artifacts web ./web
USER artifacts
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
CMD ["python", "registry.py"]
