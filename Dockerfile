# Rift in a container: the web console by default, or any CLI command.
#
#   docker compose up                     # console on http://localhost:8600
#   docker compose run --rm rift https://app.example.com --i-am-authorised
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    RIFT_CONTAINER=1

WORKDIR /app
RUN useradd --create-home --uid 10001 rift

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY rift ./rift
RUN mkdir -p /app/scans && chown rift:rift /app/scans
USER rift

EXPOSE 8600
ENTRYPOINT ["python", "-m", "rift"]
CMD ["serve", "--host", "0.0.0.0", "--no-browser"]
