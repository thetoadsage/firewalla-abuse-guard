FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY firewalla_abuse_guard ./firewalla_abuse_guard
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home guard \
    && mkdir /app/data && chown guard:guard /app/data
USER 10001:10001
ENTRYPOINT ["firewalla-abuse-guard"]
CMD ["--config", "/app/config.yml"]
