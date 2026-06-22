# Audel — Ears for AI Agents 👂  (REST service image)
#
# Security posture:
# - runs as a NON-root user;
# - the service binds loopback by default and is zero-config; to expose it on a routable interface
#   you MUST pass AUDEL_API_TOKEN (the app refuses a non-loopback bind without it — fail closed);
# - no secrets are baked into the image (provider keys come from the runtime env at request time);
# - ffmpeg is the only system dependency (the deterministic signal path).
FROM python:3.12-slim AS base

# ffmpeg for decode/signals; clean apt lists to keep the image small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user.
RUN useradd --create-home --uid 10001 audel
WORKDIR /app

# Install the package with the REST service extra. (Build context = repo root.)
COPY . /app
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[serve]"

USER audel
EXPOSE 8000

# Loopback-only by default. To expose: run with -e AUDEL_API_TOKEN=... and pass --host 0.0.0.0.
ENV AUDEL_LOG_LEVEL=WARNING
ENTRYPOINT ["audel", "serve"]
CMD ["--host", "127.0.0.1", "--port", "8000"]
