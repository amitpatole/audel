# Audel — Ears for AI Agents (REST service image)
#
# Security posture:
# - runs as a NON-root user (uid 10001) and works with a read-only root filesystem: the only
#   writable paths are the workspace (/var/cache/audel) and /tmp, mounted as volumes;
# - the whisper model is downloaded at BUILD time and the runtime is offline for models
#   (HF_HUB_OFFLINE=1), so a running container never fetches code or weights;
# - binds 0.0.0.0 inside the container but REFUSES to start without auth (AUDEL_API_TOKEN):
#   fail closed;
# - no secrets are baked in (tokens and provider keys come from the runtime environment).
#
# Build:  docker build -t audel:1.0 --build-arg EXTRAS=serve,asr --build-arg ASR_MODEL=small .
# Run:    docker run --read-only --tmpfs /tmp -v audel-cache:/var/cache/audel \
#           --env-file audel.env -p 8000:8000 audel:1.0      (keeps the token out of `docker inspect` args)
# Base pinned by digest (python:3.12-slim); bump deliberately.
FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e AS base

ARG EXTRAS=serve,asr
ARG ASR_MODEL=base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 audel
WORKDIR /app
COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[${EXTRAS}]"

# Bake the ASR model in (only when the asr extra is installed).
ENV AUDEL_ASR_MODEL_DIR=/opt/audel/models AUDEL_ASR_MODEL=${ASR_MODEL}
RUN mkdir -p /opt/audel/models \
    && if python -c "import faster_whisper" 2>/dev/null; then \
         python -c "from faster_whisper import WhisperModel; WhisperModel('${ASR_MODEL}', device='cpu', compute_type='int8', download_root='/opt/audel/models')"; \
       fi \
    && chown -R 10001:10001 /opt/audel

ENV HF_HUB_OFFLINE=1 \
    AUDEL_CACHE_DIR=/var/cache/audel \
    AUDEL_LOG_LEVEL=WARNING \
    HOME=/home/audel
RUN mkdir -p /var/cache/audel && chown 10001:10001 /var/cache/audel
VOLUME ["/var/cache/audel"]

USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"
ENTRYPOINT ["audel", "serve"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
