# syntax=docker/dockerfile:1
FROM python:3.11-slim AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml README.md ./
COPY src ./src

# Build a wheel so the runtime stage installs one artifact, not the source
# tree + a build backend.
RUN pip install --upgrade pip build && python -m build --wheel --outdir /build/dist


FROM python:3.11-slim AS runtime

# libcap2-bin gives us setcap so the container can grant the interpreter
# CAP_NET_RAW/CAP_NET_ADMIN for live capture without running the whole
# process as root (see docker-compose.yml's `cap_add` as the alternative,
# simpler route for local/dev use).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 nids
WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

ENV NIDS_ENVIRONMENT=production \
    NIDS_API_HOST=0.0.0.0 \
    NIDS_API_PORT=8000 \
    PYTHONUNBUFFERED=1

USER nids
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/system/health', timeout=2).status==200 else 1)"


# No init process baked in — run with `docker run --init` (or compose's
# `init: true`, already set in docker-compose.yml) so SIGTERM reaches
# uvicorn directly and zombie reaping is handled by the container runtime.
CMD ["nids", "serve"]
