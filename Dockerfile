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

# libcap2-bin gives us setcap (see below). tcpdump pulls in libpcap as a
# dependency — without it scapy has no way to *compile* a BPF filter
# string like "ip or ip6" at all (it shells out to `tcpdump -ddd` for
# that on Linux) and sniff() raises Scapy_Exception on the first live
# capture attempt, filter or no filter in the call.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 nids
WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# This is the step that actually grants it — `docker-compose.yml`'s
# `cap_add: [NET_RAW, NET_ADMIN]` alone only adds those to the
# *container's* capability bounding set; a non-root process (see `USER
# nids` below) doesn't get anything from the bounding set for free. It
# needs the capability in its own file-capability set to gain it on
# exec — verified the hard way: `cap_add` without this line still raised
# `PermissionError: Operation not permitted` from a non-root scapy sniff().
# Setting it on the interpreter itself (not a narrower wrapper) is a
# known, accepted tradeoff for a single-purpose image whose only job is
# running this app.
RUN setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v python3)")"

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
