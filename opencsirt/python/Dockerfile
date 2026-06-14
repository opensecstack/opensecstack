# OpenCSIRT advisory subsystem container.
#
# Multi-stage:
#   1. python:3.11-slim builder — pip-install into a virtualenv
#   2. python:3.11-slim runtime  — copy the venv + drop privileges
#
# Build context is opencsirt/python/:
#   docker build -t opensecstack/opencsirt-advisory:dev .

FROM python:3.11-slim AS build

# yara-python is a C-extension; it needs the YARA source/headers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libssl-dev libmagic1 pkg-config \
      libyara-dev automake libtool make gcc \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml ./
COPY advisory ./advisory

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel \
 && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.11-slim

# libyara1 is the runtime counterpart of libyara-dev; libmagic1 is used
# by python-magic when the YARA rules expand to attachment-typing in a
# future iteration.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libyara9 libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --gid nogroup --home /app advisory

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPENCSIRT_PY_PORT=8089

COPY --from=build /opt/venv /opt/venv
COPY --from=build /src/advisory /app/advisory

WORKDIR /app
USER advisory:nogroup

EXPOSE 8089
ENTRYPOINT ["opencsirt-advisory"]
