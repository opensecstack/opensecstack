# OpenCSIRT advisory subsystem container.
#
# Multi-stage:
#   1. python:3.11-slim-bookworm builder — pip-install into a virtualenv
#   2. python:3.11-slim-bookworm runtime  — copy the venv + drop privileges
#
# Both stages pin the Debian codename explicitly (not the floating
# "slim" tag, which tracks whatever Debian release is current stable)
# because yara-python is a C extension dynamically linked against
# libyara-dev's runtime .so at build time -- if the runtime stage
# resolved to a different Debian release than the build stage, its
# libyara package name and SONAME could both silently diverge, exactly
# what broke this build when "slim" floated from bookworm to trixie
# (libyara9 -> libyara10) between whenever this file was written and
# whenever CI first actually built it.
#
# Build context is opencsirt/python/:
#   docker build -t opensecstack/opencsirt-advisory:dev .

FROM python:3.11-slim-bookworm AS build

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

FROM python:3.11-slim-bookworm

# libyara9 is bookworm's runtime counterpart of libyara-dev (trixie's is
# libyara10 -- see the header comment on why this stage is pinned to
# bookworm specifically); libmagic1 is used
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
