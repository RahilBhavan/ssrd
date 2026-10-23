# SSRD runtime image (ingest + fetcher). See SAFETY.md for the threat model.
FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables util-linux ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin ssrd
COPY --from=build /opt/venv /opt/venv
COPY config /app/config
COPY docker/fetcher-entrypoint.sh docker/egress.nft /usr/local/lib/ssrd/
ENV PATH=/opt/venv/bin:$PATH SSRD_ROOT=/app PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
ENTRYPOINT ["/usr/local/lib/ssrd/fetcher-entrypoint.sh"]
