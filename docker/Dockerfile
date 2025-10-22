# syntax=docker/dockerfile:1.7
FROM postgres:18 AS builder
ARG DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    build-essential libcurl4-openssl-dev postgresql-server-dev-18; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY src/ ./src/
RUN make -C src

FROM ghcr.io/cloudnative-pg/postgresql:18-standard-trixie
ARG DEBIAN_FRONTEND=noninteractive
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libcurl4 ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*
COPY --chmod=0644 docker/certs/server.crt /usr/local/share/ca-certificates/kc-root.crt
RUN update-ca-certificates
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
USER postgres
COPY --from=builder /work/src/kc_validator.so /usr/lib/postgresql/18/lib/