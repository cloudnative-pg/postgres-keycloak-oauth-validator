ARG BASE=ghcr.io/cloudnative-pg/postgresql:18-standard-trixie

FROM $BASE AS builder
ARG DEBIAN_FRONTEND=noninteractive
USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    libcurl4-openssl-dev \
    postgresql-server-dev-18
WORKDIR /srv
COPY meson.build LICENSE ./
COPY src/ ./src/
RUN meson setup build && meson compile -C build/

FROM scratch

COPY --from=builder /srv/build/kc_validator.so /lib
