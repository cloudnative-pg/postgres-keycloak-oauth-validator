ARG BASE=ghcr.io/cloudnative-pg/postgresql:18-minimal-trixie

FROM $BASE AS builder
ARG DEBIAN_FRONTEND=noninteractive
ARG PG_MAJOR=18

USER root
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    # Base image system libraries
    ldconfig -p | awk '{print $NF}' | grep '^/' | sort | uniq > /tmp/base-image-libs.out && \
    # Build Dependencies
    apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      meson \
      libcurl4-openssl-dev \
      "postgresql-server-dev-${PG_MAJOR}"

WORKDIR /srv
COPY meson.build LICENSE ./
COPY src/ ./src/
RUN meson setup build && meson compile -C build/

# Gather keycloack-oauth-validator system libraries and their licenses
RUN mkdir -p /system /licenses && \
    ldd /srv/build/kc_validator.so | awk '{print $3}' | grep '^/' | sort | uniq > /tmp/all-deps.out && \
    comm -13 /tmp/base-image-libs.out /tmp/all-deps.out > /tmp/libraries.out && \
    for lib in $(cat /tmp/libraries.out); do cp -a "${lib%.so*}.so"* /system; done && \
    # Licenses
    for lib in $(find /system -maxdepth 1 -type f -name '*.so*'); do \
      pkg=$(dpkg -S "$(basename "$lib")" | awk -F: '{print $1}'); \
      [ -z "$pkg" ] && continue; \
      mkdir -p "/licenses/$pkg" && cp -a /usr/share/doc/"$pkg"/* "/licenses/$pkg/"; \
    done


FROM scratch

COPY --from=builder /srv/LICENSE ./
COPY --from=builder /srv/build/kc_validator.so /lib/
COPY --from=builder /system /system/
COPY --from=builder /licenses /licenses/
