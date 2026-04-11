FROM rust:1.94-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY src src
COPY config config

RUN cargo build --release

FROM debian:bookworm-slim AS geoip-downloader
ARG GEOLITE2_COUNTRY_MMDB_URL
ARG MAXMIND_ACCOUNT_ID
ARG MAXMIND_LICENSE_KEY
ARG MAXMIND_EDITION_ID=GeoLite2-Country
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget tar && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/geoip
RUN mkdir -p /out \
    && if [ -n "${GEOLITE2_COUNTRY_MMDB_URL}" ]; then \
         echo "Downloading GeoLite2-Country.mmdb from static URL"; \
         wget --tries=3 -L "${GEOLITE2_COUNTRY_MMDB_URL}" -O /out/GeoLite2-Country.mmdb; \
       else \
         test -n "${MAXMIND_ACCOUNT_ID}" || (echo "MAXMIND_ACCOUNT_ID is required when GEOLITE2_COUNTRY_MMDB_URL is not set" && exit 1); \
         test -n "${MAXMIND_LICENSE_KEY}" || (echo "MAXMIND_LICENSE_KEY is required when GEOLITE2_COUNTRY_MMDB_URL is not set" && exit 1); \
         umask 077; \
         export HOME=/tmp; \
         printf "machine download.maxmind.com\nlogin %s\npassword %s\n" "${MAXMIND_ACCOUNT_ID}" "${MAXMIND_LICENSE_KEY}" > /tmp/.netrc; \
         wget --tries=3 --auth-no-challenge -L "https://download.maxmind.com/geoip/databases/${MAXMIND_EDITION_ID}/download?suffix=tar.gz" -O geoip.tar.gz; \
         rm -f /tmp/.netrc; \
         tar -xzf geoip.tar.gz; \
         mmdb_path="$(find . -maxdepth 2 -type f -name '*.mmdb' | head -n 1)"; \
         test -n "${mmdb_path}"; \
         cp "${mmdb_path}" /out/GeoLite2-Country.mmdb; \
       fi

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/release/edge-guard /usr/local/bin/edge-guard
COPY --from=builder /app/config /app/config
COPY --from=geoip-downloader /out/GeoLite2-Country.mmdb /app/data/GeoLite2-Country.mmdb

ENV EDGE_GUARD_LISTEN_ADDR=0.0.0.0:8080
ENV EDGE_GUARD_POLICY_FILE=/app/config/policies.yaml
ENV EDGE_GUARD_GEOIP_DB_FILE=/app/data/GeoLite2-Country.mmdb

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/edge-guard"]
