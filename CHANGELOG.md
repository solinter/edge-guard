# Changelog

All notable changes to this project are documented in this file.

## [0.0.2] - 2026-04-19

### Added

- **Throttling rule type** (`type: throttle`) with:
  - request limits per `max_requests` in `window_seconds`
  - temporary blocking for `block_seconds`
  - key dimensions via `key_by` (`client_ip`, `method`, `path`)
  - optional rule scoping by `match_method_in` and `match_path_prefix_in`
- **Throttle engine integration** into policy evaluation pipeline.
- **Storage abstraction for throttling** via `ThrottleStore` trait to support future distributed backends (for example Redis) and horizontal scaling.
- **In-memory high-performance throttle store** implementation using `DashMap`.
- **Additional policy example** in `strict-v2` showing throttling on `/login` traffic.
- **Comprehensive README updates** documenting:
  - throttling behavior and design
  - all supported rule types
  - GeoIP download source precedence and build options
  - fixed policy override usage

## [0.0.1] - 2026-04-11

### Initial Release

### Added

- Rust-based WAF authorization microservice (`edge-guard`) for balancer/proxy integrations.
- Header-only request evaluation model (compatible with NGINX `auth_request` and Traefik `ForwardAuth`).
- Policy engine embedded in service with static configured policies (`baseline-v1`, `strict-v2`).
- Optional inline policy evaluation for trusted callers.
- Fixed policy override by ID through request header.
- Rule types:
  - `path_contains`
  - `method_in`
  - `header_equals`
  - `header_regex`
  - `ip_in_denylist`
  - `country_in`
  - `continent_in`
  - `is_in_european_union`
- GeoIP resolver using MaxMind GeoLite2-Country database with in-memory startup load.
- Docker and Docker Compose setup with build-time GeoLite2 download support:
  - static URL override (`GEOLITE2_COUNTRY_MMDB_URL`)
  - MaxMind authenticated fallback (`MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`)
- Graceful shutdown handling for container stop signals (`SIGINT`, `SIGTERM`).
- Health endpoint (`/healthz`) and observability headers in auth responses.

