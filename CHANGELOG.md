# Changelog

## 0.3.0 (2026-09-26)

- `-v` / `-vv` / `-vvv` on every command, before or after the subcommand: step progress
  (including the fetch progress `update` used to discard), then every network request and
  response and every git command, then every SQL statement on writable connections. Output
  goes to stderr; without the flag nothing changes.

## 0.2.0 (2026-09-24)

- `vulnmirror serve`: a read-only JSON API over the mirror (status, CVE, GHSA, paginated search,
  OpenAPI description) on the standard library HTTP server. Read-only is enforced by the connection
  mode, `PRAGMA query_only` and an SQLite authorizer; queries run under a time limit; optional
  bearer token and CORS header; loopback by default.
- CI on Ubuntu and macOS with Python 3.11 to 3.13, one workflow per cell so the README can show a
  badge matrix. The release workflow runs the same matrix through a shared `test.yml`.
- README badges for the PyPI version and supported Python versions.

## 0.1.0 (2026-09-23)

- First release: `init`, `fetch`, `build`, `update`, `status`, `get`, `sql`, `filter`, `config`.
