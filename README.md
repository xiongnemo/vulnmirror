# vulnmirror

A local, incrementally updated SQLite mirror of public vulnerability metadata:

| Source | What it contributes | Incremental channel |
|---|---|---|
| CVE Program [`cvelistV5`](https://github.com/CVEProject/cvelistV5) | the authoritative CVE record: state, dates, CNA, description, CNA/ADP affected vendor + product, references with tags, CWE, CVSS | `cves/deltaLog.json` (about 30 days) |
| [NVD](https://nvd.nist.gov) CVE API 2.0 feeds | NVD analysis status, CPE configurations, NVD reference tags, NVD CWE and CVSS | `modified` + `recent` feeds (8 days) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | known-exploited flag, date added | full reload (small) |
| [GitHub Advisory Database](https://github.com/github/advisory-database) (OSV format) | package ecosystem and name, affected and fixed versions, CVE aliases, CWE, severity | `git diff` between synced commits |

Everything lands in one SQLite file you can query with plain SQL. Every row records which
provider supplied it (`cna`, `adp:<name>`, `nvd`), so CNA-reported and NVD-enriched facts
are never silently mixed.

## Requirements

- Python 3.11 or newer, `curl` and `git` on `PATH`
- Disk: about 3.2 GB of raw downloads and a 2.8 GB database (measured 2026-09-24)

## Install

```sh
uv tool install vulnmirror          # or: pipx install vulnmirror
# from a checkout:
uv tool install --editable .
```

Or run it without installing:

```sh
uvx vulnmirror status                                 # from PyPI, in a throwaway environment
uv run vulnmirror status                              # inside a checkout
uv run --project /path/to/vulnmirror vulnmirror status  # a checkout, from any directory
```

Every form reads the same data directory (next section), so they can be mixed freely.

## Quick start

```sh
vulnmirror init        # download everything, clone the advisory database, build, update
vulnmirror status      # sync markers, their age, row counts
vulnmirror update      # afterwards: incremental update, about a minute
```

`init` retries through network outages, and every download resumes where it stopped, so
it is safe to interrupt. A first run took roughly half an hour on 2026-09-23: the NVD feeds
took about 13 minutes (NVD serves them slowly; they are fetched in parallel), the rest went
to cloning the advisory database and a build of under 3 minutes.

## Where the data lives

The data directory ("home") is resolved in this order:

1. `--home PATH`
2. `$VULNMIRROR_HOME`
3. `home = "..."` in `$XDG_CONFIG_HOME/vulnmirror/config.toml` (default `~/.config/vulnmirror/config.toml`)
4. `$XDG_DATA_HOME/vulnmirror` (default `~/.local/share/vulnmirror`)

```sh
vulnmirror config set-home ~/datasets/vulnmirror
vulnmirror config show
```

Layout inside the home: `vulnmirror.sqlite`, `MANIFEST.json` (the raw snapshot), and
`raw/` (`cvelistV5/`, `nvd/`, `kev/`, `ghsa/advisory-database/`, `cases/`).

## Keeping it current

```sh
vulnmirror update                   # all sources
vulnmirror update --only nvd,ghsa   # a subset
```

Each source is applied in its own transaction. A source that fails is rolled back and keeps
its sync marker, so running `update` again retries the same window; running it twice in a
row changes nothing. Run it at least weekly:

- NVD older than 7 days: `update` reloads the NVD tables from the yearly feeds by itself.
- cvelistV5 older than the delta log (about 30 days): `update` refuses; run `vulnmirror fetch`
  and `vulnmirror build`, then `update`.
- The advisory-database clone missing or re-cloned: `update` clones it again and reloads the
  GHSA tables when the recorded commit is gone.

A full rebuild (`vulnmirror fetch && vulnmirror build`) writes to `vulnmirror.sqlite.building`
and renames it into place when done, so queries keep working meanwhile.

## Individual records: `vulnmirror get`

Fetch single records by identifier or URL, one at a time or from lists:

```sh
vulnmirror get CVE-2024-3094                                  # CVE record + NVD record
vulnmirror get --type nvd CVE-2024-3094                       # NVD record only
vulnmirror get https://nvd.nist.gov/vuln/detail/CVE-2021-44228
vulnmirror get https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
vulnmirror get -f refs.txt                                    # one reference per line, '#' comments
cat refs.txt | vulnmirror get -f -                            # from stdin
vulnmirror get -f refs.txt --ingest                           # also upsert into the database
```

| Reference | Record type |
|---|---|
| `CVE-YYYY-NNNN` | `cve` and `nvd` (narrow with `--type`) |
| `GHSA-xxxx-xxxx-xxxx` | `ghsa` |
| `cve.org`, `cve.mitre.org`, cvelistV5 file URLs | `cve` |
| `nvd.nist.gov` pages and NVD API URLs | `nvd` |
| GitHub advisory pages (global or repository), `osv.dev`, `api.osv.dev`, advisory-database file URLs | `ghsa` |
| any other URL that contains exactly one CVE or GHSA identifier | inferred from the identifier |

Records are stored as `raw/cases/<type>/<ID>.json`. An existing file is kept unless you pass
`--force`, so re-running a long list only fetches what is missing. Every download is logged
with its source URL in `raw/cases/index.jsonl`.

- `cve` comes from cvelistV5 on GitHub.
- `nvd` comes from the NVD CVE API 2.0. Requests are spaced 6.5 s apart; set `NVD_API_KEY` to
  use the higher limit (0.7 s).
- `ghsa` is the original file from github/advisory-database, located through the OSV API. If
  the original cannot be fetched, the OSV copy is stored instead and the log says so.

## Querying

```sh
vulnmirror sql "SELECT kind, count(*) FROM reference GROUP BY kind"
vulnmirror sql "SELECT * FROM kev LIMIT 5" --format json
vulnmirror filter --vendor examplevendor --from 2024-06-01 --to 2025-05-31 --format csv -o hits.csv
vulnmirror filter --cpe-part h --cpe-scope any --from 2024-06-01 --to 2025-05-31 --count
```

`filter` searches the CNA/ADP `affected` table and the NVD `nvd_cpe` table together; the
`sources` column says which one matched. Output formats: `tsv` (default), `csv`, `json`, `jsonl`.

### Tables

| Table | Grain | Notes |
|---|---|---|
| `cve` | one row per CVE ID | from cvelistV5; `state` is `PUBLISHED` or `REJECTED` |
| `nvd` | one row per CVE ID known to NVD | `status` is NVD's analysis status |
| `affected` | CVE × provider × product | vendor and product are free text as supplied |
| `reference` | CVE × provider × URL | `kind` is derived from the URL; `tags` are the provider's own vocabulary |
| `weakness`, `metric` | CVE × provider × CWE / CVSS version | |
| `nvd_cpe` | CVE × CPE match | `part` is `a` / `o` / `h`; `vulnerable` = 1 for vulnerable matches |
| `kev` | one row per KEV entry | |
| `ghsa` | one row per advisory | `reviewed` = 1 for GitHub-reviewed advisories |
| `ghsa_alias` | advisory × alias | join to `cve.id` on CVE aliases |
| `ghsa_affected` | advisory × package | first `introduced` / `fixed` / `last_affected` event; full ranges as JSON |
| `ghsa_reference`, `ghsa_cwe` | advisory × URL / CWE | |
| `snapshot` | key / value | source snapshots and sync markers |

### Before you count

- **NVD marks device hardware as a non-vulnerable platform.** A device CVE is usually modelled as
  vulnerable firmware (`o:*_firmware`, vulnerable = 1) running on hardware (`h`, vulnerable = 0).
  Use `--cpe-scope any` for hardware queries.
- **NVD CPE coverage is incomplete** for recent CVEs, so CPE-based counts are lower bounds; the
  CNA `affected` table covers records NVD has not analysed yet.
- **CNA vendor fields are often `n/a`**, with the vendor only in NVD's CPEs. Query both tables
  (`filter` does).
- **There is no device-type field.** Selecting CVEs for one kind of device means choosing vendor
  and product criteria and checking a sample by hand.
- **Dates differ by source.** `cve.date_published`, `nvd.published` and `ghsa.published` can be
  hours to days apart; say which one a count uses.
- **Only GitHub-reviewed advisories** reliably carry package ecosystems and version ranges.

## Data terms

vulnmirror downloads data; it does not redistribute it. Each source has its own terms:

- cvelistV5: "You may search, download, and use the content hosted in this repository, per the
  [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse)" (cvelistV5 README).
- GitHub Advisory Database: [CC BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md);
  attribute GitHub when you publish derived data.
- NVD and CISA KEV: see the terms published on their sites.

## License

vulnmirror is released under the [BSD Zero Clause License](LICENSE) (SPDX `0BSD`). The data it
downloads is not covered by this license; see [Data terms](#data-terms).

## Development

```sh
uv sync                                        # environment with dev dependencies
uv run pytest                                  # unit and integration tests on synthetic data, no network
VULNMIRROR_REGRESSION=1 uv run pytest -m regression   # checks a real mirror against reference counts
uv run ruff check src tests && uv run ruff format --check src tests
uv build                                       # sdist and wheel in dist/
```

The regression tests compare a real mirror with counts computed independently from the NVD API
on 2026-09-23 (for example 42,612 non-rejected CVEs published 2024-06-01 to 2025-05-31). NVD
re-analyses records over time, so these counts carry a tolerance.
