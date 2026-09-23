"""The read-only API behind `vulnmirror serve`: pure functions returning JSON-ready dicts.

Read-only is enforced three ways: the database is opened with mode=ro, `PRAGMA query_only`
is on, and an SQLite authorizer allows nothing but reads (no ATTACH, no PRAGMA, no writes).
No endpoint accepts SQL. Every query runs under a time limit.
"""

import json
import re
import sqlite3
import time
from pathlib import Path

from vulnmirror import query
from vulnmirror.cases import CVE_RE, GHSA_RE, normalize_id

SNAPSHOT_KEYS = ("cvelist_synced_through", "nvd_synced_at", "ghsa_commit", "kev_catalog", "last_update_at")
_READ_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_TEXT = 200


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _authorizer(action, *_):
    return sqlite3.SQLITE_OK if action in _READ_ACTIONS else sqlite3.SQLITE_DENY


def connect(db_path: Path, timeout_s: float) -> sqlite3.Connection:
    """A read-only connection whose queries are aborted after timeout_s seconds."""
    if not db_path.exists():
        raise ApiError(503, "the mirror database has not been built")
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only = ON")
    db.set_authorizer(_authorizer)
    deadline = time.monotonic() + timeout_s
    db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
    return db


def _json(value):
    return json.loads(value) if value else None


def _rows(db, sql, *params) -> list:
    return [dict(r) for r in db.execute(sql, params).fetchall()]


def snapshot(db: sqlite3.Connection) -> dict:
    marks = ",".join("?" * len(SNAPSHOT_KEYS))
    return dict(db.execute(f"SELECT key, value FROM snapshot WHERE key IN ({marks})", SNAPSHOT_KEYS).fetchall())


def status(db: sqlite3.Connection) -> dict:
    st = query.status(db)
    return {"markers": st["markers"], "rows": st["rows"], "snapshot": snapshot(db)}


def _identifier(raw: str, pattern: re.Pattern, kind: str) -> str:
    ident = normalize_id(raw) if len(raw) <= 40 else raw
    if not pattern.fullmatch(ident):
        raise ApiError(400, f"not a {kind} identifier: {raw[:40]!r}")
    return ident


def cve(db: sqlite3.Connection, raw_id: str) -> dict:
    cid = _identifier(raw_id, CVE_RE, "CVE")
    rec = _rows(
        db,
        "SELECT state, assigner, date_reserved, date_published, date_updated, title, description FROM cve WHERE id=?",
        cid,
    )
    nvd = _rows(db, "SELECT status, published, last_modified, description FROM nvd WHERE cve_id=?", cid)
    if not rec and not nvd:
        raise ApiError(404, f"{cid} is not in the mirror")
    affected = _rows(
        db,
        "SELECT provider, vendor, product, default_status, versions, platforms, cpes FROM affected WHERE cve_id=?",
        cid,
    )
    for a in affected:
        for k in ("versions", "platforms", "cpes"):
            a[k] = _json(a[k])
    references = _rows(db, "SELECT provider, url, kind, tags FROM reference WHERE cve_id=?", cid)
    for r in references:
        r["tags"] = _json(r["tags"])
    cpes = _rows(
        db,
        "SELECT vulnerable, part, vendor, product, version, criteria, version_start_including,"
        " version_start_excluding, version_end_including, version_end_excluding"
        " FROM nvd_cpe WHERE cve_id=?",
        cid,
    )
    for c in cpes:
        c["vulnerable"] = bool(c["vulnerable"])
    kev = _rows(
        db, "SELECT vendor, product, name, date_added, due_date, known_ransomware, cwes FROM kev WHERE cve_id=?", cid
    )
    for k in kev:
        k["cwes"] = _json(k["cwes"])
    return {
        "id": cid,
        "cve": rec[0] if rec else None,
        "nvd": nvd[0] if nvd else None,
        "affected": affected,
        "references": references,
        "weaknesses": _rows(db, "SELECT provider, cwe_id, description FROM weakness WHERE cve_id=?", cid),
        "metrics": _rows(db, "SELECT provider, type, base_score, severity, vector FROM metric WHERE cve_id=?", cid),
        "cpes": cpes,
        "kev": kev[0] if kev else None,
        "ghsa": [r["ghsa_id"] for r in _rows(db, "SELECT ghsa_id FROM ghsa_alias WHERE alias=? ORDER BY ghsa_id", cid)],
        "snapshot": snapshot(db),
    }


def ghsa(db: sqlite3.Connection, raw_id: str) -> dict:
    gid = _identifier(raw_id, GHSA_RE, "GHSA")
    rec = _rows(
        db,
        "SELECT reviewed, published, modified, withdrawn, summary, details, severity, cvss_vector,"
        " github_reviewed_at, nvd_published_at FROM ghsa WHERE id=?",
        gid,
    )
    if not rec:
        raise ApiError(404, f"{gid} is not in the mirror")
    out = {"id": gid, **rec[0]}
    out["reviewed"] = bool(out["reviewed"])
    affected = _rows(
        db,
        "SELECT ecosystem, package, purl, introduced, fixed, last_affected, ranges, versions"
        " FROM ghsa_affected WHERE ghsa_id=?",
        gid,
    )
    for a in affected:
        a["ranges"], a["versions"] = _json(a["ranges"]), _json(a["versions"])
    out.update(
        aliases=[r["alias"] for r in _rows(db, "SELECT alias FROM ghsa_alias WHERE ghsa_id=? ORDER BY alias", gid)],
        affected=affected,
        references=_rows(db, "SELECT type, url, kind FROM ghsa_reference WHERE ghsa_id=?", gid),
        cwes=[r["cwe_id"] for r in _rows(db, "SELECT cwe_id FROM ghsa_cwe WHERE ghsa_id=? ORDER BY cwe_id", gid)],
        snapshot=snapshot(db),
    )
    return out


SEARCH_PARAMS = ("vendor", "product_like", "cpe_part", "cpe_scope", "from", "to", "state", "limit", "offset")


def _one(params: dict, name: str, default=None):
    values = params.get(name)
    if not values:
        return default
    if len(values) > 1:
        raise ApiError(400, f"parameter {name!r} given more than once")
    if len(values[0]) > MAX_TEXT:
        raise ApiError(400, f"parameter {name!r} is too long")
    return values[0]


def _int(params: dict, name: str, default: int, low: int, high: int) -> int:
    raw = _one(params, name)
    if raw is None:
        return default
    if not raw.isdigit() or not low <= int(raw) <= high:
        raise ApiError(400, f"parameter {name!r} must be an integer from {low} to {high}")
    return int(raw)


def search_cves(db: sqlite3.Connection, params: dict, max_limit: int = 1000) -> dict:
    """params: parsed query string ({name: [values]}), as from urllib.parse.parse_qs."""
    unknown = sorted(set(params) - set(SEARCH_PARAMS))
    if unknown:
        raise ApiError(400, f"unknown parameter(s): {', '.join(unknown)}")
    vendors = params.get("vendor") or []
    if any(len(v) > MAX_TEXT or not v.strip() for v in vendors):
        raise ApiError(400, "each 'vendor' must be non-empty and at most 200 characters")
    product_like = _one(params, "product_like")
    cpe_part = _one(params, "cpe_part")
    if cpe_part not in (None, "a", "o", "h"):
        raise ApiError(400, "'cpe_part' must be a, o or h")
    if not (vendors or product_like or cpe_part):
        raise ApiError(400, "give at least one of 'vendor', 'product_like' or 'cpe_part'")
    cpe_scope = _one(params, "cpe_scope", "vulnerable")
    if cpe_scope not in ("vulnerable", "any"):
        raise ApiError(400, "'cpe_scope' must be vulnerable or any")
    date_from, date_to = _one(params, "from"), _one(params, "to")
    for name, value in (("from", date_from), ("to", date_to)):
        if value is not None and not _DATE.match(value):
            raise ApiError(400, f"'{name}' must be a YYYY-MM-DD date")
    state = _one(params, "state", "PUBLISHED")
    if state not in ("PUBLISHED", "REJECTED"):
        raise ApiError(400, "'state' must be PUBLISHED or REJECTED")
    limit = _int(params, "limit", min(100, max_limit), 1, max_limit)
    offset = _int(params, "offset", 0, 0, 10**9)

    sql, p = query.filter_sql(
        vendors or None, product_like, cpe_part, cpe_scope, date_from, date_to, state, as_json=True
    )
    # One pass: the window function counts the full result while LIMIT/OFFSET cut the page.
    rows = db.execute(f"SELECT *, count(*) OVER () AS _total FROM ({sql}) LIMIT ? OFFSET ?", [*p, limit, offset])
    rows = rows.fetchall()
    if rows:
        total = rows[0]["_total"]
    else:  # empty page: either no match at all, or an offset past the end
        total = 0 if offset == 0 else db.execute(f"SELECT count(*) FROM ({sql})", p).fetchone()[0]
    items = []
    for r in rows:
        item = {k: r[k] for k in r.keys() if k != "_total"}
        item["sources"], item["products"] = json.loads(item["sources"]), json.loads(item["products"])
        items.append(item)
    return {"total": total, "limit": limit, "offset": offset, "items": items, "snapshot": snapshot(db)}
