"""Read-only queries: status, raw SQL, and the vendor / product / CPE filter."""

import datetime as dt
import sqlite3
from pathlib import Path

from vulnmirror.update import ts

# How old a sync marker may get before an incremental update can no longer catch up.
STALE_AFTER = {"cvelist_synced_through": dt.timedelta(days=25), "nvd_synced_at": dt.timedelta(days=6)}
COUNTED = ("cve", "nvd", "affected", "reference", "nvd_cpe", "kev", "ghsa", "ghsa_affected")


def connect(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise FileNotFoundError(f"no database at {path}; run `vulnmirror build` first")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def status(db: sqlite3.Connection) -> dict:
    snap = dict(db.execute("SELECT key, value FROM snapshot").fetchall())
    now = dt.datetime.now(dt.UTC)
    markers = {}
    for key, limit in STALE_AFTER.items():
        value = snap.get(key)
        age = now - ts(value) if value else None
        markers[key] = {
            "value": value,
            "age_hours": round(age.total_seconds() / 3600, 1) if age else None,
            "stale": age is None or age > limit,
        }
    rows = {t: db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in COUNTED}
    info = {k: snap.get(k) for k in ("ghsa_commit", "kev_catalog", "cvelistV5_release", "last_update_at")}
    return {"markers": markers, "info": info, "rows": rows}


def run_sql(db: sqlite3.Connection, statement: str) -> tuple:
    cur = db.execute(statement)
    cols = [d[0] for d in cur.description or []]
    return cols, [tuple(r) for r in cur.fetchall()]


def filter_sql(
    vendor=None,
    product_like=None,
    cpe_part=None,
    cpe_scope="vulnerable",
    date_from=None,
    date_to=None,
    state="PUBLISHED",
) -> tuple:
    """One query over CNA/ADP `affected` and NVD `nvd_cpe`; each hit reports which source matched.

    NVD models a device as vulnerable firmware ('o', vulnerable=1) running on hardware
    ('h', vulnerable=0), so hardware queries need cpe_scope='any'.
    """
    parts, params = [], []

    def vp_clause() -> str:
        conds = []
        if vendor:
            conds.append("(" + " OR ".join("lower(vendor) LIKE ?" for _ in vendor) + ")")
            params.extend(f"%{v.lower()}%" for v in vendor)
        if product_like:
            conds.append("lower(product) LIKE ?")
            params.append(product_like.lower())
        return " AND ".join(conds) or "1"

    if not cpe_part:
        parts.append("SELECT cve_id, provider AS source, vendor, product FROM affected WHERE " + vp_clause())
    cpe_where = vp_clause()
    if cpe_part:
        cpe_where += " AND part = ?"
        params.append(cpe_part)
    vuln = "vulnerable=1 AND " if cpe_scope == "vulnerable" else ""
    parts.append("SELECT cve_id, 'nvd_cpe' AS source, vendor, product FROM nvd_cpe WHERE " + vuln + cpe_where)

    window, wparams = [], []
    if date_from:
        window.append("substr(COALESCE(n.published, c.date_published),1,10) >= ?")
        wparams.append(date_from)
    if date_to:
        window.append("substr(COALESCE(n.published, c.date_published),1,10) <= ?")
        wparams.append(date_to)
    sql = (
        "SELECT h.cve_id, c.state, COALESCE(n.published, c.date_published) AS published, c.assigner,"
        " group_concat(DISTINCT h.source) AS sources,"
        " group_concat(DISTINCT h.vendor || ':' || h.product) AS products"
        f" FROM ({' UNION '.join(parts)}) h"
        " JOIN cve c ON c.id = h.cve_id LEFT JOIN nvd n ON n.cve_id = h.cve_id"
        " WHERE c.state = ?" + "".join(f" AND {w}" for w in window) + " GROUP BY h.cve_id ORDER BY published"
    )
    return sql, params + [state] + wparams
