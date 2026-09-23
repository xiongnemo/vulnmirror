"""Per-record parsing shared by the full build and the incremental update.

Every row keeps its provider ('cna', 'adp:<shortName>', 'nvd') so that CNA-supplied and
NVD-enriched facts are never mixed silently.
"""

import gzip
import json
import re
import sqlite3
from importlib import resources
from pathlib import Path

GH_COMMIT = re.compile(r"^https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", re.I)
GH_PR = re.compile(r"^https?://github\.com/[^/]+/[^/]+/pull/\d+", re.I)
GH_ADVISORY = re.compile(r"^https?://github\.com/([^/]+/[^/]+/security/advisories|advisories)/", re.I)
GL_COMMIT = re.compile(r"^https?://gitlab\.[^/]+/.+/-/commit/[0-9a-f]{7,40}", re.I)
GH_ANY = re.compile(r"^https?://github\.com/", re.I)


def sql_text(name: str) -> str:
    return resources.files("vulnmirror").joinpath("sql", name).read_text(encoding="utf-8")


def ref_kind(url: str) -> str:
    """Coarse, deterministic classification of a reference URL."""
    if GH_COMMIT.match(url):
        return "github_commit"
    if GH_PR.match(url):
        return "github_pull"
    if GH_ADVISORY.match(url):
        return "github_advisory"
    if GL_COMMIT.match(url):
        return "gitlab_commit"
    if GH_ANY.match(url):
        return "github_other"
    return "other"


def en(items) -> str:
    """English text from a list of {lang, value}; falls back to the first entry."""
    for d in items or []:
        if d.get("lang", "").lower().startswith("en"):
            return d.get("value", "")
    return items[0].get("value", "") if items else ""


def split_cpe(criteria: str):
    """'cpe:2.3:part:vendor:product:version:...' -> (part, vendor, product, version)."""
    p = criteria.split(":")
    return (p[2], p[3], p[4], p[5]) if len(p) > 5 else (None, None, None, None)


def jdump(v):
    return json.dumps(v) if v else None


# ---------------------------------------------------------------- snapshot state
def set_state(db: sqlite3.Connection, **kv) -> None:
    db.executemany("INSERT OR REPLACE INTO snapshot(key, value) VALUES (?,?)", [(k, str(v)) for k, v in kv.items()])


def get_state(db: sqlite3.Connection, key: str):
    row = db.execute("SELECT value FROM snapshot WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------- cvelistV5
def insert_cvelist_record(db: sqlite3.Connection, rec: dict):
    md = rec.get("cveMetadata", {})
    cid = md.get("cveId")
    if not cid:
        return None
    cont = rec.get("containers", {})
    cna = cont.get("cna", {})
    db.execute(
        "INSERT OR REPLACE INTO cve(id, state, assigner, date_reserved, date_published, date_updated, title,"
        " description) VALUES (?,?,?,?,?,?,?,?)",
        (
            cid,
            md.get("state"),
            md.get("assignerShortName"),
            md.get("dateReserved"),
            md.get("datePublished"),
            md.get("dateUpdated"),
            cna.get("title"),
            en(cna.get("descriptions")) or en(cna.get("rejectedReasons")),
        ),
    )
    providers = [("cna", cna)] + [
        ("adp:" + a.get("providerMetadata", {}).get("shortName", "?"), a) for a in cont.get("adp", [])
    ]
    for prov, c in providers:
        for a in c.get("affected", []) or []:
            db.execute(
                "INSERT INTO affected(cve_id, provider, vendor, product, platforms, default_status, versions, cpes)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    cid,
                    prov,
                    a.get("vendor"),
                    a.get("product"),
                    jdump(a.get("platforms")),
                    a.get("defaultStatus"),
                    jdump(a.get("versions")),
                    jdump(a.get("cpes")),
                ),
            )
        for r in c.get("references", []) or []:
            url = r.get("url", "")
            db.execute(
                "INSERT INTO reference(cve_id, provider, url, kind, tags) VALUES (?,?,?,?,?)",
                (cid, prov, url, ref_kind(url), jdump(r.get("tags"))),
            )
        for pt in c.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                db.execute(
                    "INSERT INTO weakness(cve_id, provider, cwe_id, description) VALUES (?,?,?,?)",
                    (cid, prov, d.get("cweId"), d.get("description")),
                )
        for m in c.get("metrics", []) or []:
            for mtype, body in m.items():
                if isinstance(body, dict) and "baseScore" in body:
                    db.execute(
                        "INSERT INTO metric(cve_id, provider, type, base_score, severity, vector) VALUES (?,?,?,?,?,?)",
                        (cid, prov, mtype, body.get("baseScore"), body.get("baseSeverity"), body.get("vectorString")),
                    )
    return cid


def delete_cvelist_rows(db: sqlite3.Connection, cid: str) -> None:
    db.execute("DELETE FROM cve WHERE id=?", (cid,))
    db.execute("DELETE FROM affected WHERE cve_id=?", (cid,))
    for t in ("reference", "weakness", "metric"):
        db.execute(f"DELETE FROM {t} WHERE cve_id=? AND provider!='nvd'", (cid,))


# ---------------------------------------------------------------- NVD
def insert_nvd_record(db: sqlite3.Connection, c: dict) -> str:
    cid = c["id"]
    db.execute(
        "INSERT OR REPLACE INTO nvd(cve_id, status, published, last_modified, description) VALUES (?,?,?,?,?)",
        (cid, c.get("vulnStatus"), c.get("published"), c.get("lastModified"), en(c.get("descriptions"))),
    )
    for r in c.get("references", []):
        url = r.get("url", "")
        db.execute(
            "INSERT INTO reference(cve_id, provider, url, kind, tags) VALUES (?,?,?,?,?)",
            (cid, "nvd", url, ref_kind(url), jdump(r.get("tags"))),
        )
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            db.execute(
                "INSERT INTO weakness(cve_id, provider, cwe_id, description) VALUES (?,?,?,?)",
                (cid, "nvd", d.get("value"), w.get("source")),
            )
    for mtype, lst in (c.get("metrics") or {}).items():
        for m in lst:
            cd = m.get("cvssData", {})
            db.execute(
                "INSERT INTO metric(cve_id, provider, type, base_score, severity, vector) VALUES (?,?,?,?,?,?)",
                (
                    cid,
                    "nvd",
                    mtype,
                    cd.get("baseScore"),
                    cd.get("baseSeverity") or m.get("baseSeverity"),
                    cd.get("vectorString"),
                ),
            )
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for mt in node.get("cpeMatch", []):
                part, vendor, product, version = split_cpe(mt.get("criteria", ""))
                db.execute(
                    "INSERT INTO nvd_cpe(cve_id, vulnerable, part, vendor, product, version, criteria,"
                    " version_start_including, version_start_excluding, version_end_including,"
                    " version_end_excluding) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        cid,
                        1 if mt.get("vulnerable") else 0,
                        part,
                        vendor,
                        product,
                        version,
                        mt.get("criteria"),
                        mt.get("versionStartIncluding"),
                        mt.get("versionStartExcluding"),
                        mt.get("versionEndIncluding"),
                        mt.get("versionEndExcluding"),
                    ),
                )
    return cid


def delete_nvd_rows(db: sqlite3.Connection, cid: str) -> None:
    db.execute("DELETE FROM nvd WHERE cve_id=?", (cid,))
    db.execute("DELETE FROM nvd_cpe WHERE cve_id=?", (cid,))
    for t in ("reference", "weakness", "metric"):
        db.execute(f"DELETE FROM {t} WHERE cve_id=? AND provider='nvd'", (cid,))


def delete_all_nvd(db: sqlite3.Connection) -> None:
    db.execute("DELETE FROM nvd")
    db.execute("DELETE FROM nvd_cpe")
    for t in ("reference", "weakness", "metric"):
        db.execute(f"DELETE FROM {t} WHERE provider='nvd'")


def iter_nvd_feed(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    for v in data.get("vulnerabilities", []):
        yield v["cve"]


# ---------------------------------------------------------------- KEV
def load_kev(db: sqlite3.Connection, path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    db.execute("DELETE FROM kev")
    for v in data.get("vulnerabilities", []):
        db.execute(
            "INSERT OR REPLACE INTO kev(cve_id, vendor, product, name, date_added, due_date,"
            " known_ransomware, cwes) VALUES (?,?,?,?,?,?,?,?)",
            (
                v.get("cveID"),
                v.get("vendorProject"),
                v.get("product"),
                v.get("vulnerabilityName"),
                v.get("dateAdded"),
                v.get("dueDate"),
                v.get("knownRansomwareCampaignUse"),
                jdump(v.get("cwes")),
            ),
        )
    return len(data.get("vulnerabilities", []))
