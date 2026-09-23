"""Fetch individual records ("cases") by identifier or URL, one or many.

A reference is an identifier or a URL:

  CVE-2024-3094                                    kinds cve + nvd (or just one with type=)
  GHSA-xxxx-xxxx-xxxx                              kind ghsa
  https://www.cve.org/CVERecord?id=CVE-...         kind cve   (also cve.mitre.org, cvelistV5 on GitHub)
  https://nvd.nist.gov/vuln/detail/CVE-...         kind nvd   (also the NVD CVE API URL)
  https://github.com/advisories/GHSA-...           kind ghsa  (also repository security advisories,
                                                               osv.dev, api.osv.dev, github/advisory-database)
  any other URL holding exactly one CVE or GHSA identifier: inferred from that identifier

Each record is stored as <home>/raw/cases/<kind>/<ID>.json (written atomically). An existing
file is kept unless force=True, so re-running a list resumes where it stopped.
Every download is logged to <home>/raw/cases/index.jsonl with its source URL.

Sources: cve -> cvelistV5 on GitHub; nvd -> NVD CVE API 2.0 (rate limited; set NVD_API_KEY
for the higher limit); ghsa -> the original file in github/advisory-database, located via
api.osv.dev (falls back to the OSV copy, marked as such, if the original cannot be fetched).
"""

import datetime as dt
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from vulnmirror import ghsa, net, records
from vulnmirror.config import Paths

KINDS = ("cve", "nvd", "ghsa")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
COMMENT_RE = re.compile(r"(^|\s)#.*$")

CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/vulns"

URL_KIND_RULES = [
    # (host suffix, path must contain, kind)
    ("nvd.nist.gov", "", "nvd"),
    ("cve.org", "", "cve"),
    ("cve.mitre.org", "", "cve"),
    ("github.com", "/cveproject/cvelistv5", "cve"),
    ("raw.githubusercontent.com", "/cveproject/cvelistv5", "cve"),
    ("github.com", "/github/advisory-database", "ghsa"),
    ("raw.githubusercontent.com", "/github/advisory-database", "ghsa"),
    ("github.com", "/advisories/", "ghsa"),
    ("osv.dev", "", "ghsa"),
]


@dataclass(frozen=True)
class Case:
    kind: str
    id: str


def normalize_id(raw: str) -> str:
    return raw.upper() if raw.upper().startswith("CVE-") else "GHSA-" + raw[5:].lower()


def _ids_in(text: str) -> list:
    ids = [normalize_id(m) for m in CVE_RE.findall(text)] + [normalize_id(m) for m in GHSA_RE.findall(text)]
    return list(dict.fromkeys(ids))


def _check(kind: str, cid: str, ref: str) -> None:
    want_cve = kind in ("cve", "nvd")
    if want_cve != cid.startswith("CVE-"):
        raise ValueError(f"{ref!r}: identifier {cid} does not fit type {kind}")


def parse_ref(ref: str, kind: str | None = None) -> list:
    """Turn one reference into cases. kind forces the record type."""
    ref = ref.strip()
    if not ref or ref.startswith("#"):
        return []
    if kind and kind not in KINDS:
        raise ValueError(f"unknown type {kind!r}; expected one of {', '.join(KINDS)}")
    if "://" in ref or ref.lower().startswith("www."):
        u = urllib.parse.urlparse(ref if "://" in ref else "https://" + ref)
        host, path = (u.hostname or "").lower(), urllib.parse.unquote(u.path).lower()
        ids = _ids_in(urllib.parse.unquote(ref))
        if len(ids) != 1:
            raise ValueError(f"{ref!r}: expected exactly one CVE or GHSA identifier, found {len(ids)}")
        cid = ids[0]
        inferred = next((k for h, p, k in URL_KIND_RULES if (host == h or host.endswith("." + h)) and p in path), None)
        if inferred is None:
            inferred = "ghsa" if cid.startswith("GHSA-") else None
        kinds = [kind] if kind else ([inferred] if inferred else ["cve", "nvd"])
    else:
        ids = _ids_in(ref)
        if len(ids) != 1 or ids[0] != normalize_id(ref):
            raise ValueError(f"{ref!r}: not a CVE or GHSA identifier")
        cid = ids[0]
        kinds = [kind] if kind else (["ghsa"] if cid.startswith("GHSA-") else ["cve", "nvd"])
    for k in kinds:
        _check(k, cid, ref)
    return [Case(k, cid) for k in kinds]


def read_refs(items: list, files: list | None = None, stdin=None) -> list:
    """Collect references from positional items, list files ('-' = stdin), one per line; '#' starts a comment."""
    refs = list(items)
    for f in files or []:
        text = stdin.read() if f == "-" else Path(f).read_text(encoding="utf-8")
        for line in text.splitlines():
            # A comment starts at '#' at the line start or after whitespace; URL fragments keep theirs.
            line = COMMENT_RE.sub("", line).strip()
            if line:
                refs.append(line)
    return refs


# ---------------------------------------------------------------- fetchers
def cvelist_url(cid: str) -> str:
    _, year, num = cid.split("-")
    return f"{CVELIST_RAW}/{year}/{int(num) // 1000}xxx/{cid}.json"


class _RateLimit:
    """Minimum spacing between calls, shared across threads."""

    def __init__(self, interval: float):
        self.interval, self.last, self.lock = interval, 0.0, threading.Lock()

    def wait(self) -> None:
        with self.lock:
            delay = self.last + self.interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.last = time.monotonic()


# NVD allows 5 requests per rolling 30 s without a key and 50 with one.
_NVD_LIMIT = _RateLimit(0.7 if os.environ.get("NVD_API_KEY") else 6.5)


def fetch_cve(cid: str):
    url = cvelist_url(cid)
    rec = net.get_json(url)
    got = rec.get("cveMetadata", {}).get("cveId")
    if got != cid:
        raise RuntimeError(f"{url} returned {got}")
    return rec, url


def fetch_nvd(cid: str):
    url = f"{NVD_API}?cveId={cid}"
    key = os.environ.get("NVD_API_KEY")
    _NVD_LIMIT.wait()
    data = net.get_json(url, headers={"apiKey": key} if key else None)
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        raise net.NotFound(url)
    return vulns[0]["cve"], url


def fetch_ghsa(gid: str):
    osv = net.get_json(f"{OSV_API}/{gid}")
    path = None
    for a in osv.get("affected") or []:
        src = (a.get("database_specific") or {}).get("source", "")
        if "/blob/main/" in src:
            path = src.split("/blob/main/", 1)[1]
            break
    path = path or ghsa.repo_path_for(osv)
    url = ghsa.RAW_BASE + path
    try:
        rec = net.get_json(url)
        if rec.get("id") != gid:
            raise RuntimeError(f"{url} returned {rec.get('id')}")
        return rec, url
    except net.NotFound:
        return osv, f"{OSV_API}/{gid}"  # the OSV copy: same advisory, with OSV's derived fields added


FETCHERS = {"cve": fetch_cve, "nvd": fetch_nvd, "ghsa": fetch_ghsa}


# ---------------------------------------------------------------- driver
def case_file(paths: Paths, case: Case) -> Path:
    return paths.raw / "cases" / case.kind / f"{case.id}.json"


def _write_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    tmp.replace(path)


def _one(paths: Paths, case: Case, force: bool) -> dict:
    dest = case_file(paths, case)
    if dest.exists() and not force:
        return {"kind": case.kind, "id": case.id, "status": "cached", "path": str(dest)}
    try:
        rec, url = FETCHERS[case.kind](case.id)
    except net.NotFound:
        return {"kind": case.kind, "id": case.id, "status": "not_found"}
    except Exception as e:
        return {"kind": case.kind, "id": case.id, "status": "error", "message": str(e)}
    _write_atomic(dest, rec)
    return {"kind": case.kind, "id": case.id, "status": "downloaded", "path": str(dest), "source": url}


def get_cases(paths: Paths, cases: list, force: bool = False, jobs: int = 8) -> list:
    """Download cases, skipping existing files unless force. NVD requests run one at a time."""
    cases = list(dict.fromkeys(cases))
    nvd = [c for c in cases if c.kind == "nvd"]
    other = [c for c in cases if c.kind != "nvd"]
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        results = list(ex.map(lambda c: _one(paths, c, force), other))
    results += [_one(paths, c, force) for c in nvd]
    index = paths.raw / "cases" / "index.jsonl"
    index.parent.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    with open(index, "a", encoding="utf-8") as f:
        for r in results:
            if r["status"] == "downloaded":
                f.write(json.dumps({"kind": r["kind"], "id": r["id"], "source": r["source"], "fetched_at": now}) + "\n")
    order = {c: i for i, c in enumerate(cases)}
    return sorted(results, key=lambda r: order[Case(r["kind"], r["id"])])


def ingest(paths: Paths, results: list) -> int:
    """Upsert downloaded or cached cases into the database; sync markers are left alone."""
    if not paths.db.exists():
        raise FileNotFoundError(f"no database at {paths.db}; run `vulnmirror build` first")
    db = sqlite3.connect(paths.db)
    n = 0
    with db:
        for r in results:
            if r["status"] not in ("downloaded", "cached"):
                continue
            rec = json.loads(Path(r["path"]).read_text(encoding="utf-8"))
            if r["kind"] == "cve":
                records.delete_cvelist_rows(db, r["id"])
                records.insert_cvelist_record(db, rec)
            elif r["kind"] == "nvd":
                records.delete_nvd_rows(db, r["id"])
                records.insert_nvd_record(db, rec)
            else:
                ghsa.delete_advisory(db, r["id"])
                ghsa.insert_advisory(db, rec, f"case:{r['path']}")
            n += 1
    db.close()
    return n
