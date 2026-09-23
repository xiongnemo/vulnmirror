"""Download the raw sources into <home>/raw and record the snapshot in <home>/MANIFEST.json.

  cvelistV5  CVE Program JSON 5 records: daily full export from the latest GitHub release
  nvd        NVD CVE API 2.0 feeds (yearly + modified + recent), each verified against its .meta sha256
  kev        CISA Known Exploited Vulnerabilities catalogue

Downloads resume after interruption and are skipped when the local copy already matches
the published checksum, so running fetch again is cheap.
"""

import datetime as dt
import gzip
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from vulnmirror import net
from vulnmirror.config import Paths

NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_FIRST_YEAR = 2002
CVELIST_LATEST = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def gunzip_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with gzip.open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def parse_meta(text: str) -> dict:
    meta = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta


def nvd_feed_names(today: dt.date | None = None) -> list:
    year = (today or dt.date.today()).year
    return [str(y) for y in range(NVD_FIRST_YEAR, year + 1)] + ["modified", "recent"]


def fetch_nvd_feed(paths: Paths, name: str) -> dict:
    """Fetch one NVD feed ('2024', 'modified', 'recent', ...) and verify it against its .meta.

    The .meta sha256 is of the uncompressed JSON; gzSize is the size of the .gz file.
    """
    meta = parse_meta(net.get_text(f"{NVD_BASE}/nvdcve-2.0-{name}.meta"))
    dest = paths.nvd_dir / f"nvdcve-2.0-{name}.json.gz"
    want = meta["sha256"].upper()
    if dest.exists() and dest.stat().st_size == int(meta["gzSize"]) and gunzip_sha256(dest) == want:
        return {"feed": name, "status": "cached", **meta}
    net.download(f"{NVD_BASE}/nvdcve-2.0-{name}.json.gz", dest)
    got = gunzip_sha256(dest)
    if got != want:
        dest.unlink()
        raise RuntimeError(f"nvd {name}: sha256 mismatch (got {got}, want {want})")
    return {"feed": name, "status": "downloaded", **meta}


def fetch_nvd(paths: Paths, jobs: int = 6, log=print) -> list:
    results, errors = [], []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futures = [(n, ex.submit(fetch_nvd_feed, paths, n)) for n in nvd_feed_names()]
        for name, fut in futures:
            try:
                r = fut.result()
                results.append(r)
                log(f"nvd {name}: {r['status']}")
            except Exception as e:  # keep going; report all failures at the end
                errors.append(f"nvd {name}: {e}")
                log(f"nvd {name}: FAILED {e}")
    if errors:
        raise RuntimeError("; ".join(errors))
    return sorted(results, key=lambda r: r["feed"])


def fetch_cvelist(paths: Paths, log=print) -> dict:
    rel = json.loads(net.get_text(CVELIST_LATEST))
    asset = next(a for a in rel["assets"] if "all_CVEs_at_midnight" in a["name"])
    dest = paths.cvelist_dir / asset["name"]
    if not (dest.exists() and dest.stat().st_size == asset["size"]):
        # Keep one full export: drop exports from earlier snapshots.
        for old in paths.cvelist_dir.glob("*_all_CVEs_at_midnight*"):
            if old != dest and not old.name.endswith(".part"):
                old.unlink()
        net.download(asset["browser_download_url"], dest)
    if dest.stat().st_size != asset["size"]:
        raise RuntimeError("cvelistV5: size mismatch")
    log(f"cvelistV5: {rel['tag_name']} ok")
    return {
        "release_tag": rel["tag_name"],
        "asset": asset["name"],
        "size": asset["size"],
        "sha256": sha256(dest),
        "published_at": rel["published_at"],
    }


def fetch_kev(paths: Paths, log=print) -> dict:
    net.download(KEV_URL, paths.kev_file, resume=False)
    data = json.loads(paths.kev_file.read_text(encoding="utf-8"))
    log(f"kev: {data.get('catalogVersion')} ok")
    return {
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "count": data.get("count"),
        "sha256": sha256(paths.kev_file),
    }


def fetch(paths: Paths, only=("cvelist", "nvd", "kev"), jobs: int = 6, log=print) -> dict:
    paths.home.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(paths.manifest.read_text()) if paths.manifest.exists() else {}
    if "cvelist" in only:
        manifest["cvelistV5"] = fetch_cvelist(paths, log)
    if "kev" in only:
        manifest["kev"] = fetch_kev(paths, log)
    if "nvd" in only:
        manifest["nvd"] = fetch_nvd(paths, jobs, log)
    manifest["fetched_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    paths.manifest.write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest
