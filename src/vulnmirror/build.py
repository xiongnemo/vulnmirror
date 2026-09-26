"""Full build of <home>/vulnmirror.sqlite from the raw mirrors listed in <home>/MANIFEST.json.

The database is written to vulnmirror.sqlite.building and renamed into place only when
complete, so queries against the previous database keep working during a rebuild.
"""

import json
import sqlite3
import zipfile
from pathlib import Path

from vulnmirror import ghsa, logs, records
from vulnmirror.config import Paths


def iter_cvelist_export(paths: Paths, asset: str):
    """Yield CVE JSON 5 records from the daily export (a zip that wraps a zip)."""
    with zipfile.ZipFile(paths.cvelist_dir / asset) as outer:
        inner_names = [n for n in outer.namelist() if n.endswith(".zip")]
        if inner_names:
            inner_path = paths.cvelist_dir / "_inner.zip"
            if not inner_path.exists() or inner_path.stat().st_size != outer.getinfo(inner_names[0]).file_size:
                with outer.open(inner_names[0]) as src, open(inner_path, "wb") as dst:
                    while chunk := src.read(1 << 20):
                        dst.write(chunk)
            z = zipfile.ZipFile(inner_path)
        else:
            z = outer
        with z:
            for name in z.namelist():
                base = name.rsplit("/", 1)[-1]
                if base.startswith("CVE-") and base.endswith(".json"):
                    yield json.loads(z.read(name))


def export_cutoff(asset_name: str) -> str:
    """'2026-09-23_all_CVEs_at_midnight.zip.zip' -> '2026-09-23T00:00:00Z'."""
    return asset_name[:10] + "T00:00:00Z"


def build(paths: Paths, log=print) -> dict:
    if not paths.manifest.exists():
        raise FileNotFoundError(f"no {paths.manifest}; run `vulnmirror fetch` first")
    manifest = json.loads(paths.manifest.read_text())
    tmp = Path(str(paths.db) + ".building")
    tmp.unlink(missing_ok=True)
    db = logs.trace_sql(sqlite3.connect(tmp))
    db.executescript(records.sql_text("schema.sql"))
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")

    cl = manifest["cvelistV5"]
    log(f"cvelistV5 {cl['release_tag']}")
    n_cl = 0
    for rec in iter_cvelist_export(paths, cl["asset"]):
        if records.insert_cvelist_record(db, rec):
            n_cl += 1
            if n_cl % 100000 == 0:
                log(f"  cvelistV5: {n_cl} records")
    db.commit()

    # 'modified' and 'recent' first: their copy of a CVE is the newest, and the first copy wins.
    feeds = [paths.nvd_dir / f"nvdcve-2.0-{n}.json.gz" for n in ("modified", "recent")]
    feeds = [f for f in feeds if f.exists()] + sorted(paths.nvd_dir.glob("nvdcve-2.0-[0-9]*.json.gz"))
    seen, n_nvd = set(), 0
    for f in feeds:
        for c in records.iter_nvd_feed(f):
            if c["id"] in seen:
                continue
            seen.add(c["id"])
            records.insert_nvd_record(db, c)
            n_nvd += 1
        db.commit()
        log(f"  nvd: {f.name} done ({n_nvd} total)")

    n_kev = records.load_kev(db, paths.kev_file) if paths.kev_file.exists() else 0

    n_ghsa, commit = 0, ""
    if paths.ghsa_repo.exists():
        n_ghsa, commit = ghsa.load_all(db, paths.ghsa_repo, log=log)
        log(f"  ghsa: {n_ghsa} advisories @ {commit[:12]}")

    nvd_feeds = {f["feed"]: f["lastModifiedDate"] for f in manifest.get("nvd", [])}
    state = dict(
        cvelistV5_release=cl["release_tag"],
        cvelist_synced_through=export_cutoff(cl["asset"]),
        nvd_synced_at=nvd_feeds.get("modified", ""),
        nvd_feeds=json.dumps(nvd_feeds),
        kev_catalog=manifest.get("kev", {}).get("catalogVersion", ""),
        fetched_at=manifest["fetched_at"],
        n_cvelist=n_cl,
        n_nvd=n_nvd,
        n_kev=n_kev,
        n_ghsa=n_ghsa,
    )
    if commit:
        state["ghsa_commit"] = commit
    records.set_state(db, **state)
    db.executescript(records.sql_text("indexes.sql"))
    db.commit()
    db.close()
    tmp.replace(paths.db)
    summary = {"cvelist": n_cl, "nvd": n_nvd, "kev": n_kev, "ghsa": n_ghsa}
    log(f"built {paths.db}: " + " ".join(f"{k}={v}" for k, v in summary.items()))
    return summary
