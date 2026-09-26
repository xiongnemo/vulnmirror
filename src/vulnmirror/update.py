"""Incremental, in-place update of <home>/vulnmirror.sqlite.

  cvelist  cves/deltaLog.json (rolling ~30 days): every CVE listed in a batch newer than
           snapshot.cvelist_synced_through is re-fetched and upserted. Records are fetched in
           their current form, so re-applying a batch is harmless; a one-hour overlap is kept.
  nvd      'modified' + 'recent' feeds (rolling 8 days): every CVE in them is upserted. If the
           last NVD sync is older than NVD_MAX_GAP, the NVD tables are reloaded from the yearly feeds.
  kev      reloaded in full.
  ghsa     git fetch + diff against snapshot.ghsa_commit; reloaded in full if that commit is gone.

Each source runs in its own transaction: a failure rolls back that source only and leaves
its sync marker unchanged, so running update again retries the same window.
"""

import datetime as dt
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from vulnmirror import fetch, ghsa, logs, net, records
from vulnmirror.config import Paths

DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
OVERLAP = dt.timedelta(hours=1)
NVD_MAX_GAP = dt.timedelta(days=7)
SOURCES = ("cvelist", "nvd", "kev", "ghsa")

log = logging.getLogger("vulnmirror.update")


class NeedFullRebuild(RuntimeError):
    pass


def ts(s: str) -> dt.datetime:
    """Parse ISO timestamps with 'Z', offsets or fractional seconds into aware UTC datetimes."""
    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=dt.UTC)


def update_cvelist(db: sqlite3.Connection, paths: Paths, jobs: int = 16) -> str:
    since = records.get_state(db, "cvelist_synced_through")
    if not since:
        raise NeedFullRebuild("no cvelist_synced_through in snapshot")
    delta = net.get_json(DELTA_LOG)
    oldest = min(ts(e["fetchTime"]) for e in delta)
    start = ts(since) - OVERLAP
    log.info(
        "cvelist: synced through %s; delta log has %d batches from %s", since, len(delta), f"{oldest:%Y-%m-%d %H:%M}Z"
    )
    if start < oldest:
        raise NeedFullRebuild(f"gap starts {start:%Y-%m-%d}, delta log starts {oldest:%Y-%m-%d}")
    changed, newest = {}, ts(since)
    for e in delta:
        t = ts(e["fetchTime"])
        if t > start:
            for x in (e.get("new") or []) + (e.get("updated") or []):
                changed[x["cveId"]] = x["githubLink"]
            newest = max(newest, t)
    log.info(
        "cvelist: %d records changed since %s; fetching with %d workers", len(changed), f"{start:%Y-%m-%d %H:%M}Z", jobs
    )
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        recs = list(ex.map(net.get_json, changed.values()))
    log.info("cvelist: fetched %d records; writing", len(recs))
    with db:
        for rec in recs:
            cid = rec.get("cveMetadata", {}).get("cveId")
            if cid:
                records.delete_cvelist_rows(db, cid)
                records.insert_cvelist_record(db, rec)
        records.set_state(db, cvelist_synced_through=newest.isoformat().replace("+00:00", "Z"))
    return f"{len(recs)} records upserted, synced through {newest:%Y-%m-%d %H:%M}Z"


def update_nvd(db: sqlite3.Connection, paths: Paths) -> str:
    last = records.get_state(db, "nvd_synced_at")
    full = not last or dt.datetime.now(dt.UTC) - ts(last) > NVD_MAX_GAP
    log.info(
        "nvd: last synced %s; %s",
        last or "never",
        "full reload from the yearly feeds" if full else "applying modified + recent",
    )
    if full:
        metas = fetch.fetch_nvd(paths, jobs=6, log=log.info)
        names = ["modified", "recent"] + sorted(m["feed"] for m in metas if m["feed"][0].isdigit())
    else:
        metas = [fetch.fetch_nvd_feed(paths, "modified"), fetch.fetch_nvd_feed(paths, "recent")]
        for m in metas:
            log.info("nvd %s: %s", m["feed"], m.get("status", "fetched"))
        names = ["modified", "recent"]
    seen = set()
    with db:
        if full:
            records.delete_all_nvd(db)
        for name in names:
            log.info("nvd: loading feed %s", name)
            for c in records.iter_nvd_feed(paths.nvd_dir / f"nvdcve-2.0-{name}.json.gz"):
                if c["id"] in seen:
                    continue
                seen.add(c["id"])
                if not full:
                    records.delete_nvd_rows(db, c["id"])
                records.insert_nvd_record(db, c)
        mod = next(m for m in metas if m["feed"] == "modified")
        records.set_state(db, nvd_synced_at=mod["lastModifiedDate"])
    return f"{'full reload' if full else 'modified+recent'}, {len(seen)} CVEs upserted"


def update_kev(db: sqlite3.Connection, paths: Paths) -> str:
    meta = fetch.fetch_kev(paths, log=log.info)
    with db:
        n = records.load_kev(db, paths.kev_file)
        records.set_state(db, kev_catalog=meta["catalogVersion"])
    return f"{n} entries, catalog {meta['catalogVersion']}"


def update_ghsa(db: sqlite3.Connection, paths: Paths) -> str:
    repo = paths.ghsa_repo
    if not repo.exists():
        ghsa.clone(repo)
    synced = records.get_state(db, "ghsa_commit")
    log.info("ghsa: synced commit %s", synced[:12] if synced else "unset")
    if not synced or not ghsa.has_commit(repo, synced):
        # No recorded commit, or the mirror was re-cloned and no longer holds it: a diff is
        # impossible, so reload the GHSA tables from the current head.
        ghsa.git(repo, "fetch", "--depth", "1", "origin", "main")
        ghsa.git(repo, "reset", "--hard", "-q", "FETCH_HEAD")
        with db:
            ghsa.delete_all(db)
            n, commit = ghsa.load_all(db, repo, commit_every=0)
            records.set_state(db, ghsa_commit=commit)
        return f"full reload (synced commit {'missing' if synced else 'unset'}), {n} advisories @ {commit[:12]}"
    with db:
        up, de, new = ghsa.sync(db, repo, synced)
        records.set_state(db, ghsa_commit=new)
    ghsa.finish_sync(repo, new)
    return f"{up} upserted, {de} deleted @ {new[:12]}"


STEPS = {"cvelist": update_cvelist, "nvd": update_nvd, "kev": update_kev, "ghsa": update_ghsa}


def update(paths: Paths, only=SOURCES) -> list:
    """Run the requested sources; returns [(source, ok, message)]."""
    if not paths.db.exists():
        raise FileNotFoundError(f"no database at {paths.db}; run `vulnmirror build` first")
    db = logs.trace_sql(sqlite3.connect(paths.db))
    results = []
    for name in only:
        log.info("%s: starting", name)
        try:
            results.append((name, True, STEPS[name](db, paths)))
        except NeedFullRebuild as e:
            results.append((name, False, f"needs a full rebuild ({e}); run `vulnmirror fetch` and `vulnmirror build`"))
        except Exception as e:
            results.append((name, False, f"failed, sync marker unchanged ({e})"))
    with db:
        records.set_state(db, last_update_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"))
    db.execute("PRAGMA optimize")
    db.close()
    return results
