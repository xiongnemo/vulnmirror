import json
import sqlite3

from conftest import CUTOFF, cvelist_record, ghsa_record, git, nvd_record, write_advisory, write_feed

from vulnmirror import build, fetch, net, query, records, update


def counts(db_path) -> dict:
    db = sqlite3.connect(db_path)
    tables = (
        "cve",
        "nvd",
        "affected",
        "reference",
        "weakness",
        "metric",
        "nvd_cpe",
        "kev",
        "ghsa",
        "ghsa_alias",
        "ghsa_affected",
        "ghsa_reference",
        "ghsa_cwe",
    )
    out = {t: db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables}
    db.close()
    return out


def one(db_path, sql, *params):
    db = sqlite3.connect(db_path)
    try:
        return db.execute(sql, params).fetchone()
    finally:
        db.close()


# ---------------------------------------------------------------- build
def test_build_loads_every_source(home):
    summary = build.build(home, log=lambda *_: None)
    assert summary == {"cvelist": 2, "nvd": 2, "kev": 1, "ghsa": 1}
    c = counts(home.db)
    assert c["cve"] == 2 and c["nvd"] == 2 and c["kev"] == 1 and c["ghsa"] == 1
    # providers are kept apart: CNA, ADP and NVD references are separate rows
    assert one(home.db, "SELECT count(DISTINCT provider) FROM reference WHERE cve_id='CVE-2099-0001'")[0] == 3
    assert not home.db.with_name(home.db.name + ".building").exists()


def test_build_modified_feed_wins(home):
    build.build(home, log=lambda *_: None)
    assert one(home.db, "SELECT status FROM nvd WHERE cve_id='CVE-2099-0001'")[0] == "Modified"


def test_build_records_sync_markers(home):
    build.build(home, log=lambda *_: None)
    db = sqlite3.connect(home.db)
    assert records.get_state(db, "cvelist_synced_through") == CUTOFF
    assert records.get_state(db, "nvd_synced_at") == "2099-01-02T00:00:00-04:00"
    assert len(records.get_state(db, "ghsa_commit")) == 40
    db.close()


def test_reference_kind_is_derived(home):
    build.build(home, log=lambda *_: None)
    assert (
        one(home.db, "SELECT kind FROM reference WHERE provider='cna' AND cve_id='CVE-2099-0001'")[0] == "github_commit"
    )


def test_hardware_cpe_needs_scope_any(home):
    build.build(home, log=lambda *_: None)
    db = query.connect(home.db)
    for scope, expected in (("vulnerable", 0), ("any", 1)):
        sql, params = query.filter_sql(cpe_part="h", cpe_scope=scope)
        assert len(db.execute(sql, params).fetchall()) == expected
    db.close()


# ---------------------------------------------------------------- cvelist update
def serve_delta(monkeypatch, entries, records_by_url):
    def fake_get_json(url, *a, **k):
        if url == update.DELTA_LOG:
            return entries
        if url in records_by_url:
            return records_by_url[url]
        raise net.NotFound(url)

    monkeypatch.setattr(net, "get_json", fake_get_json)


def delta_entry(fetch_time, cid, url):
    return {
        "fetchTime": fetch_time,
        "numberOfChanges": 1,
        "new": [],
        "updated": [{"cveId": cid, "githubLink": url, "dateUpdated": fetch_time}],
        "error": [],
    }


def test_update_cvelist_upserts_and_is_idempotent(home, monkeypatch):
    build.build(home, log=lambda *_: None)
    url_new = "https://example.invalid/CVE-2099-0100.json"
    url_upd = "https://example.invalid/CVE-2099-0001.json"
    entries = [
        delta_entry("2098-12-30T00:00:00.000Z", "CVE-2099-0200", "https://example.invalid/never"),  # before overlap
        delta_entry("2099-01-02T03:00:00.000Z", "CVE-2099-0100", url_new),
        delta_entry("2099-01-02T04:00:00.000Z", "CVE-2099-0001", url_upd),
    ]
    serve_delta(
        monkeypatch,
        entries,
        {
            url_new: cvelist_record("CVE-2099-0100"),
            url_upd: cvelist_record("CVE-2099-0001", product="widget-pro", updated="2099-01-02T04:00:00.000Z"),
        },
    )
    db = sqlite3.connect(home.db)
    msg = update.update_cvelist(db, home)
    assert msg.startswith("2 records upserted")
    assert records.get_state(db, "cvelist_synced_through") == "2099-01-02T04:00:00Z"
    db.close()
    first = counts(home.db)
    assert first["cve"] == 3
    assert (
        one(home.db, "SELECT product FROM affected WHERE cve_id='CVE-2099-0001' AND provider='cna'")[0] == "widget-pro"
    )
    db = sqlite3.connect(home.db)
    update.update_cvelist(db, home)  # the overlap window re-applies the last batch
    db.close()
    assert counts(home.db) == first


def test_update_cvelist_refuses_gap_beyond_delta_log(home, monkeypatch):
    build.build(home, log=lambda *_: None)
    serve_delta(monkeypatch, [delta_entry("2099-02-01T00:00:00.000Z", "CVE-2099-0100", "x")], {})
    results = update.update(home, only=("cvelist",))
    assert results[0][1] is False and "full rebuild" in results[0][2]
    db = sqlite3.connect(home.db)
    assert records.get_state(db, "cvelist_synced_through") == CUTOFF  # marker untouched
    db.close()


def test_failed_source_leaves_marker_and_data(home, monkeypatch):
    build.build(home, log=lambda *_: None)
    before = counts(home.db)
    url = "https://example.invalid/CVE-2099-0100.json"

    def failing(u, *a, **k):
        if u == update.DELTA_LOG:
            # the log must reach back past the overlap window, or update refuses before fetching
            return [
                delta_entry("2098-12-30T00:00:00.000Z", "CVE-2099-0200", "https://example.invalid/old"),
                delta_entry("2099-01-02T03:00:00.000Z", "CVE-2099-0100", url),
            ]
        raise RuntimeError("network down")

    monkeypatch.setattr(net, "get_json", failing)
    results = update.update(home, only=("cvelist",))
    assert results[0][1] is False and "sync marker unchanged" in results[0][2]
    assert counts(home.db) == before


# ---------------------------------------------------------------- NVD update
def test_update_nvd_applies_modified_and_recent(home, monkeypatch):
    build.build(home, log=lambda *_: None)
    write_feed(home.nvd_dir / "nvdcve-2.0-modified.json.gz", [nvd_record("CVE-2099-0003", status="Modified")])
    write_feed(home.nvd_dir / "nvdcve-2.0-recent.json.gz", [nvd_record("CVE-2099-0004", status="Received")])
    monkeypatch.setattr(
        fetch, "fetch_nvd_feed", lambda paths, name: {"feed": name, "lastModifiedDate": "2099-01-03T00:00:00-04:00"}
    )
    db = sqlite3.connect(home.db)
    assert "2 CVEs upserted" in update.update_nvd(db, home)
    assert records.get_state(db, "nvd_synced_at") == "2099-01-03T00:00:00-04:00"
    db.close()
    assert one(home.db, "SELECT status FROM nvd WHERE cve_id='CVE-2099-0003'")[0] == "Modified"
    assert one(home.db, "SELECT count(*) FROM nvd")[0] == 3
    # the NVD child rows of an upserted CVE are replaced, not duplicated
    assert one(home.db, "SELECT count(*) FROM nvd_cpe WHERE cve_id='CVE-2099-0003'")[0] == 2


# ---------------------------------------------------------------- GHSA update
def test_update_ghsa_applies_add_modify_delete(home, upstream):
    build.build(home, log=lambda *_: None)
    write_advisory(upstream, ghsa_record("GHSA-aaaa-bbbb-cccc", cid="CVE-2099-0001", fixed="9.9.9"))
    write_advisory(upstream, ghsa_record("GHSA-dddd-eeee-ffff", cid="CVE-2099-0100", published="2099-02-01T00:00:00Z"))
    git(upstream, "add", "-A")
    git(upstream, "commit", "-q", "-m", "add and modify")
    db = sqlite3.connect(home.db)
    assert update.update_ghsa(db, home).startswith("2 upserted, 0 deleted")
    db.close()
    assert one(home.db, "SELECT fixed FROM ghsa_affected WHERE ghsa_id='GHSA-aaaa-bbbb-cccc'")[0] == "9.9.9"
    assert one(home.db, "SELECT count(*) FROM ghsa")[0] == 2

    git(upstream, "rm", "-q", "-r", "advisories/github-reviewed/2099/02")
    git(upstream, "commit", "-q", "-m", "withdraw")
    db = sqlite3.connect(home.db)
    assert update.update_ghsa(db, home).startswith("0 upserted, 1 deleted")
    db.close()
    c = counts(home.db)
    assert c["ghsa"] == 1 and c["ghsa_alias"] == 1 and c["ghsa_affected"] == 1


def test_update_ghsa_reloads_when_synced_commit_is_missing(home):
    build.build(home, log=lambda *_: None)
    before = counts(home.db)
    db = sqlite3.connect(home.db)
    with db:
        records.set_state(db, ghsa_commit="deadbeef" * 5)
    assert update.update_ghsa(db, home).startswith("full reload (synced commit missing)")
    assert records.get_state(db, "ghsa_commit") != "deadbeef" * 5
    db.close()
    assert counts(home.db) == before


def test_update_all_sources_report(home, monkeypatch):
    build.build(home, log=lambda *_: None)
    # A delta log whose only batch predates the overlap window: nothing to apply, no gap.
    monkeypatch.setattr(update.net, "get_json", lambda url, *a, **k: [{"fetchTime": "2099-01-01T00:00:00Z"}])
    monkeypatch.setattr(
        fetch, "fetch_nvd_feed", lambda paths, name: {"feed": name, "lastModifiedDate": "2099-01-03T00:00:00Z"}
    )
    monkeypatch.setattr(fetch, "fetch_kev", lambda paths, log=None: {"catalogVersion": "2099.01.01"})
    results = update.update(home)
    assert [r[0] for r in results] == ["cvelist", "nvd", "kev", "ghsa"]
    assert all(ok for _, ok, _ in results), results
    st = query.status(query.connect(home.db))
    assert st["rows"]["cve"] == 2 and json.dumps(st)
