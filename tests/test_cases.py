import io
import json
import sqlite3

import pytest
from conftest import cvelist_record, ghsa_record, nvd_record

from vulnmirror import build, cases, ghsa, net
from vulnmirror.cases import Case, parse_ref

C, N, G = "cve", "nvd", "ghsa"


@pytest.mark.parametrize(
    "ref, kind, expected",
    [
        ("CVE-2024-3094", None, [Case(C, "CVE-2024-3094"), Case(N, "CVE-2024-3094")]),
        ("cve-2024-3094", N, [Case(N, "CVE-2024-3094")]),
        ("GHSA-22C2-9GWG-MJ59", None, [Case(G, "GHSA-22c2-9gwg-mj59")]),
        ("https://nvd.nist.gov/vuln/detail/CVE-2024-3094", None, [Case(N, "CVE-2024-3094")]),
        ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094", None, [Case(N, "CVE-2024-3094")]),
        ("https://www.cve.org/CVERecord?id=CVE-2024-3094", None, [Case(C, "CVE-2024-3094")]),
        ("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094", None, [Case(C, "CVE-2024-3094")]),
        (
            "https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/3xxx/CVE-2024-3094.json",
            None,
            [Case(C, "CVE-2024-3094")],
        ),
        (
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/3xxx/CVE-2024-3094.json",
            None,
            [Case(C, "CVE-2024-3094")],
        ),
        ("https://github.com/advisories/GHSA-22c2-9gwg-mj59", None, [Case(G, "GHSA-22c2-9gwg-mj59")]),
        (
            "https://github.com/example/widget/security/advisories/GHSA-22c2-9gwg-mj59",
            None,
            [Case(G, "GHSA-22c2-9gwg-mj59")],
        ),
        ("https://osv.dev/vulnerability/GHSA-22c2-9gwg-mj59", None, [Case(G, "GHSA-22c2-9gwg-mj59")]),
        (
            "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2025/05/"
            "GHSA-22c2-9gwg-mj59/GHSA-22c2-9gwg-mj59.json",
            None,
            [Case(G, "GHSA-22c2-9gwg-mj59")],
        ),
        ("https://example.org/blog/CVE-2024-3094", None, [Case(C, "CVE-2024-3094"), Case(N, "CVE-2024-3094")]),
        ("https://nvd.nist.gov/vuln/detail/CVE-2024-3094", C, [Case(C, "CVE-2024-3094")]),  # explicit type wins
    ],
)
def test_parse_ref(ref, kind, expected):
    assert parse_ref(ref, kind) == expected


@pytest.mark.parametrize(
    "ref, kind",
    [
        ("https://example.org/CVE-2024-1111-and-CVE-2024-2222", None),  # two identifiers
        ("https://example.org/nothing-here", None),
        ("not-an-id", None),
        ("CVE-2024-3094", G),  # type does not fit the identifier
        ("GHSA-22c2-9gwg-mj59", N),
        ("CVE-2024-3094", "kev"),
    ],
)
def test_parse_ref_rejects(ref, kind):
    with pytest.raises(ValueError):
        parse_ref(ref, kind)


def test_parse_ref_ignores_blank_and_comment():
    assert parse_ref("   ") == [] and parse_ref("# note") == []


def test_read_refs_files_and_comments(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("CVE-2024-3094   # xz\n\n# a comment line\nhttps://nvd.nist.gov/vuln/detail/CVE-2021-44228#range\n")
    refs = cases.read_refs(["GHSA-22c2-9gwg-mj59"], [str(f), "-"], stdin=io.StringIO("CVE-2014-0160\n"))
    assert refs == [
        "GHSA-22c2-9gwg-mj59",
        "CVE-2024-3094",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228#range",
        "CVE-2014-0160",
    ]


@pytest.mark.parametrize(
    "cid, bucket",
    [
        ("CVE-2024-3094", "2024/3xxx"),
        ("CVE-2024-28041", "2024/28xxx"),
        ("CVE-2026-12974", "2026/12xxx"),
        ("CVE-2024-0006", "2024/0xxx"),
    ],
)
def test_cvelist_url(cid, bucket):
    assert cases.cvelist_url(cid).endswith(f"/cves/{bucket}/{cid}.json")


def test_repo_path_for():
    assert (
        ghsa.repo_path_for(ghsa_record("GHSA-aaaa-bbbb-cccc", published="2025-05-06T20:00:17Z"))
        == "advisories/github-reviewed/2025/05/GHSA-aaaa-bbbb-cccc/GHSA-aaaa-bbbb-cccc.json"
    )
    assert ghsa.repo_path_for(ghsa_record("GHSA-aaaa-bbbb-cccc", reviewed=False)).startswith("advisories/unreviewed/")


# ---------------------------------------------------------------- download driver
@pytest.fixture
def fake_fetchers(monkeypatch):
    calls = []
    store = {
        ("cve", "CVE-2099-0100"): cvelist_record("CVE-2099-0100"),
        ("nvd", "CVE-2099-0100"): nvd_record("CVE-2099-0100"),
        ("ghsa", "GHSA-dddd-eeee-ffff"): ghsa_record("GHSA-dddd-eeee-ffff", cid="CVE-2099-0100"),
    }

    def make(kind):
        def f(cid):
            calls.append((kind, cid))
            if (kind, cid) == ("cve", "CVE-2099-0999"):
                raise RuntimeError("boom")
            if (kind, cid) not in store:
                raise net.NotFound(cid)
            return store[(kind, cid)], f"https://example.invalid/{kind}/{cid}"

        return f

    monkeypatch.setattr(cases, "FETCHERS", {k: make(k) for k in cases.KINDS})
    return calls


def test_get_downloads_then_skips(home, fake_fetchers):
    wanted = parse_ref("CVE-2099-0100") + parse_ref("GHSA-dddd-eeee-ffff")
    first = cases.get_cases(home, wanted)
    assert [r["status"] for r in first] == ["downloaded"] * 3
    assert len(fake_fetchers) == 3
    second = cases.get_cases(home, wanted)
    assert [r["status"] for r in second] == ["cached"] * 3
    assert len(fake_fetchers) == 3  # nothing fetched again
    forced = cases.get_cases(home, wanted, force=True)
    assert [r["status"] for r in forced] == ["downloaded"] * 3
    stored = json.loads(cases.case_file(home, Case("nvd", "CVE-2099-0100")).read_text())
    assert stored["id"] == "CVE-2099-0100"
    assert not list((home.raw / "cases").rglob("*.tmp"))
    index = (home.raw / "cases" / "index.jsonl").read_text().splitlines()
    assert len(index) == 6 and json.loads(index[0])["source"].startswith("https://example.invalid/")


def test_get_reports_not_found_and_errors(home, fake_fetchers):
    res = cases.get_cases(home, [Case("cve", "CVE-2099-0404"), Case("cve", "CVE-2099-0999")])
    assert [r["status"] for r in res] == ["not_found", "error"]
    assert not cases.case_file(home, Case("cve", "CVE-2099-0404")).exists()


def test_get_ingest_upserts(home, fake_fetchers):
    build.build(home, log=lambda *_: None)
    res = cases.get_cases(home, parse_ref("CVE-2099-0100") + parse_ref("GHSA-dddd-eeee-ffff"))
    assert cases.ingest(home, res) == 3
    db = sqlite3.connect(home.db)
    assert db.execute("SELECT count(*) FROM cve WHERE id='CVE-2099-0100'").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM nvd WHERE cve_id='CVE-2099-0100'").fetchone()[0] == 1
    assert db.execute("SELECT path FROM ghsa WHERE id='GHSA-dddd-eeee-ffff'").fetchone()[0].startswith("case:")
    before = db.execute("SELECT count(*) FROM reference").fetchone()[0]
    db.close()
    cases.ingest(home, res)  # ingesting again replaces rows, never duplicates them
    db = sqlite3.connect(home.db)
    assert db.execute("SELECT count(*) FROM reference").fetchone()[0] == before
    db.close()


def test_fetch_ghsa_prefers_original_file(monkeypatch):
    osv = ghsa_record("GHSA-dddd-eeee-ffff", cid="CVE-2099-0100")
    osv["affected"][0]["database_specific"] = {
        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2099/01/"
        "GHSA-dddd-eeee-ffff/GHSA-dddd-eeee-ffff.json"
    }
    original = ghsa_record("GHSA-dddd-eeee-ffff", cid="CVE-2099-0100")
    served = {}

    def fake(url, *a, **k):
        served.setdefault("urls", []).append(url)
        if url.startswith(cases.OSV_API):
            return osv
        if url.startswith(ghsa.RAW_BASE):
            return original
        raise net.NotFound(url)

    monkeypatch.setattr(net, "get_json", fake)
    rec, url = cases.fetch_ghsa("GHSA-dddd-eeee-ffff")
    assert rec is original and url.startswith(ghsa.RAW_BASE)
    assert url.endswith("github-reviewed/2099/01/GHSA-dddd-eeee-ffff/GHSA-dddd-eeee-ffff.json")


def test_fetch_ghsa_falls_back_to_osv_copy(monkeypatch):
    osv = ghsa_record("GHSA-dddd-eeee-ffff", reviewed=False)

    def fake(url, *a, **k):
        if url.startswith(cases.OSV_API):
            return osv
        raise net.NotFound(url)

    monkeypatch.setattr(net, "get_json", fake)
    rec, url = cases.fetch_ghsa("GHSA-dddd-eeee-ffff")
    assert rec is osv and url.startswith(cases.OSV_API)
