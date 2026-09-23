import json
import sqlite3
import threading
import urllib.error
import urllib.request

import pytest
from conftest import cvelist_record

from vulnmirror import api, build, records, serve


@pytest.fixture
def served(home):
    """start(**settings) -> base URL of a live read-only server over the synthetic mirror."""
    build.build(home, log=lambda *_: None)
    started = []

    def start(**settings):
        server = serve.make_server(serve.Settings(paths=home, **settings), "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for s in started:
        s.shutdown()
        s.server_close()


def call(url, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            return r.status, dict(r.headers), json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, dict(e.headers), json.loads(body) if body else None


# ---------------------------------------------------------------- endpoints
def test_health_status_and_index(served):
    base = served()
    assert call(f"{base}/healthz")[2] == {"ok": True}
    status, _, st = call(f"{base}/v1/status")
    assert status == 200 and st["rows"]["cve"] == 2 and "ghsa_commit" in st["snapshot"]
    idx = call(f"{base}/")[2]
    assert "/v1/cve/{id}" in idx["endpoints"] and idx["openapi"] == "/openapi.json"
    spec = call(f"{base}/openapi.json")[2]
    assert spec["openapi"].startswith("3.") and "/v1/search/cves" in spec["paths"]


def test_cve_detail(served):
    base = served()
    status, _, d = call(f"{base}/v1/cve/cve-2099-0001")  # identifiers are normalised
    assert status == 200 and d["id"] == "CVE-2099-0001"
    assert d["cve"]["state"] == "PUBLISHED" and d["nvd"]["status"] == "Modified"
    assert {r["provider"] for r in d["references"]} == {"cna", "adp:EXAMPLE-ADP", "nvd"}
    assert d["kev"]["vendor"] == "examplevendor"
    assert d["ghsa"] == ["GHSA-aaaa-bbbb-cccc"]
    hardware = [c for c in d["cpes"] if c["part"] == "h"]
    assert hardware and hardware[0]["vulnerable"] is False
    assert d["affected"][0]["versions"] == [{"version": "1.0", "status": "affected"}]
    assert "cvelist_synced_through" in d["snapshot"]


def test_cve_errors(served):
    base = served()
    assert call(f"{base}/v1/cve/CVE-2099-9999")[0] == 404
    assert call(f"{base}/v1/cve/not-a-cve")[0] == 400
    assert call(f"{base}/v1/cve/GHSA-aaaa-bbbb-cccc")[0] == 400
    assert call(f"{base}/v1/cve/CVE-2099-0001?x=1")[0] == 400
    assert call(f"{base}/v1/nothing-here")[0] == 404


def test_ghsa_detail(served):
    base = served()
    status, _, d = call(f"{base}/v1/ghsa/GHSA-AAAA-BBBB-CCCC")
    assert status == 200 and d["id"] == "GHSA-aaaa-bbbb-cccc" and d["reviewed"] is True
    assert d["aliases"] == ["CVE-2099-0001"] and d["cwes"] == ["CWE-79"]
    assert d["affected"][0]["fixed"] == "1.2.3" and d["affected"][0]["ranges"][0]["type"] == "ECOSYSTEM"
    assert call(f"{base}/v1/ghsa/GHSA-zzzz-zzzz-zzzz")[0] == 404


def test_search(served):
    base = served()
    status, _, d = call(f"{base}/v1/search/cves?vendor=examplevendor")
    assert status == 200 and d["total"] == 1 and d["limit"] == 100 and d["offset"] == 0
    item = d["items"][0]
    assert item["cve_id"] == "CVE-2099-0001" and isinstance(item["products"], list)
    assert set(item["sources"]) == {"cna", "nvd_cpe"}
    assert call(f"{base}/v1/search/cves?cpe_part=h")[2]["total"] == 0  # hardware is a non-vulnerable platform
    assert call(f"{base}/v1/search/cves?cpe_part=h&cpe_scope=any")[2]["total"] == 1
    past_end = call(f"{base}/v1/search/cves?vendor=examplevendor&offset=1")[2]
    assert past_end["items"] == [] and past_end["total"] == 1  # the total survives paging past the end
    assert call(f"{base}/v1/search/cves?vendor=nobody-at-all")[2]["total"] == 0


@pytest.mark.parametrize(
    "query",
    [
        "",  # no filter at all
        "vendor=x&limit=0",
        "vendor=x&limit=100000",
        "vendor=x&from=2024/01/01",
        "vendor=x&cpe_part=z",
        "vendor=x&state=DRAFT",
        "vendor=x&bogus=1",
        "vendor=x&limit=1&limit=2",
    ],
)
def test_search_rejects(served, query):
    assert call(f"{served()}/v1/search/cves?{query}")[0] == 400


def test_max_limit_setting(served):
    base = served(max_limit=5)
    assert call(f"{base}/v1/search/cves?vendor=x&limit=5")[0] == 200
    assert call(f"{base}/v1/search/cves?vendor=x&limit=6")[0] == 400


# ---------------------------------------------------------------- HTTP behaviour
def test_methods_head_and_cors(served):
    base = served(cors_origin="*")
    status, headers, body = call(f"{base}/v1/status", method="POST")
    assert status == 405 and "GET" in headers["Allow"]
    status, headers, body = call(f"{base}/v1/status", method="HEAD")
    assert status == 200 and body is None and int(headers["Content-Length"]) > 0
    status, headers, _ = call(f"{base}/v1/status", method="OPTIONS")
    assert status == 204 and headers["Access-Control-Allow-Origin"] == "*"
    assert call(f"{base}/v1/status")[1]["Access-Control-Allow-Origin"] == "*"


def test_no_cors_header_by_default(served):
    assert "Access-Control-Allow-Origin" not in call(f"{served()}/v1/status")[1]


def test_token(served):
    base = served(token="s3cret")
    assert call(f"{base}/healthz")[0] == 200  # liveness stays public
    status, headers, _ = call(f"{base}/v1/status")
    assert status == 401 and headers["WWW-Authenticate"] == "Bearer"
    assert call(f"{base}/v1/status", headers={"Authorization": "Bearer wrong"})[0] == 401
    assert call(f"{base}/v1/status", headers={"Authorization": "Basic s3cret"})[0] == 401
    assert call(f"{base}/v1/status", headers={"Authorization": "Bearer s3cret"})[0] == 200


def test_query_timeout_maps_to_504(served, monkeypatch):
    base = served()

    def slow(*a, **k):
        raise sqlite3.OperationalError("interrupted")

    monkeypatch.setattr(api, "search_cves", slow)
    assert call(f"{base}/v1/search/cves?vendor=x")[0] == 504


def test_unexpected_errors_still_answer(served, monkeypatch):
    base = served()
    monkeypatch.setattr(api, "status", lambda db: 1 / 0)
    status, _, body = call(f"{base}/v1/status")
    assert status == 500 and body == {"error": "internal error"}


def test_sees_updates_without_restart(served, home):
    base = served()
    assert call(f"{base}/v1/cve/CVE-2099-0100")[0] == 404
    db = sqlite3.connect(home.db)
    with db:
        records.insert_cvelist_record(db, cvelist_record("CVE-2099-0100"))
    db.close()
    assert call(f"{base}/v1/cve/CVE-2099-0100")[0] == 200


# ---------------------------------------------------------------- read-only guarantees
def test_connection_refuses_writes_and_attach(home, tmp_path):
    build.build(home, log=lambda *_: None)
    db = api.connect(home.db, timeout_s=10)
    for stmt in (
        "DELETE FROM cve",
        "INSERT INTO kev(cve_id) VALUES ('x')",
        "DROP TABLE cve",
        f"ATTACH DATABASE '{tmp_path / 'other.db'}' AS other",
        "PRAGMA query_only = OFF",
    ):
        with pytest.raises(sqlite3.DatabaseError):
            db.execute(stmt)
    assert db.execute("SELECT count(*) FROM cve").fetchone()[0] == 2
    db.close()


def test_connection_time_limit(home):
    build.build(home, log=lambda *_: None)
    db = api.connect(home.db, timeout_s=0)  # deadline already passed: the first progress check aborts
    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        db.execute(
            "SELECT count(*) FROM reference a, reference b, reference c, reference d, reference e,"
            " reference f, reference g, reference h"
        ).fetchone()
    db.close()


def test_is_loopback():
    assert serve.is_loopback("127.0.0.1") and serve.is_loopback("::1") and serve.is_loopback("localhost")
    assert not serve.is_loopback("0.0.0.0") and not serve.is_loopback("") and not serve.is_loopback("192.168.1.2")
