"""Snapshot regression: a real, fully built mirror against counts computed independently.

The reference values come from the NVD CVE API 2.0 (paged queries, not the feeds) on
2026-09-23, for CVEs published 2024-06-01 .. 2025-05-31. NVD re-analyses records over
time, so counts carry a tolerance; the CVE-Genie membership checks are exact.

Opt in:  VULNMIRROR_REGRESSION=1 uv run pytest -m regression
"""

import os
import sqlite3
from pathlib import Path

import pytest

from vulnmirror.config import Paths, resolve_home

pytestmark = pytest.mark.regression
FIXTURE = Path(__file__).with_name("fixtures") / "cvegenie_large_ids.txt"
WINDOW = "substr(n.published,1,10) BETWEEN '2024-06-01' AND '2025-05-31' AND n.status != 'Rejected'"
EMBEDDED = """EXISTS (SELECT 1 FROM nvd_cpe c WHERE c.cve_id=n.cve_id
              AND (c.part='h' OR (c.part='o' AND c.product LIKE '%\\_firmware' ESCAPE '\\')))"""
GH_COMMIT = """EXISTS (SELECT 1 FROM reference r WHERE r.cve_id=n.cve_id AND r.provider='nvd'
               AND r.kind='github_commit')"""


def within(value: int, ref: int, rel: float) -> bool:
    return abs(value - ref) <= max(1, round(ref * rel))


@pytest.fixture(scope="module")
def one():
    if os.environ.get("VULNMIRROR_REGRESSION") != "1":
        pytest.skip("set VULNMIRROR_REGRESSION=1 to check a real mirror")
    db_path = Paths(resolve_home()[0]).db
    if not db_path.exists():
        pytest.skip(f"no mirror at {db_path}")
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    yield lambda sql: db.execute(sql).fetchone()[0]
    db.close()


@pytest.fixture(scope="module")
def genie():
    return [line.strip() for line in FIXTURE.read_text().splitlines() if line.startswith("CVE-")]


def test_window_size(one):
    assert within(one(f"SELECT count(*) FROM nvd n WHERE {WINDOW}"), 42612, 0.005)


def test_window_github_commit(one):
    assert within(one(f"SELECT count(*) FROM nvd n WHERE {WINDOW} AND {GH_COMMIT}"), 2103, 0.01)


def test_cvegenie_fixture(genie):
    assert len(genie) == len(set(genie)) == 841


def test_cvegenie_all_in_window_with_github_commit(one, genie):
    ids = ",".join(f"'{i}'" for i in genie)
    assert one(f"SELECT count(*) FROM nvd n WHERE n.cve_id IN ({ids}) AND {WINDOW}") == 841
    assert one(f"SELECT count(*) FROM nvd n WHERE n.cve_id IN ({ids}) AND {GH_COMMIT}") == 841


def test_embedded_cpe_share(one):
    assert within(one(f"SELECT count(*) FROM nvd n WHERE {WINDOW} AND {EMBEDDED}"), 2883, 0.02)
    assert abs(one(f"SELECT count(*) FROM nvd n WHERE {WINDOW} AND {EMBEDDED} AND {GH_COMMIT}") - 13) <= 3


def test_every_nvd_cve_has_cvelist_record(one):
    cutoff = one("SELECT value FROM snapshot WHERE key='cvelist_synced_through'")
    orphans = one(f"""SELECT count(*) FROM nvd n LEFT JOIN cve c ON c.id=n.cve_id
                      WHERE c.id IS NULL AND n.published < '{cutoff[:19]}'""")
    assert orphans < 5, orphans


def test_ghsa_loaded_and_joins_to_cve(one):
    assert one("SELECT count(*) FROM ghsa") > 300000
    assert one("SELECT count(*) FROM ghsa WHERE reviewed=1") > 30000
    assert (
        one("""SELECT count(DISTINCT a.alias) FROM ghsa_alias a JOIN cve c ON c.id=a.alias
                  WHERE a.alias LIKE 'CVE-%'""")
        > 250000
    )
