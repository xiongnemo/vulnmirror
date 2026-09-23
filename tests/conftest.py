"""Synthetic fixtures: a tiny home directory with every raw source, no network needed.

All identifiers use the year 2099 and vendor "examplevendor" so they can never be
mistaken for real records.
"""

import gzip
import io
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from vulnmirror.config import Paths

EXPORT = "2099-01-02_all_CVEs_at_midnight.zip.zip"
CUTOFF = "2099-01-02T00:00:00Z"


def cvelist_record(cid, state="PUBLISHED", product="widget", updated="2099-01-01T10:00:00.000Z", refs=None):
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {
            "cveId": cid,
            "state": state,
            "assignerShortName": "examplecna",
            "dateReserved": "2098-12-01T00:00:00.000Z",
            "datePublished": "2099-01-01T09:00:00.000Z",
            "dateUpdated": updated,
        },
        "containers": {
            "cna": {
                "title": f"Synthetic record {cid}",
                "descriptions": [{"lang": "en", "value": f"Synthetic test record {cid}."}],
                "affected": [
                    {
                        "vendor": "examplevendor",
                        "product": product,
                        "defaultStatus": "unaffected",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
                "references": refs
                if refs is not None
                else [
                    {
                        "url": "https://github.com/example/widget/commit/0123456789abcdef0123456789abcdef01234567",
                        "tags": ["patch"],
                    }
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-20", "description": "CWE-20", "lang": "en"}]}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 5.0,
                            "baseSeverity": "MEDIUM",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        }
                    }
                ],
            },
            "adp": [
                {
                    "providerMetadata": {"shortName": "EXAMPLE-ADP"},
                    "references": [{"url": "https://example.org/advisory", "tags": ["third-party-advisory"]}],
                }
            ],
        },
    }


def nvd_record(cid, status="Analyzed", published="2099-01-01T09:30:00.000", cpes=None, refs=None):
    return {
        "id": cid,
        "vulnStatus": status,
        "published": published,
        "lastModified": published,
        "descriptions": [{"lang": "en", "value": f"Synthetic NVD record {cid}."}],
        "references": refs
        if refs is not None
        else [{"url": "https://example.org/nvd-ref", "tags": ["Vendor Advisory"]}],
        "weaknesses": [
            {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-20"}]}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 5.0,
                        "baseSeverity": "MEDIUM",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"vulnerable": v, "criteria": c}
                            for c, v in (
                                cpes
                                or [
                                    ("cpe:2.3:o:examplevendor:widget_firmware:1.0:*:*:*:*:*:*:*", True),
                                    ("cpe:2.3:h:examplevendor:widget:-:*:*:*:*:*:*:*", False),
                                ]
                            )
                        ]
                    }
                ]
            }
        ],
    }


def ghsa_record(gid, cid=None, reviewed=True, published="2099-01-01T08:00:00Z", fixed="1.2.3", summary="Synthetic"):
    rec = {
        "schema_version": "1.4.0",
        "id": gid,
        "modified": published,
        "published": published,
        "aliases": [cid] if cid else [],
        "summary": summary,
        "details": "Synthetic advisory.",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "examplepkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
        "references": [{"type": "WEB", "url": "https://github.com/example/examplepkg/pull/1"}],
        "database_specific": {
            "cwe_ids": ["CWE-79"],
            "severity": "MODERATE",
            "github_reviewed": reviewed,
            "github_reviewed_at": published if reviewed else None,
            "nvd_published_at": None,
        },
    }
    return rec


def write_feed(path: Path, recs: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump({"vulnerabilities": [{"cve": r} for r in recs]}, f)


def write_cvelist_export(path: Path, recs: list) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        for r in recs:
            cid = r["cveMetadata"]["cveId"]
            _, year, num = cid.split("-")
            z.writestr(f"cves/{year}/{int(num) // 1000}xxx/{cid}.json", json.dumps(r))
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr("cves.zip", inner.getvalue())


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def advisory_path(rec: dict) -> str:
    tier = "github-reviewed" if rec["database_specific"]["github_reviewed"] else "unreviewed"
    pub = rec["published"]
    return f"advisories/{tier}/{pub[:4]}/{pub[5:7]}/{rec['id']}/{rec['id']}.json"


def write_advisory(upstream: Path, rec: dict) -> None:
    p = upstream / advisory_path(rec)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec, indent=1))


@pytest.fixture
def upstream(tmp_path) -> Path:
    """A local stand-in for github/advisory-database with one reviewed advisory."""
    up = tmp_path / "upstream"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    write_advisory(up, ghsa_record("GHSA-aaaa-bbbb-cccc", cid="CVE-2099-0001"))
    git(up, "add", "-A")
    git(up, "commit", "-q", "-m", "initial")
    return up


@pytest.fixture
def home(tmp_path, upstream) -> Paths:
    """A home directory holding every raw source, ready for `build`."""
    paths = Paths(tmp_path / "home")
    write_cvelist_export(
        paths.cvelist_dir / EXPORT,
        [
            cvelist_record("CVE-2099-0001"),
            cvelist_record("CVE-2099-0002", state="REJECTED"),
        ],
    )
    write_feed(paths.nvd_dir / "nvdcve-2.0-2099.json.gz", [nvd_record("CVE-2099-0001"), nvd_record("CVE-2099-0003")])
    # The modified feed carries a newer copy of CVE-2099-0001; it must win over the yearly feed.
    write_feed(paths.nvd_dir / "nvdcve-2.0-modified.json.gz", [nvd_record("CVE-2099-0001", status="Modified")])
    write_feed(paths.nvd_dir / "nvdcve-2.0-recent.json.gz", [])
    paths.kev_file.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_file.write_text(
        json.dumps(
            {
                "catalogVersion": "2099.01.01",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2099-0001",
                        "vendorProject": "examplevendor",
                        "product": "widget",
                        "vulnerabilityName": "Synthetic",
                        "dateAdded": "2099-01-01",
                        "dueDate": "2099-01-22",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ],
            }
        )
    )
    paths.ghsa_repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{upstream}", str(paths.ghsa_repo)], check=True)
    paths.manifest.write_text(
        json.dumps(
            {
                "cvelistV5": {"release_tag": "cve_2099-01-02_0000Z", "asset": EXPORT},
                "kev": {"catalogVersion": "2099.01.01"},
                "nvd": [
                    {"feed": "2099", "lastModifiedDate": "2099-01-02T00:00:00-04:00"},
                    {"feed": "modified", "lastModifiedDate": "2099-01-02T00:00:00-04:00"},
                ],
                "fetched_at": "2099-01-02T01:00:00+00:00",
            }
        )
    )
    return paths
