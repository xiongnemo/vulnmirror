"""GitHub Advisory Database mirror (github/advisory-database, OSV format, CC-BY-4.0).

The mirror is a shallow git clone. The database records the commit it was built from
(snapshot.ghsa_commit); an incremental sync fetches the new head and applies
`git diff --no-renames <synced> <new>` file by file. The synced commit is pinned under
refs/vulnmirror/synced so a shallow repository keeps it for the next diff.
"""

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

from vulnmirror import net
from vulnmirror.records import ref_kind

REMOTE = "https://github.com/github/advisory-database.git"
RAW_BASE = "https://raw.githubusercontent.com/github/advisory-database/main/"
PIN = "refs/vulnmirror/synced"
TABLES = ("ghsa", "ghsa_alias", "ghsa_affected", "ghsa_reference", "ghsa_cwe")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [net.require("git"), "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def clone(repo: Path, remote: str = REMOTE) -> None:
    """Shallow-clone into a temporary directory first, so an interrupted clone leaves nothing half-made."""
    partial = repo.with_name(repo.name + ".partial")
    if partial.exists():
        shutil.rmtree(partial)
    partial.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([net.require("git"), "clone", "--depth", "1", "--single-branch", remote, str(partial)], check=True)
    partial.rename(repo)


def repo_path_for(advisory: dict) -> str:
    """Path of an advisory inside github/advisory-database.

    Layout: advisories/{github-reviewed|unreviewed}/<published YYYY>/<MM>/<id>/<id>.json
    (checked against a 3,000-file sample of the repository on 2026-09-24: no exceptions).
    """
    reviewed = bool((advisory.get("database_specific") or {}).get("github_reviewed"))
    pub, gid = advisory["published"], advisory["id"]
    tier = "github-reviewed" if reviewed else "unreviewed"
    return f"advisories/{tier}/{pub[:4]}/{pub[5:7]}/{gid}/{gid}.json"


def _first_event(ranges, key):
    for r in ranges or []:
        for e in r.get("events", []):
            if key in e:
                return e[key]
    return None


def insert_advisory(db: sqlite3.Connection, d: dict, path: str) -> str:
    gid = d["id"]
    ds = d.get("database_specific") or {}
    sev = d.get("severity") or []
    db.execute(
        "INSERT OR REPLACE INTO ghsa(id, reviewed, published, modified, withdrawn, summary, details, severity,"
        " cvss_vector, github_reviewed_at, nvd_published_at, path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            gid,
            1 if ds.get("github_reviewed") else 0,
            d.get("published"),
            d.get("modified"),
            d.get("withdrawn"),
            d.get("summary"),
            d.get("details"),
            ds.get("severity"),
            sev[0].get("score") if sev else None,
            ds.get("github_reviewed_at"),
            ds.get("nvd_published_at"),
            path,
        ),
    )
    for a in d.get("aliases") or []:
        db.execute("INSERT INTO ghsa_alias(ghsa_id, alias) VALUES (?,?)", (gid, a))
    for a in d.get("affected") or []:
        pkg = a.get("package") or {}
        ranges = a.get("ranges")
        db.execute(
            "INSERT INTO ghsa_affected(ghsa_id, ecosystem, package, purl, introduced, fixed, last_affected,"
            " ranges, versions) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                gid,
                pkg.get("ecosystem"),
                pkg.get("name"),
                pkg.get("purl"),
                _first_event(ranges, "introduced"),
                _first_event(ranges, "fixed"),
                _first_event(ranges, "last_affected"),
                json.dumps(ranges) if ranges else None,
                json.dumps(a.get("versions")) if a.get("versions") else None,
            ),
        )
    for r in d.get("references") or []:
        url = r.get("url", "")
        db.execute(
            "INSERT INTO ghsa_reference(ghsa_id, type, url, kind) VALUES (?,?,?,?)",
            (gid, r.get("type"), url, ref_kind(url)),
        )
    for c in ds.get("cwe_ids") or []:
        db.execute("INSERT INTO ghsa_cwe(ghsa_id, cwe_id) VALUES (?,?)", (gid, c))
    return gid


def delete_advisory(db: sqlite3.Connection, gid: str) -> None:
    db.execute("DELETE FROM ghsa WHERE id=?", (gid,))
    for t in TABLES[1:]:
        db.execute(f"DELETE FROM {t} WHERE ghsa_id=?", (gid,))


def delete_all(db: sqlite3.Connection) -> None:
    for t in TABLES:
        db.execute(f"DELETE FROM {t}")


def load_all(db: sqlite3.Connection, repo: Path, commit_every: int = 100000, log=print):
    """Load every advisory in the working tree; returns (count, commit).

    commit_every=0 keeps everything in the caller's transaction (the incremental update
    clears the GHSA tables first and must not expose a half-loaded state).
    """
    commit = git(repo, "rev-parse", "HEAD").strip()
    n = 0
    for p in sorted((repo / "advisories").rglob("GHSA-*.json")):
        insert_advisory(db, json.loads(p.read_text(encoding="utf-8")), str(p.relative_to(repo)))
        n += 1
        if commit_every and n % commit_every == 0:
            db.commit()
            log(f"  ghsa: {n} advisories")
    if commit_every:
        db.commit()
    git(repo, "update-ref", PIN, commit)
    return n, commit


def has_commit(repo: Path, sha: str) -> bool:
    r = subprocess.run(
        [net.require("git"), "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
    )
    return r.returncode == 0


def sync(db: sqlite3.Connection, repo: Path, synced: str):
    """Apply advisories changed between `synced` and the remote head; returns (upserted, deleted, new_commit)."""
    git(repo, "fetch", "--depth", "1", "origin", "main")
    new = git(repo, "rev-parse", "FETCH_HEAD").strip()
    if new == synced:
        return 0, 0, new
    diff = git(repo, "diff", "--no-renames", "--name-status", synced, new, "--", "advisories")
    up = de = 0
    for line in diff.splitlines():
        status, path = line.split("\t", 1)
        if not path.endswith(".json") or "/GHSA-" not in path:
            continue
        gid = Path(path).stem
        delete_advisory(db, gid)
        if status == "D":
            de += 1
            continue
        insert_advisory(db, json.loads(git(repo, "show", f"{new}:{path}")), path)
        up += 1
    return up, de, new


def finish_sync(repo: Path, new: str) -> None:
    """Call after the database transaction commits: move the working tree and the pin."""
    git(repo, "reset", "--hard", "-q", new)
    git(repo, "update-ref", PIN, new)
