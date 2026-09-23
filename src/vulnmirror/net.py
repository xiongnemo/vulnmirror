"""Network helpers: resumable downloads via curl, small JSON documents via urllib."""

import json
import os
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import certifi


class MissingTool(RuntimeError):
    pass


def require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise MissingTool(f"'{tool}' is required but was not found on PATH")
    return path


def download(url: str, dest: Path, resume: bool = True, retries: int = 5) -> None:
    """Download url to dest through dest.part; a later call resumes a partial download."""
    curl = require("curl")
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    cmd = [
        curl,
        "-sS",
        "-L",
        "--fail",
        "--retry",
        str(retries),
        "--retry-delay",
        "10",
        "--retry-all-errors",
        "--connect-timeout",
        "30",
        "-o",
        str(part),
    ]
    if resume and part.exists():
        cmd[1:1] = ["-C", "-"]
    subprocess.run([*cmd, url], check=True)
    part.replace(dest)


def get_text(url: str, retries: int = 5) -> str:
    curl = require("curl")
    out = subprocess.run(
        [curl, "-sS", "-L", "--fail", "--retry", str(retries), "--retry-all-errors", url],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout


def _ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or certifi.where())


_CTX = _ssl_context()


class NotFound(LookupError):
    pass


def get_json(url: str, tries: int = 5, headers: dict | None = None):
    """GET a JSON document. 404 raises NotFound at once; other 4xx fail at once; 429/5xx/network retry."""
    req = urllib.request.Request(url, headers={"User-Agent": "vulnmirror", **(headers or {})})
    for i in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=60, context=_CTX) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(url) from e
            if 400 <= e.code < 500 and e.code != 429:
                raise
            if i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))
