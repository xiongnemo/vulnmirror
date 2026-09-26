"""Network helpers: resumable downloads via curl, small JSON documents via urllib."""

import json
import logging
import os
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import certifi

log = logging.getLogger("vulnmirror.net")


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
    offset = part.stat().st_size if resume and part.exists() else 0
    if offset:
        cmd[1:1] = ["-C", "-"]
    log.debug("GET %s -> %s%s", url, dest, f" (resuming at {offset:,} bytes)" if offset else "")
    t0 = time.monotonic()
    try:
        subprocess.run([*cmd, url], check=True)
    except subprocess.CalledProcessError as e:
        log.debug("GET %s failed: curl exit %s after %.1fs", url, e.returncode, time.monotonic() - t0)
        raise
    size = part.stat().st_size
    part.replace(dest)
    log.debug("GET %s done: %s bytes in %.1fs", url, f"{size:,}", time.monotonic() - t0)


def get_text(url: str, retries: int = 5) -> str:
    curl = require("curl")
    log.debug("GET %s", url)
    t0 = time.monotonic()
    try:
        out = subprocess.run(
            [curl, "-sS", "-L", "--fail", "--retry", str(retries), "--retry-all-errors", url],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        log.debug("GET %s failed: curl exit %s (%s)", url, e.returncode, (e.stderr or "").strip())
        raise
    log.debug("GET %s -> %s chars in %.2fs", url, f"{len(out.stdout):,}", time.monotonic() - t0)
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
        attempt = f" (attempt {i + 1}/{tries})" if i else ""
        log.debug("GET %s%s", url, attempt)
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=60, context=_CTX) as r:
                body = r.read()
                log.debug("GET %s -> %s, %s bytes in %.2fs", url, r.status, f"{len(body):,}", time.monotonic() - t0)
                return json.loads(body)
        except urllib.error.HTTPError as e:
            log.debug("GET %s -> HTTP %s in %.2fs", url, e.code, time.monotonic() - t0)
            if e.code == 404:
                raise NotFound(url) from e
            if 400 <= e.code < 500 and e.code != 429:
                raise
            if i == tries - 1:
                raise
        except Exception as e:
            log.debug("GET %s failed: %s", url, e)
            if i == tries - 1:
                raise
        log.debug("retrying %s in %ss", url, 2 * (i + 1))
        time.sleep(2 * (i + 1))
