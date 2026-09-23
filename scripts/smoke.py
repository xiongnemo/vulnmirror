"""Smoke test for a built vulnmirror distribution (run against the wheel and the sdist).

Checks what a packaging mistake would break: the import, the bundled SQL files and the CLI entry.
"""

import subprocess
import sys
import tempfile

from vulnmirror import cli, records, serve

assert "CREATE TABLE cve" in records.sql_text("schema.sql"), "schema.sql missing from the distribution"
assert "ANALYZE" in records.sql_text("indexes.sql"), "indexes.sql missing from the distribution"
assert "/v1/cve/{id}" in serve.openapi()["paths"], "serve module incomplete"

out = subprocess.run([sys.executable, "-m", "vulnmirror", "--version"], check=True, capture_output=True, text=True)
assert out.stdout.startswith("vulnmirror "), out.stdout

with tempfile.TemporaryDirectory() as home:
    assert cli.main(["--home", home, "config", "show"]) == 0

print("smoke test passed:", out.stdout.strip())
