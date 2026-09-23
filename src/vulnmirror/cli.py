"""vulnmirror command line."""

import argparse
import csv
import json
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from vulnmirror import build, cases, config, fetch, ghsa, query, serve, update
from vulnmirror.config import Paths


def _version() -> str:
    try:
        return version("vulnmirror")
    except PackageNotFoundError:
        return "unknown"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def emit(cols: list, rows: list, fmt: str, output: str | None) -> None:
    out = open(output, "w", newline="", encoding="utf-8") if output else sys.stdout
    try:
        if fmt == "json":
            json.dump([dict(zip(cols, r, strict=True)) for r in rows], out, indent=1)
            out.write("\n")
        elif fmt == "jsonl":
            for r in rows:
                out.write(json.dumps(dict(zip(cols, r, strict=True))) + "\n")
        elif fmt == "csv":
            w = csv.writer(out)
            w.writerow(cols)
            w.writerows(rows)
        else:
            out.write("\t".join(cols) + "\n")
            for r in rows:
                out.write("\t".join("" if v is None else str(v) for v in r) + "\n")
    finally:
        if output:
            out.close()
            _log(f"{len(rows)} rows -> {output}")


def _retrying(fn, retry_forever: bool, interval: int):
    while True:
        try:
            return fn()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if not retry_forever:
                raise
            _log(f"failed ({e}); retrying in {interval}s (downloads resume where they stopped)")
            time.sleep(interval)


# ---------------------------------------------------------------- commands
def cmd_config(args, paths: Paths, source: str) -> int:
    if args.action == "set-home":
        target = config.expand_path(args.path)
        cfg = config.read_config()
        cfg["home"] = str(target)
        written = config.write_config(cfg)
        print(f"home = {target}  (written to {written})")
        return 0
    print(f"home         {paths.home}")
    print(f"resolved by  {source}")
    print(f"config file  {config.config_path()}{'' if config.config_path().exists() else '  (absent)'}")
    print(f"database     {paths.db}{'' if paths.db.exists() else '  (not built yet)'}")
    return 0


def cmd_fetch(args, paths: Paths) -> int:
    only = tuple(args.only.split(","))
    _retrying(lambda: fetch.fetch(paths, only=only, jobs=args.jobs, log=_log), args.retry_forever, args.retry_interval)
    _log("fetch done")
    return 0


def cmd_build(args, paths: Paths) -> int:
    build.build(paths, log=_log)
    return 0


def cmd_update(args, paths: Paths) -> int:
    failed = False
    for name, ok, msg in update.update(paths, only=tuple(args.only.split(","))):
        print(f"{name}: {msg}")
        failed |= not ok
    return 1 if failed else 0


def cmd_init(args, paths: Paths) -> int:
    retry = not args.no_retry
    _retrying(lambda: fetch.fetch(paths, jobs=args.jobs, log=_log), retry, args.retry_interval)
    if not paths.ghsa_repo.exists():
        _log("cloning github/advisory-database (shallow)...")
        _retrying(lambda: ghsa.clone(paths.ghsa_repo), retry, args.retry_interval)
    build.build(paths, log=_log)
    rc = cmd_update(argparse.Namespace(only=",".join(update.SOURCES)), paths)
    cmd_status(argparse.Namespace(json=False), paths)
    return rc


def cmd_status(args, paths: Paths) -> int:
    with query.connect(paths.db) as db:
        st = query.status(db)
    if args.json:
        print(json.dumps(st, indent=1))
        return 0
    print(f"home                     {paths.home}")
    for key, m in st["markers"].items():
        flag = "STALE: run `vulnmirror update`" if m["stale"] else "ok"
        print(f"{key:24} {m['value'] or '-':32} age {m['age_hours']}h  {flag}")
    for key, v in st["info"].items():
        print(f"{key:24} {v or '-'}")
    for t, n in st["rows"].items():
        print(f"rows {t:19} {n:>10,}")
    return 0


def cmd_get(args, paths: Paths) -> int:
    refs = cases.read_refs(args.refs, args.file, stdin=sys.stdin)
    if not refs:
        _log("nothing to fetch: give identifiers or URLs, or --file LIST")
        return 2
    wanted, bad = [], 0
    for ref in refs:
        try:
            wanted += cases.parse_ref(ref, args.type)
        except ValueError as e:
            _log(f"skip: {e}")
            bad += 1
    results = cases.get_cases(paths, wanted, force=args.force, jobs=args.jobs)
    for r in results:
        detail = r.get("path") or r.get("message") or ""
        print(f"{r['status']:10} {r['kind']:4} {r['id']:22} {detail}")
    sys.stdout.flush()  # keep the status lines ahead of the stderr log below
    if args.ingest:
        _log(f"ingested {cases.ingest(paths, results)} records into {paths.db}")
    if args.print:
        for r in results:
            if r.get("path"):
                with open(r["path"], encoding="utf-8") as f:
                    sys.stdout.write(f.read())
    problems = bad + sum(r["status"] in ("not_found", "error") for r in results)
    return 1 if problems else 0


def cmd_sql(args, paths: Paths) -> int:
    with query.connect(paths.db) as db:
        cols, rows = query.run_sql(db, args.statement)
    emit(cols, rows, args.format, args.output)
    return 0


def cmd_filter(args, paths: Paths) -> int:
    sql, params = query.filter_sql(
        args.vendor, args.product_like, args.cpe_part, args.cpe_scope, args.date_from, args.date_to, args.state
    )
    with query.connect(paths.db) as db:
        cur = db.execute(sql, params)
        cols = [d[0] for d in cur.description]
        rows = [tuple(r) for r in cur.fetchall()]
    if args.count:
        print(len(rows))
        return 0
    emit(cols, rows, args.format, args.output)
    return 0


def cmd_serve(args, paths: Paths) -> int:
    token = None
    if args.token_file:
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError(f"{args.token_file} is empty")
    elif os.environ.get("VULNMIRROR_TOKEN", "").strip():
        token = os.environ["VULNMIRROR_TOKEN"].strip()
    if args.max_limit < 1 or args.timeout <= 0:
        raise ValueError("--max-limit must be at least 1 and --timeout positive")
    if not paths.db.exists():
        raise FileNotFoundError(f"no database at {paths.db}; run `vulnmirror build` first")
    settings = serve.Settings(
        paths=paths, token=token, cors_origin=args.cors_origin, max_limit=args.max_limit, timeout_s=args.timeout
    )
    server = serve.make_server(settings, args.host, args.port)
    host, port = server.server_address[:2]
    if not serve.is_loopback(args.host) and not token:
        _log("warning: serving on a non-loopback address without a token; anyone who can reach it can query it")
    _log(f"serving {paths.db} read-only on http://{host}:{port}" + ("  (bearer token required)" if token else ""))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("stopped")
    finally:
        server.server_close()
    return 0


# ---------------------------------------------------------------- parser
def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vulnmirror", description="Local mirror of CVE, NVD, KEV and GHSA metadata.")
    ap.add_argument("--version", action="version", version=f"vulnmirror {_version()}")
    ap.add_argument("--home", help="data directory (overrides $VULNMIRROR_HOME and the config file)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def fmt_opts(p):
        p.add_argument("--format", choices=["tsv", "csv", "json", "jsonl"], default="tsv")
        p.add_argument("-o", "--output", help="write to FILE instead of stdout")

    p = sub.add_parser("init", help="first-time setup: fetch, clone GHSA, build, update")
    p.add_argument("--jobs", type=int, default=6)
    p.add_argument("--no-retry", action="store_true", help="stop at the first network failure")
    p.add_argument("--retry-interval", type=int, default=60)

    p = sub.add_parser("fetch", help="download raw sources (resumable; skips files already current)")
    p.add_argument("--only", default="cvelist,nvd,kev")
    p.add_argument("--jobs", type=int, default=6)
    p.add_argument("--retry-forever", action="store_true", help="keep retrying through network outages")
    p.add_argument("--retry-interval", type=int, default=60)

    sub.add_parser("build", help="rebuild the database from raw sources")

    p = sub.add_parser("update", help="incremental update in place")
    p.add_argument("--only", default=",".join(update.SOURCES))

    p = sub.add_parser("status", help="sync markers, their age, row counts")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("get", help="download individual records by identifier or URL")
    p.add_argument("refs", nargs="*", help="CVE / GHSA identifiers or URLs")
    p.add_argument("-f", "--file", action="append", help="file with one reference per line ('-' = stdin); repeatable")
    p.add_argument("-t", "--type", choices=cases.KINDS, help="record type; default: inferred (a CVE gets cve + nvd)")
    p.add_argument("--force", action="store_true", help="download again even if the record is already stored")
    p.add_argument("--ingest", action="store_true", help="also upsert the records into the database")
    p.add_argument("--print", action="store_true", help="print the stored JSON to stdout")
    p.add_argument("--jobs", type=int, default=8)

    p = sub.add_parser("sql", help="run a read-only SQL statement")
    p.add_argument("statement")
    fmt_opts(p)

    p = sub.add_parser("filter", help="select CVEs by vendor / product / NVD CPE part / date window")
    p.add_argument("--vendor", action="append", help="case-insensitive substring; repeatable")
    p.add_argument("--product-like", help="SQL LIKE pattern on the product name")
    p.add_argument("--cpe-part", choices=["a", "o", "h"])
    p.add_argument(
        "--cpe-scope",
        choices=["vulnerable", "any"],
        default="vulnerable",
        help="'any' also matches non-vulnerable platform CPEs (needed for hardware)",
    )
    p.add_argument("--from", dest="date_from")
    p.add_argument("--to", dest="date_to")
    p.add_argument("--state", default="PUBLISHED")
    p.add_argument("--count", action="store_true")
    fmt_opts(p)

    p = sub.add_parser("serve", help="serve the mirror read-only as a JSON API over HTTP")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default loopback only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument(
        "--token-file",
        help="require 'Authorization: Bearer <token>'; the token is read from FILE (or set $VULNMIRROR_TOKEN)",
    )
    p.add_argument("--cors-origin", help="value for Access-Control-Allow-Origin, e.g. '*' or https://example.org")
    p.add_argument("--max-limit", type=int, default=1000, help="largest page size a search may ask for")
    p.add_argument("--timeout", type=float, default=30.0, help="per-request query time limit, seconds")

    p = sub.add_parser("config", help="show or set the data directory")
    csub = p.add_subparsers(dest="action", required=True)
    csub.add_parser("show")
    sh = csub.add_parser("set-home")
    sh.add_argument("path")
    return ap


COMMANDS = {
    "init": cmd_init,
    "fetch": cmd_fetch,
    "build": cmd_build,
    "update": cmd_update,
    "status": cmd_status,
    "get": cmd_get,
    "sql": cmd_sql,
    "filter": cmd_filter,
    "serve": cmd_serve,
}


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    home, source = config.resolve_home(args.home)
    paths = Paths(home)
    try:
        if args.cmd == "config":
            return cmd_config(args, paths, source)
        return COMMANDS[args.cmd](args, paths)
    except (FileNotFoundError, ValueError) as e:
        _log(f"vulnmirror: {e}")
        return 2
    except KeyboardInterrupt:
        _log("interrupted; downloads resume on the next run")
        return 130


if __name__ == "__main__":
    sys.exit(main())
