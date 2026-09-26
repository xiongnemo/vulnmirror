"""Diagnostic logging, off unless asked for with -v.

  -v     progress of each step (what update is fetching, which feeds, how many records)
  -vv    every network request and its response, and every git command
  -vvv   every SQL statement executed on a writable database connection

Everything goes to stderr under the "vulnmirror" logger, so stdout stays clean for
query output. The normal, unconditional messages of the CLI are unaffected.
"""

import logging
import sqlite3
import sys

TRACE = 5
logging.addLevelName(TRACE, "TRACE")

LEVELS = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}
SQL_MAX_CHARS = 300

root = logging.getLogger("vulnmirror")
sql_log = logging.getLogger("vulnmirror.sql")


def setup(verbosity: int) -> None:
    """Configure the vulnmirror logger for a verbosity count (0 = quiet)."""
    level = LEVELS.get(verbosity, TRACE)
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    if verbosity <= 0:
        return
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(asctime)s.%(msecs)03d %(levelname)-5s %(name)s: %(message)s" if verbosity >= 2 else "%(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    root.addHandler(handler)
    root.propagate = False


def _trace_statement(statement: str) -> None:
    text = " ".join(statement.split())
    if len(text) > SQL_MAX_CHARS:
        text = text[:SQL_MAX_CHARS] + f"... ({len(text)} chars)"
    sql_log.log(TRACE, text)


def trace_sql(db: sqlite3.Connection) -> sqlite3.Connection:
    """Log every statement run on db at TRACE level (-vvv); a no-op otherwise."""
    if sql_log.isEnabledFor(TRACE):
        db.set_trace_callback(_trace_statement)
    return db
