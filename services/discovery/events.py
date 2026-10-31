"""Sandbox output protocol: progress events on stderr, one result line on stdout."""

import json
import sys

from routes_shared.events import emit  # noqa: F401  (re-exported for the sandbox code)

RESULT_PREFIX = "ROUTES_RESULT "


def emit_result(data: dict) -> None:
    sys.stdout.write(RESULT_PREFIX + json.dumps(data, separators=(",", ":")) + "\n")
    sys.stdout.flush()
