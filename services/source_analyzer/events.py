import json
import sys

from routes_shared.contracts import EVENT_PREFIX

RESULT_PREFIX = "ROUTES_RESULT "


def emit(stage: str, message: str = "") -> None:
    sys.stderr.write(EVENT_PREFIX + json.dumps({"stage": stage, "message": message[:300]}) + "\n")
    sys.stderr.flush()


def emit_result(data: dict) -> None:
    sys.stdout.write(RESULT_PREFIX + json.dumps(data, separators=(",", ":")) + "\n")
    sys.stdout.flush()
