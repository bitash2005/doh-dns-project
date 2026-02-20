import json
import time
from datetime import datetime


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def log_event(path: str, event: dict):
    """
    event را به صورت JSON line داخل فایل می‌نویسد.
    هر خط = یک request
    """
    event = dict(event)
    event["ts"] = now_iso()

    line = json.dumps(event, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class Timer:
    def __init__(self):
        self.t0 = time.perf_counter()

    def ms(self) -> int:
        return int((time.perf_counter() - self.t0) * 1000)
