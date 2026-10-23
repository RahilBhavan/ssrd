"""Hourly counters appended to data/metrics.jsonl."""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from . import config


class Counters:
    def __init__(self, component: str, every: int = 3600):
        self.component = component
        self.every = every
        self.counts: Counter = Counter()
        self.started = time.time()
        self.path = Path(config.load()["paths"]["data_dir"]) / "metrics.jsonl"

    def inc(self, key: str, n: int = 1) -> None:
        self.counts[key] += n
        if time.time() - self.started >= self.every:
            self.flush()

    def flush(self) -> None:
        rec = {
            "component": self.component,
            "start": int(self.started),
            "end": int(time.time()),
            **self.counts,
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        self.counts.clear()
        self.started = time.time()
