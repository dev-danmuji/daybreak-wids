"""JSONL notifier: one JSON object per alert, size-rotated."""

from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any

from ..models import Alert
from .base import Notifier, register_notifier


def rotating_logger(name: str, path: Path, *, max_bytes: int, backup_count: int) -> logging.Logger:
    """A dedicated logger writing raw lines to ``path`` with size-based rotation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backup_count,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


@register_notifier("jsonl")
class JsonlNotifier(Notifier):
    rate_limited = False

    def __init__(self, min_severity: Any = "INFO", path: str | Path | None = None,
                 max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5, **options: Any):
        super().__init__(min_severity, **options)
        if path is None:
            raise ValueError("jsonl notifier needs a path")
        self.path = Path(path)
        self.logger = rotating_logger(f"daybreak.jsonl.{self.path}", self.path,
                                      max_bytes=max_bytes, backup_count=backup_count)

    def notify(self, alert: Alert, *, note: str | None = None) -> None:
        record = alert.to_dict()
        if note:
            record["note"] = note
        self.logger.info(json.dumps(record, ensure_ascii=False, sort_keys=False, default=str))

    def close(self) -> None:
        for h in list(self.logger.handlers):
            h.close()
            self.logger.removeHandler(h)
