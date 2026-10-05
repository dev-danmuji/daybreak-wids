"""Assemble storage, logging, notifiers and the pipeline from configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TextIO

from .alerts.base import Notifier, build_notifiers
from .alerts.jsonl import rotating_logger
from .alerts.manager import AlertManager
from .baseline.engine import BaselineStore
from .config import Config
from .pipeline import Pipeline
from .storage import Database


@dataclass
class Runtime:
    config: Config
    db: Database | None
    pipeline: Pipeline
    alerts: AlertManager
    baseline: BaselineStore | None
    dry_run: bool

    def close(self) -> None:
        self.pipeline.flush()
        self.alerts.close()
        if self.db is not None:
            self.db.close()


def build_runtime(config: Config, *, dry_run: bool = False, console_stream: TextIO | None = None,
                  extra_notifiers: list[Notifier] | None = None, use_baseline: bool = True,
                  db: Database | None = None) -> Runtime:
    """``dry_run``: nothing is written (no database, logs or desktop notifications)."""
    if db is None and not dry_run:
        db = Database(config.database_path)
    lc = config.logging
    log_dir = config.log_dir
    human_log = None
    if not dry_run:
        human_log = rotating_logger(f"daybreak.human.{log_dir}", log_dir / lc.human_log,
                                    max_bytes=lc.max_bytes, backup_count=lc.backup_count)
    notifier_cfgs = [n for n in config.alerts.notifiers
                     if not dry_run or n.type == "console"]
    context: dict[str, dict[str, Any]] = {
        "jsonl": {"path": log_dir / lc.jsonl_log, "max_bytes": lc.max_bytes, "backup_count": lc.backup_count},
        "console": {"stream": console_stream} if console_stream is not None else {},
    }
    notifiers = build_notifiers(notifier_cfgs, **context) + list(extra_notifiers or [])
    manager = AlertManager(notifiers, db=db, cooldown=config.alerts.cooldown,
                           escalation_delta=config.alerts.escalation_delta,
                           rate_limit_per_minute=config.alerts.rate_limit_per_minute,
                           human_log=human_log, dry_run=dry_run)
    store = BaselineStore.from_db(db) if (use_baseline and db is not None) else None
    pipeline = Pipeline(config, db=db, sink=manager.submit, baseline=store or None)
    return Runtime(config, db, pipeline, manager, store or None, dry_run)
