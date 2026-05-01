"""Privacy-aware logging setup for CleanNet."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import os
import time
from typing import Any, Callable, Mapping


class DashboardLogHandler(logging.Handler):
    def __init__(self, maxlen: int = 200):
        super().__init__()
        self._entries = deque(maxlen=maxlen)
        self._counter = 0

    def emit(self, record: logging.LogRecord) -> None:
        self._counter += 1
        self._entries.append((self._counter, self.format(record)))

    def get_entries_after(self, after_id: int) -> list[tuple[int, str]]:
        return [(i, msg) for i, msg in self._entries if i > after_id]


@dataclass
class LoggingSetup:
    logger: logging.Logger
    dashboard_handler: DashboardLogHandler
    log_file: str
    hash_host: Callable[[Any], str]


def hash_host(host: Any, log_real_hosts: bool = False) -> str:
    if not host:
        return "(none)"
    if log_real_hosts:
        return str(host)
    digest = hashlib.sha256(str(host).encode("utf-8", "ignore")).hexdigest()
    return f"<h#{digest[:8]}>"


def _purge_rotated_logs(app_dir: str, retention_days: int, now_func: Callable[[], float] = time.time) -> None:
    try:
        cutoff = now_func() - retention_days * 86400
        for name in os.listdir(app_dir):
            if name.startswith("bypass.log."):
                path = os.path.join(app_dir, name)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except OSError:
                    pass
    except OSError:
        pass


def _reset_logger_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass


def setup_logging(
    app_dir: str,
    *,
    logger_name: str = "dpi-bypass",
    env: Mapping[str, str] | None = None,
    dashboard_maxlen: int = 200,
    retention_days: int = 2,
    disk_max_bytes: int = 256 * 1024,
    backup_count: int = 1,
    reset_handlers: bool = False,
) -> LoggingSetup:
    """Set up disk logging, dashboard logging, and host privacy hashing."""
    env = os.environ if env is None else env
    log_file = os.path.join(app_dir, "bypass.log")
    disk_level_name = env.get("DPI_BYPASS_LOG_LEVEL", "WARNING").upper()
    disk_level = getattr(logging, disk_level_name, logging.WARNING)
    no_disk_log = env.get("DPI_BYPASS_NO_DISK_LOG") == "1"
    log_real_hosts = env.get("DPI_BYPASS_LOG_HOSTS") == "1"

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    if reset_handlers:
        _reset_logger_handlers(logger)

    if not no_disk_log:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=disk_max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(disk_level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(file_handler)
        _purge_rotated_logs(app_dir, retention_days)

    dashboard_handler = DashboardLogHandler(maxlen=dashboard_maxlen)
    dashboard_handler.setLevel(logging.DEBUG)
    dashboard_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(dashboard_handler)

    return LoggingSetup(
        logger=logger,
        dashboard_handler=dashboard_handler,
        log_file=log_file,
        hash_host=lambda host: hash_host(host, log_real_hosts=log_real_hosts),
    )
