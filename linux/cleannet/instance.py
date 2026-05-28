"""Single-instance guard for CleanNet on Linux."""

from __future__ import annotations

import os
import tempfile
import fcntl


class SingleInstance:
    """Small cross-runtime guard. Uses a Linux fcntl lock."""

    def __init__(self, name: str):
        self.name = name
        self._lock_path = os.path.join(tempfile.gettempdir(), f"{name}.lock")
        self._fd = None

    def acquire(self) -> bool:
        try:
            self._fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(self._fd, str(os.getpid()).encode("ascii"))
            return True
        except (BlockingIOError, OSError):
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except Exception:
                    pass
                self._fd = None
            return False

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
                os.remove(self._lock_path)
            except Exception:
                pass
            self._fd = None
