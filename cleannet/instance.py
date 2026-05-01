"""Single-instance guard for CleanNet."""

from __future__ import annotations

import os
import tempfile


class SingleInstance:
    """Small cross-runtime guard. Uses a Windows mutex when available."""

    def __init__(self, name: str):
        self.name = name
        self._handle = None
        self._lock_path = os.path.join(tempfile.gettempdir(), f"{name}.lock")
        self._fd = None

    def acquire(self) -> bool:
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            self._handle = kernel32.CreateMutexW(None, False, self.name)
            if not self._handle:
                return False
            return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
        except Exception:
            try:
                self._fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, str(os.getpid()).encode("ascii"))
                return True
            except FileExistsError:
                return False

    def release(self) -> None:
        if self._handle:
            try:
                import ctypes

                ctypes.windll.kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None
        if self._fd is not None:
            try:
                os.close(self._fd)
                os.remove(self._lock_path)
            except Exception:
                pass
            self._fd = None
