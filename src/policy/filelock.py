"""Cross-process advisory file lock.

Extracted from exceptions.py so audit.py can use the same mechanism.
Both need the same guarantee for the same reason: a read-modify-write
that two processes can perform concurrently.

An OS-level lock rather than a lock file created with O_EXCL,
specifically because the OS releases it when the process dies. A lock
file left behind by a crash would block every future write — turning a
crash into a permanently unusable store or an unwritable audit log, which
is worse than the race it prevents.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import IO

log = logging.getLogger(__name__)


def _lock_fh(fh: IO[bytes]) -> None:
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)


def _unlock_fh(fh: IO[bytes]) -> None:
    if sys.platform == "win32":
        import msvcrt

        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class FileLock:
    """Advisory lock held for the duration of a read-modify-write.

    The lock is on a sidecar `<path>.lock` file, never on the target
    itself: the target is replaced by `os.replace` (exceptions.json) or
    renamed by rotation (audit.jsonl), and a lock on a file that gets
    replaced out from under it protects nothing.
    """

    def __init__(self, target: Path) -> None:
        self._path = target.with_suffix(target.suffix + ".lock")
        self._fh: IO[bytes] | None = None

    def __enter__(self) -> "FileLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a+b")
        self._fh.write(b"\0")  # msvcrt locks a byte range; there must be a byte
        self._fh.seek(0)
        _lock_fh(self._fh)
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fh is None:
            return
        try:
            _unlock_fh(self._fh)
        except OSError:
            log.warning("could not release lock on %s", self._path, exc_info=True)
        finally:
            self._fh.close()
            self._fh = None