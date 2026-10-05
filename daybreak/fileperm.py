"""Private runtime files (database, logs, monitor status, registry).

They contain MAC addresses and network names, so they are created owner-only
(``0600`` files, ``0700`` directories). When daybreak-wids runs through ``sudo``
(passive backend), the files it creates are handed back to the invoking user
(``SUDO_UID``/``SUDO_GID``) so the normal-user CLI and dashboard can read them.

Permissions and ownership are changed on the file itself, never through a symbolic
link. Logs are opened with ``O_NOFOLLOW``, the status file and the registry are
written through ``mkstemp`` + rename, and a symlinked database path is refused.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path

PRIVATE_UMASK = 0o077


def invoking_user() -> tuple[int, int] | None:
    """(uid, gid) of the user who ran ``sudo``, when running as root through sudo."""
    if os.geteuid() != 0:
        return None
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    if not (uid.isdigit() and gid.isdigit()) or int(uid) == 0:
        return None
    return int(uid), int(gid)


def secure_path(path: str | Path) -> None:
    """Best effort: owner-only permissions, then hand the path back to the sudo user.

    Works on an ``O_NOFOLLOW`` descriptor, so a symbolic link (or a swap to one) is never
    followed; ``chmod``/``chown`` by path are not used.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:  # missing, a symlink (ELOOP), or not ours to open
        return
    try:
        secure_fd(fd, path)
    except OSError:
        pass
    finally:
        os.close(fd)


def private_dir(path: str | Path) -> Path:
    """``mkdir -p`` with owner-only permissions for every directory it creates."""
    p = Path(path)
    missing = []
    probe = p
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    for created in reversed(missing):
        secure_path(created)
    return p


def _parent_owner(path: str | Path | None) -> int | None:
    if path is None:
        return None
    try:
        return os.stat(Path(path).parent).st_uid
    except OSError:
        return None


def secure_fd(fd: int, path: str | Path | None = None) -> None:
    """Owner-only permissions (``0600``, directories ``0700``) applied to an open descriptor.

    Under sudo the invoking user becomes the owner, but only inside a directory that user owns
    (e.g. the repository's ``var/``): files a config points into system directories stay root's.
    A regular file with more than one hard link is never changed.
    """
    st = os.fstat(fd)
    if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
        return
    if st.st_mode & 0o077 and (st.st_uid == os.geteuid() or os.geteuid() == 0):
        os.fchmod(fd, 0o700 if stat.S_ISDIR(st.st_mode) else 0o600)
    owner = invoking_user()
    if owner is not None and (st.st_uid, st.st_gid) != owner and _parent_owner(path) == owner[0]:
        try:
            os.fchown(fd, *owner)
        except OSError:
            pass


def open_private_append(path: str | Path):
    """Open a log file for appending: owner-only, never through a symbolic link."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    secure_fd(fd, path)
    return fd


def write_private_atomic(path: str | Path, text: str) -> None:
    """Replace ``path`` with ``text`` via ``mkstemp`` (``O_EXCL``) + rename: a planted symlink
    at a temporary name cannot redirect the write, and the rename replaces a link itself."""
    p = Path(path)
    private_dir(p.parent)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        secure_fd(fd, tmp)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
