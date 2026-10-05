"""Built-in passive capture backend (fallback when Kismet is unavailable).

Opens an ``AF_PACKET`` socket on a monitor-mode sensor interface, only ever
reads from it, and converts frames to metadata events. The socket is wrapped in
:class:`ReceiveOnlySocket`, whose interface offers receive operations only; no
code in the package writes to it (tests/test_safety.py checks the common forms).
Requires CAP_NET_RAW (run as root; do not give file capabilities to a shared Python interpreter).
"""

from __future__ import annotations

import errno
import select
import socket
import time
from pathlib import Path
from typing import Callable, Sequence

from ..dot11.frames import LINKTYPE_IEEE802_11, LINKTYPE_RADIOTAP, FrameParseError, parse_frame
from ..models import Event
from .backend import Backend, BackendStatus, BackendUnavailable

ETH_P_ALL = 0x0003
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_RADIOTAP = 803
ARPHRD_TO_LINKTYPE = {ARPHRD_IEEE80211_RADIOTAP: LINKTYPE_RADIOTAP, ARPHRD_IEEE80211: LINKTYPE_IEEE802_11}
_GONE = {errno.ENETDOWN, errno.ENXIO, errno.ENODEV, errno.EBADF}


class ReceiveOnlySocket:
    """Minimal wrapper offering receive, fileno and close only (a convention the package keeps,
    not a sandbox: nothing outside this module touches the underlying socket)."""

    __slots__ = ("_sock",)

    def __init__(self, interface: str):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            sock.bind((interface, 0))
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def fileno(self) -> int:
        return self._sock.fileno()

    def recv_into(self, buf: bytearray | memoryview) -> int:
        return self._sock.recv_into(buf)

    def close(self) -> None:
        self._sock.close()


def interface_linktype(interface: str, sysfs_root: str | Path = "/sys/class/net") -> int | None:
    try:
        arphrd = int((Path(sysfs_root) / interface / "type").read_text().strip())
    except (OSError, ValueError):
        return None
    return ARPHRD_TO_LINKTYPE.get(arphrd)


class PassiveBackend(Backend):
    name = "passive"

    def __init__(self, interface: str, *, sensor_name: str = "", channels: Sequence[int] = (),
                 dwell: float = 0.5, set_channel: Callable[[int], object] | None = None,
                 socket_factory: Callable[[str], ReceiveOnlySocket] = ReceiveOnlySocket,
                 sysfs_root: str | Path = "/sys/class/net", max_batch: int = 2000,
                 clock: Callable[[], float] = time.time):
        super().__init__(sensor_name or interface)
        self.interface = interface
        self.channels = list(dict.fromkeys(channels))
        self.dwell = dwell
        self.set_channel = set_channel
        self.socket_factory = socket_factory
        self.sysfs_root = sysfs_root
        self.max_batch = max_batch
        self.clock = clock
        self.linktype: int | None = None
        self._sock: ReceiveOnlySocket | None = None
        self._buf = bytearray(65536)
        self._hop_index = 0
        self._next_hop = 0.0
        self.current_channel: int | None = None
        self.stats.update(frames=0, unparsable=0, ignored=0)
        self._failed: str | None = None

    def open(self) -> None:
        if not (Path(self.sysfs_root) / self.interface).exists():
            raise BackendUnavailable(f"sensor interface {self.interface} is not present")
        self.linktype = interface_linktype(self.interface, self.sysfs_root)
        if self.linktype is None:
            raise BackendUnavailable(
                f"{self.interface} is not in monitor mode (radiotap); run "
                f"`sudo daybreak-wids sensor prepare --apply` (changes {self.interface} only)")
        try:
            self._sock = self.socket_factory(self.interface)
        except PermissionError as exc:
            raise BackendUnavailable("raw capture needs CAP_NET_RAW (run the monitor with sudo)") from exc
        except OSError as exc:
            raise BackendUnavailable(f"cannot open capture on {self.interface}: {exc}") from exc
        self._failed = None
        if self.channels and self.set_channel:
            self._tune(self.channels[0])
            self._next_hop = self.clock() + self.dwell

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def set_interface(self, interface: str) -> None:
        self.close()
        self.interface = interface

    def _tune(self, channel: int) -> None:
        try:
            self.set_channel(channel)
            self.current_channel = channel
        except Exception as exc:  # guard refusal or iw failure: keep listening where we are
            self.note_error(f"channel {channel}: {exc}")

    def _maybe_hop(self) -> None:
        if len(self.channels) < 2 or not self.set_channel:
            return
        now = self.clock()
        if now >= self._next_hop:
            self._hop_index = (self._hop_index + 1) % len(self.channels)
            self._tune(self.channels[self._hop_index])
            self._next_hop = now + self.dwell

    def poll(self, timeout: float) -> list[Event]:
        if self._sock is None:
            raise BackendUnavailable(self._failed or "capture not open")
        self._maybe_hop()
        wait = min(timeout, self.dwell) if len(self.channels) > 1 else timeout
        try:
            ready, _, _ = select.select([self._sock], [], [], max(wait, 0))
        except (OSError, ValueError) as exc:
            self._fail(f"select failed: {exc}")
        if not ready:
            return []
        out: list[Event] = []
        view = memoryview(self._buf)
        for _ in range(self.max_batch):
            try:
                n = self._sock.recv_into(view)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno in _GONE:
                    self._fail(f"sensor interface {self.interface} went away ({exc.strerror})")
                raise BackendUnavailable(str(exc)) from exc
            self.stats["frames"] += 1
            try:
                ev = parse_frame(bytes(view[:n]), linktype=self.linktype or LINKTYPE_RADIOTAP,
                                 timestamp=self.clock(), sensor=self.sensor_name,
                                 default_channel=self.current_channel)
            except FrameParseError:
                self.stats["unparsable"] += 1
                continue
            if ev is None:
                self.stats["ignored"] += 1
                continue
            out.append(ev)
        self.stats["events"] += len(out)
        return out

    def _fail(self, message: str) -> None:
        self._failed = message
        self.close()
        raise BackendUnavailable(message)

    def status(self) -> BackendStatus:
        ok = self._sock is not None
        detail = f"passive capture on {self.interface}"
        if self.channels:
            detail += f", channels {','.join(map(str, self.channels))}"
        if self._failed:
            detail += f" ({self._failed})"
        return BackendStatus(self.name, ok, detail, sensor_ok=ok,
                             extra={"stats": dict(self.stats), "channel": self.current_channel})
