"""Offline analysis of existing capture files (pcap / pcapng), read-only.

Frames are reduced to metadata events exactly like live capture. Nothing is
written back and no frame content beyond detection metadata is retained.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from ..dot11.frames import FrameParseError, parse_frame
from ..models import Event
from .backend import Backend, BackendStatus, BackendUnavailable

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = 0x0A0D0D0A


class CaptureFormatError(ValueError):
    pass


def iter_capture(fh: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    """Yield (timestamp, linktype, frame bytes) from a pcap or pcapng stream."""
    head = fh.read(4)
    if head in PCAP_MAGIC:
        yield from _iter_pcap(fh, head)
    elif len(head) == 4 and struct.unpack("<I", head)[0] == PCAPNG_SHB:
        yield from _iter_pcapng(fh, head)
    else:
        raise CaptureFormatError("not a pcap/pcapng file")


def _iter_pcap(fh: BinaryIO, magic: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian, unit = PCAP_MAGIC[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        raise CaptureFormatError("truncated pcap header")
    linktype = struct.unpack(endian + "HHiIII", rest)[5] & 0x0FFFFFFF
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield sec + frac * unit, linktype, data


def _iter_pcapng(fh: BinaryIO, first: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    pending = first
    while True:
        hdr = pending + fh.read(8 - len(pending)) if pending else fh.read(8)
        pending = b""
        if len(hdr) < 8:
            return
        btype_raw = hdr[:4]
        if struct.unpack("<I", btype_raw)[0] == PCAPNG_SHB:
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            (blen,) = struct.unpack(endian + "I", hdr[4:8])
            fh.read(blen - 12)
            interfaces = []
            continue
        btype, blen = struct.unpack(endian + "II", hdr)
        if blen < 12:
            raise CaptureFormatError("invalid pcapng block length")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            unit = 1e-6
            off = 8
            while off + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, off)
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = body[off + 4]
                    unit = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                off += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, unit))
        elif btype == 6:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap = struct.unpack_from(endian + "IIII", body, 0)
            if iface >= len(interfaces):
                continue
            linktype, unit = interfaces[iface]
            yield ((ts_hi << 32) | ts_lo) * unit, linktype, body[20:20 + cap]
        elif btype == 3 and interfaces:  # Simple Packet Block
            linktype, _unit = interfaces[0]
            yield 0.0, linktype, body[4:]


class PcapFileBackend(Backend):
    name = "pcap"

    def __init__(self, path: str | Path, *, sensor_name: str = "pcap", batch: int = 1000):
        super().__init__(sensor_name)
        self.path = Path(path)
        self.batch = batch
        self._fh: BinaryIO | None = None
        self._iter: Iterator[tuple[float, int, bytes]] | None = None
        self._done = False
        self.stats.update(frames=0, unparsable=0, ignored=0)

    def open(self) -> None:
        try:
            self._fh = open(self.path, "rb")
            self._iter = iter_capture(self._fh)
        except OSError as exc:
            raise BackendUnavailable(f"cannot read {self.path}: {exc}") from exc

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    @property
    def finished(self) -> bool:
        return self._done

    def poll(self, timeout: float) -> list[Event]:
        out: list[Event] = []
        if self._iter is None:
            return out
        try:
            for ts, linktype, data in self._iter:
                self.stats["frames"] += 1
                try:
                    ev = parse_frame(data, linktype=linktype, timestamp=ts or 1.0, sensor=self.sensor_name)
                except FrameParseError:
                    self.stats["unparsable"] += 1
                    continue
                if ev is None:
                    self.stats["ignored"] += 1
                    continue
                out.append(ev)
                if len(out) >= self.batch:
                    break
            else:
                self._done = True
        except CaptureFormatError as exc:
            self._done = True
            raise BackendUnavailable(str(exc)) from exc
        self.stats["events"] += len(out)
        return out

    def status(self) -> BackendStatus:
        return BackendStatus(self.name, True, f"reading {self.path} ({self.stats['frames']} frames, "
                             f"{self.stats['events']} events)")
