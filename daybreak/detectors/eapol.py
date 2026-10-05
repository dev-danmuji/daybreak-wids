"""EAPOL / re-authentication surge detection from metadata only.

Counts EAPOL frames and 4-way-handshake *starts* (message 1) per station and
per BSSID. Handshake contents are never inspected: the parser only exposes the
message number derived from the Key Information bits.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import EapolConfig
from ..models import Event, EventType, Finding
from .base import EAPOL_REAUTH_SURGE, DetectionContext, finding
from .window import KeyedState, SlidingWindow, Trigger

# EAPOL-Key message 1 retransmissions closer than this are one handshake attempt.
RETRY_COALESCE = 3.0


@dataclass
class _StationState:
    frames: SlidingWindow
    starts: SlidingWindow
    trigger: Trigger
    last_start: float = -1e18


@dataclass
class _BssidState:
    frames: SlidingWindow
    reauth: SlidingWindow   # values: station performing a handshake start
    frame_t: Trigger
    station_t: Trigger


class EapolDetector:
    name = "eapol"

    def __init__(self, cfg: EapolConfig):
        self.cfg = cfg
        self.stations: KeyedState[tuple[str, str], _StationState] = KeyedState(lambda: _StationState(
            frames=SlidingWindow(cfg.station_window), starts=SlidingWindow(cfg.station_window),
            trigger=Trigger(1, rearm_after=cfg.station_window)))
        self.bssids: KeyedState[str, _BssidState] = KeyedState(lambda: _BssidState(
            frames=SlidingWindow(cfg.bssid_window), reauth=SlidingWindow(cfg.bssid_window),
            frame_t=Trigger(cfg.bssid_frame_threshold, rearm_after=cfg.bssid_window),
            station_t=Trigger(cfg.bssid_station_threshold, rearm_after=cfg.bssid_window)))

    @staticmethod
    def _is_start(ev: Event) -> bool:
        md = ev.metadata
        return md.get("eapol_msg") == 1 or md.get("eapol_type") == "start"

    def process(self, ev: Event, ctx: DetectionContext) -> list[Finding]:
        if self.bssids.keep is None:
            self.bssids.keep = lambda bssid, reg=ctx.registry: reg.by_bssid(bssid) is not None
        if ev.event_type is not EventType.EAPOL or not ev.bssid:
            return []
        ts = ev.timestamp
        out: list[Finding] = []
        b = self.bssids.get(ev.bssid, ts)
        b.frames.add(ts, ev.station)
        start = self._is_start(ev)

        if ev.station:
            s = self.stations.get((ev.bssid, ev.station), ts)
            s.frames.add(ts)
            if start and ts - s.last_start >= RETRY_COALESCE:
                s.starts.add(ts)
                b.reauth.add(ts, ev.station)
            if start:
                s.last_start = ts
            n_frames, n_starts = s.frames.count(ts), s.starts.count(ts)
            hot = (n_starts >= self.cfg.station_handshake_threshold
                   or n_frames >= self.cfg.station_frame_threshold)
            if s.trigger.update(1 if hot else 0, ts):
                out.append(finding(
                    EAPOL_REAUTH_SURGE, ev, ctx, category="eapol_reauth_surge",
                    label="EAPOL reauthentication surge",
                    detail=f"{ev.station}: {n_starts} handshakes, {n_frames} EAPOL frames in "
                           f"{self.cfg.station_window:g}s",
                    stations={ev.station},
                    details={"scope": "station", "station": ev.station, "handshakes": n_starts,
                             "eapol_frames": n_frames, "window": self.cfg.station_window},
                ))

        n_bssid = b.frames.count(ts)
        reauth_stations = b.reauth.distinct(ts)
        fired_frames = b.frame_t.update(n_bssid, ts)
        fired_stations = b.station_t.update(len(reauth_stations), ts)
        if fired_frames or fired_stations:
            out.append(finding(
                EAPOL_REAUTH_SURGE, ev, ctx, category="eapol_reauth_surge",
                label="EAPOL reauthentication surge",
                detail=f"{len(reauth_stations)} stations re-authenticating, {n_bssid} EAPOL frames in "
                       f"{self.cfg.bssid_window:g}s",
                stations=reauth_stations,
                details={"scope": "bssid", "stations": len(reauth_stations), "eapol_frames": n_bssid,
                         "window": self.cfg.bssid_window},
            ))
        return out

    def expire(self, now: float) -> None:
        self.stations.evict_idle(now)
        self.bssids.evict_idle(now)
