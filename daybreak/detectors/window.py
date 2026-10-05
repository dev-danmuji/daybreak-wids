"""Time-based sliding windows and threshold triggers (event-time driven)."""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Any, Callable, Generic, Hashable, Iterable, TypeVar

T = TypeVar("T")


class SlidingWindow(Generic[T]):
    """Items with timestamps; anything older than ``window`` seconds is dropped."""

    __slots__ = ("window", "_items")

    def __init__(self, window: float):
        if window <= 0:
            raise ValueError("window must be positive")
        self.window = float(window)
        self._items: deque[tuple[float, T]] = deque()

    def add(self, ts: float, value: T = None) -> None:  # type: ignore[assignment]
        if self._items and ts < self._items[-1][0]:
            if self._items[-1][0] - ts > self.window:
                # The clock went back by more than the window (or the newest item carried a
                # stray future timestamp): start over, so that item cannot hold every later
                # one in the window and inflate the counts.
                self._items.clear()
            else:
                # Small reordering: count it with the newest item (O(1); decreasing
                # timestamps cannot make every insert O(n)).
                ts = self._items[-1][0]
        self._items.append((ts, value))

    def expire(self, now: float) -> None:
        cutoff = now - self.window
        items = self._items
        while items and items[0][0] <= cutoff:
            items.popleft()

    def count(self, now: float) -> int:
        self.expire(now)
        return len(self._items)

    def values(self, now: float) -> list[T]:
        self.expire(now)
        return [v for _, v in self._items]

    def distinct(self, now: float, key: Callable[[T], Hashable] | None = None) -> set:
        self.expire(now)
        if key is None:
            return {v for _, v in self._items if v is not None}
        return {key(v) for _, v in self._items if v is not None}

    @property
    def first_ts(self) -> float | None:
        return self._items[0][0] if self._items else None

    @property
    def last_ts(self) -> float | None:
        return self._items[-1][0] if self._items else None

    def __len__(self) -> int:
        return len(self._items)


class Trigger:
    """Edge-triggered threshold with hysteresis.

    ``update(count, now)`` returns ``"fire"`` when the count first reaches the
    threshold, ``"escalate"`` when it later reaches ``escalate_factor`` times the
    last reported count, and re-arms once the count falls below
    ``rearm_ratio * threshold`` or ``rearm_after`` seconds passed since firing.
    """

    __slots__ = ("threshold", "strict", "rearm_below", "rearm_after", "escalate_factor", "armed",
                 "last_reported", "fired_at")

    def __init__(self, threshold: float, *, strict: bool = False, rearm_ratio: float = 0.5,
                 rearm_after: float | None = None, escalate_factor: float = 2.0):
        self.threshold = threshold
        self.strict = strict
        self.rearm_below = max(1.0, threshold * rearm_ratio)
        self.rearm_after = rearm_after
        self.escalate_factor = escalate_factor
        self.armed = True
        self.last_reported = 0.0
        self.fired_at: float | None = None

    def _hit(self, count: float) -> bool:
        return count > self.threshold if self.strict else count >= self.threshold

    def update(self, count: float, now: float | None = None) -> str | None:
        if not self.armed:
            expired = (self.rearm_after is not None and now is not None and self.fired_at is not None
                       and now - self.fired_at >= self.rearm_after)
            if count < self.rearm_below or expired:
                self.armed = True
                self.last_reported = 0.0
        if self.armed:
            if self._hit(count):
                self.armed = False
                self.last_reported = count
                self.fired_at = now
                return "fire"
            return None
        if self.escalate_factor and count >= self.last_reported * self.escalate_factor:
            self.last_reported = count
            return "escalate"
        return None


K = TypeVar("K", bound=Hashable)


class KeyedState(Generic[K, T]):
    """Lazily created per-key state with idle eviction and at most ``max_keys`` keys: the least
    recently used key is dropped first, except keys for which ``keep`` is true (registered
    BSSIDs), so a flood of random BSSIDs cannot grow it or push out the protected network."""

    def __init__(self, factory: Callable[[], T], idle_timeout: float = 3600.0, *, max_keys: int = 4096,
                 keep: Callable[[K], bool] | None = None):
        self.factory = factory
        self.idle_timeout = idle_timeout
        self.max_keys = max_keys
        self.keep = keep
        self._state: dict[K, T] = {}
        self._seen: OrderedDict[K, float] = OrderedDict()

    def get(self, key: K, now: float) -> T:
        st = self._state.get(key)
        if st is None:
            st = self._state[key] = self.factory()
            self._seen[key] = now
            if len(self._state) > self.max_keys:
                self._evict_one(key)
        else:
            self._seen[key] = now
            self._seen.move_to_end(key)
        return st

    def _evict_one(self, newest: K) -> None:
        victim = next((k for k in self._seen if k != newest and not (self.keep and self.keep(k))), None)
        if victim is not None:
            del self._seen[victim]
            self._state.pop(victim, None)

    def peek(self, key: K) -> T | None:
        return self._state.get(key)

    def items(self) -> Iterable[tuple[K, T]]:
        return self._state.items()

    def evict_idle(self, now: float) -> int:
        stale = [k for k, t in self._seen.items() if now - t > self.idle_timeout]
        for k in stale:
            self._state.pop(k, None)
            self._seen.pop(k, None)
        return len(stale)

    def __len__(self) -> int:
        return len(self._state)

    def __contains__(self, key: Any) -> bool:
        return key in self._state
