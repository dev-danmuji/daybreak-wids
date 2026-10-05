import io
import json
import os

import pytest

from daybreak.alerts.base import NOTIFIER_TYPES, Notifier, build_notifiers, register_notifier
from daybreak.alerts.console import ConsoleNotifier
from daybreak.alerts.desktop import DesktopNotifier
from daybreak.alerts.formatting import human_text
from daybreak.alerts.jsonl import JsonlNotifier, rotating_logger
from daybreak.alerts.manager import AlertManager, TokenBucket
from daybreak.config import NotifierConfig
from daybreak.models import Alert, ScoreComponent, Severity
from daybreak.safety import TRUSTED_PATH
from daybreak.storage import Database

T0 = 1790000000.0


def alert(t=0.0, score=30, kind="DEAUTH_BURST", network="home", **kw):
    return Alert(kind, T0 + t, score, [ScoreComponent(score, "deauth burst", "37 frames/5s")],
                 summary="test", network=network, bssid="AA:BB:CC:DD:EE:FF", channel=36,
                 details=kw.pop("details", {"frames": 37, "window": 5.0, "affected_stations": 4}), **kw)


class Recorder(Notifier):
    type_name = "recorder"

    def __init__(self, min_severity="INFO", fail=False, rate_limited=True):
        super().__init__(min_severity)
        self.got = []
        self.notes = []
        self.fail = fail
        self.rate_limited = rate_limited

    def notify(self, a, *, note=None):
        if self.fail:
            raise RuntimeError("boom")
        self.got.append(a)
        self.notes.append(note)


def test_cooldown_suppresses_repeats(tmp_path):
    db = Database(tmp_path / "a.db")
    rec = Recorder()
    m = AlertManager([rec], db=db, cooldown=300)
    assert m.submit(alert(0)) is True
    assert m.submit(alert(10)) is False
    assert m.submit(alert(20)) is False
    assert len(rec.got) == 1 and m.stats["suppressed"] == 2
    row = db.list_alerts()[0]
    assert row["suppressed_count"] == 2 and row["last_seen"] == T0 + 20
    assert m.submit(alert(400)) is True          # cooldown over
    assert rec.got[-1].suppressed_count == 2     # tells the operator what was suppressed
    assert len(db.list_alerts()) == 2


def test_escalation_breaks_through_cooldown():
    rec = Recorder()
    m = AlertManager([rec], cooldown=300, escalation_delta=10)
    m.submit(alert(0, score=30))
    assert not m.submit(alert(5, score=35))      # +5: suppressed
    assert m.submit(alert(6, score=45))          # +15: escalation
    assert m.submit(alert(7, score=50))          # LOW -> MEDIUM: severity increase
    assert [a.score for a in rec.got] == [30, 45, 50]


def test_cooldown_is_per_type_and_scope():
    rec = Recorder()
    m = AlertManager([rec], cooldown=300)
    m.submit(alert(0))
    m.submit(alert(1, kind="BROADCAST_DEAUTH"))
    m.submit(alert(2, network="office"))
    assert len(rec.got) == 3


def test_rate_limit_and_note():
    rec = Recorder()
    jsonl_like = Recorder(rate_limited=False)
    m = AlertManager([rec, jsonl_like], cooldown=0, rate_limit_per_minute=3)
    for i in range(10):
        m.submit(alert(i * 0.1, kind=f"T{i}"))
    assert len(rec.got) == 3 and len(jsonl_like.got) == 10
    assert m.stats["rate_limited"] == 7
    m.submit(alert(120, kind="LATER"))          # tokens refilled
    assert rec.notes[-1] == "7 notification(s) skipped by rate limit"


def test_token_bucket_refill():
    b = TokenBucket(2)
    assert b.take(0) and b.take(0) and not b.take(0)
    assert b.take(30)  # one token per 30 s at 2/min
    assert TokenBucket(0).take(0)


def test_min_severity_and_failing_notifier_isolated():
    high_only = Recorder(min_severity="HIGH")
    broken = Recorder(fail=True)
    m = AlertManager([broken, high_only], cooldown=0)
    m.submit(alert(0, score=30))
    m.submit(alert(1, score=80, kind="POSSIBLE_DEAUTH_ATTACK"))
    assert [a.alert_type for a in high_only.got] == ["POSSIBLE_DEAUTH_ATTACK"]
    assert m.stats["notifier_errors"] == 2 and broken.errors == 2


def test_dry_run_writes_nothing(tmp_path):
    db = Database(tmp_path / "d.db")
    m = AlertManager([Recorder()], db=db, dry_run=True)
    m.submit(alert(0))
    assert db.list_alerts() == []


def test_human_format_matches_spec():
    text = human_text(alert(0, score=82, kind="POSSIBLE_DEAUTH_ATTACK"))
    lines = text.splitlines()
    assert lines[0].endswith(" HIGH POSSIBLE_DEAUTH_ATTACK")
    assert "BSSID=AA:BB:CC:DD:EE:FF" in lines and "Channel=36" in lines
    assert "Frames=37/5s" in lines and "AffectedStations=4" in lines
    assert "Risk 82 HIGH" in lines and "+82 deauth burst (37 frames/5s)" in lines


def test_console_notifier():
    buf = io.StringIO()
    ConsoleNotifier(stream=buf, color=False).notify(alert(0), note="n")
    out = buf.getvalue()
    assert "LOW DEAUTH_BURST" in out and "(n)" in out and "\033[" not in out


def test_jsonl_notifier_and_rotation(tmp_path):
    path = tmp_path / "log" / "alerts.jsonl"
    n = JsonlNotifier(path=path, max_bytes=2000, backup_count=2)
    for i in range(40):
        n.notify(alert(i, kind=f"T{i}"))
    n.close()
    files = sorted(p.name for p in path.parent.iterdir())
    assert files == ["alerts.jsonl", "alerts.jsonl.1", "alerts.jsonl.2"]
    for name in files:
        for line in (path.parent / name).read_text().splitlines():
            rec = json.loads(line)
            assert {"timestamp", "severity", "type", "score", "score_breakdown"} <= set(rec)
    last = json.loads(path.read_text().splitlines()[-1])
    assert last["type"] == "T39" and last["severity"] == "LOW"


def test_human_log_rotation(tmp_path):
    logger = rotating_logger("daybreak.test.human", tmp_path / "h.log", max_bytes=500, backup_count=3)
    for i in range(30):
        logger.info(human_text(alert(i)))
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["h.log", "h.log.1", "h.log.2", "h.log.3"]


def test_desktop_notifier_uses_notify_send():
    calls = []
    d = DesktopNotifier(min_severity="HIGH", run=lambda argv, **kw: calls.append((argv, kw)), available=True)
    a = alert(0, score=95, kind="POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")
    d.notify(a)
    argv, kw = calls[0]
    assert os.path.basename(argv[0]) == "notify-send" and "--urgency=critical" in argv
    assert "CRITICAL POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" in argv[3]
    assert kw["env"]["PATH"] == TRUSTED_PATH and not {"KISMET_API_KEY", "KISMET_PASSWORD"} & set(kw["env"])
    off = DesktopNotifier(run=lambda *a, **k: pytest.fail("must not run"), available=False)
    off.notify(a)


def test_notifier_registry_is_extensible(tmp_path):
    @register_notifier("unit-webhook")
    class Hook(Notifier):
        CONFIG_OPTIONS = frozenset({"url"})

        def __init__(self, min_severity="HIGH", url="", **options):
            super().__init__(min_severity, **options)
            self.url = url

        def notify(self, a, *, note=None):
            pass

    try:
        built = build_notifiers([NotifierConfig(type="unit-webhook", min_severity="MEDIUM",
                                                options={"url": "http://127.0.0.1/hook"}),
                                 NotifierConfig(type="jsonl")],
                                jsonl={"path": tmp_path / "x.jsonl"})
        assert isinstance(built[0], Hook) and built[0].url.endswith("/hook")
        assert built[0].min_severity is Severity.MEDIUM and isinstance(built[1], JsonlNotifier)
        with pytest.raises(ValueError, match="unknown option 'colour'"):
            build_notifiers([NotifierConfig(type="console", options={"colour": True})])
        with pytest.raises(ValueError, match="looks like a secret"):
            build_notifiers([NotifierConfig(type="unit-webhook", options={"wifi_psk": "x"})])
        with pytest.raises(ValueError, match="unknown notifier"):
            build_notifiers([NotifierConfig(type="carrier-pigeon")])
    finally:
        NOTIFIER_TYPES.pop("unit-webhook", None)
