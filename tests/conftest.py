from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest

from daybreak.config import config_from_dict

FIXTURES = Path(__file__).parent / "fixtures"

# BSSIDs used by the synthetic fixtures (documentation/example ranges only).
HOME_BSSID = "AA:BB:CC:DD:EE:FF"
HOME_BSSID_24G = "AA:BB:CC:DD:EE:F0"
ROGUE_BSSID = "02:13:37:00:00:01"


@pytest.fixture(autouse=True)
def _no_rf_or_network(monkeypatch):
    """Refuse AF_PACKET sockets at construction and subprocess.run calls to host network tools
    (loopback TCP to the fake Kismet servers stays allowed)."""
    real_socket = socket.socket

    class GuardedSocket(real_socket):
        def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
            if family == getattr(socket, "AF_PACKET", object()):
                raise AssertionError("tests must not open AF_PACKET sockets")
            super().__init__(family, type, proto, fileno)

    monkeypatch.setattr(socket, "socket", GuardedSocket)

    real_run = subprocess.run
    blocked = {"iw", "ip", "nmcli", "iwconfig", "rfkill", "notify-send", "airmon-ng", "kismet"}

    def guarded_run(args, *a, **kw):
        argv = [args] if isinstance(args, str) else list(args)
        if argv and os.path.basename(str(argv[0])) in blocked:
            raise AssertionError(f"tests must not run host network tools: {argv}")
        return real_run(args, *a, **kw)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    yield


def make_config(tmp_path: Path, **overrides):
    data = {
        "protected_networks": [
            {
                "name": "home",
                "ssid": "ExampleSSID",
                "bssids": [HOME_BSSID, HOME_BSSID_24G],
                "channels": [36, 6],
                "security": {"expected": ["WPA2", "WPA3"], "pmf": "capable"},
            },
            {"name": "lab", "ssid": "LabNet"},
        ],
        "storage": {"database": "var/test.db"},
        "logging": {"directory": "var/log"},
        "alerts": {"notifiers": [{"type": "jsonl", "min_severity": "INFO"}]},
        "registry_file": "networks.yaml",
    }
    for key, value in overrides.items():
        data[key] = value
    return config_from_dict(data, base_dir=tmp_path)


@pytest.fixture
def config(tmp_path):
    return make_config(tmp_path)
