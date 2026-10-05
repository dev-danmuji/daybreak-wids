"""Static guarantees: the package contains no transmit, injection, cracking or
password-guessing capability, and only runs an allow-listed set of host commands.

These tests inspect the source (AST) of every module under ``daybreak/``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from daybreak.safety import COMMAND_ALLOW_LIST

PKG = Path(__file__).resolve().parents[1] / "daybreak"
SOURCES = sorted(PKG.rglob("*.py"))


def _parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


TREES = {p: _parse(p) for p in SOURCES}


def _rel(path: Path) -> str:
    return str(path.relative_to(PKG.parent))


def _string_constants(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            yield node


def _calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _call_name(node: ast.Call) -> str:
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def test_sources_found():
    assert len(SOURCES) > 5


# -- No packet injection API exists ----------------------------------------------------------------

BANNED_IMPORTS = {
    "scapy", "lorcon", "pylorcon2", "pcapy", "pcapy_ng", "impacket", "pyric", "wifi",
    "netfilterqueue", "pyshark", "dpkt", "hmac",
}


def test_no_injection_or_frame_crafting_libraries():
    for path, tree in TREES.items():
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in BANNED_IMPORTS, f"{_rel(path)} imports {name}"


SEND_METHODS = {"send", "sendto", "sendmsg", "sendall", "sendfile", "sendp", "sendpfast",
                "srp", "srp1", "sr", "sr1", "inject", "write"}


def test_raw_sockets_are_receive_only():
    """Any module touching AF_PACKET / raw sockets must contain no send/write calls."""
    raw_modules = []
    for path, tree in TREES.items():
        src = path.read_text(encoding="utf-8")
        if "AF_PACKET" in src or "SOCK_RAW" in src:
            raw_modules.append(path)
            for call in _calls(tree):
                name = _call_name(call)
                last = name.rsplit(".", 1)[-1]
                assert last not in SEND_METHODS, f"{_rel(path)}:{call.lineno} calls {name}"
                assert name not in ("os.write", "os.writev"), f"{_rel(path)}:{call.lineno} calls {name}"
    # The raw capture code must exist in exactly the expected place (no hidden copies).
    assert all(p.name in {"passive.py"} for p in raw_modules), raw_modules


def test_no_transmit_shaped_definitions():
    banned = re.compile(
        r"(inject|transmit|send_?(deauth|disassoc|frame|packet|mgmt)|deauth_?(attack|flood|send)|"
        r"(craft|forge|build)_?(frame|packet|deauth|beacon|radiotap)|tx_?frame|jam)",
        re.I)
    for path, tree in TREES.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not banned.search(node.name), f"{_rel(path)}:{node.lineno} defines {node.name}"


# -- No deauth transmission exists -------------------------------------------------------------------

ATTACK_TOOLS = {
    "aireplay-ng", "aircrack-ng", "airbase-ng", "mdk3", "mdk4", "hashcat", "john", "hcxdumptool",
    "hcxpcapngtool", "hcxtools", "cowpatty", "pyrit", "reaver", "bully", "wifite", "bettercap",
    "eaphammer", "wifiphisher", "hostapd-wpe", "wpa_cli", "wpa_supplicant", "hostapd",
}


def test_no_attack_tools_are_referenced():
    for path, tree in TREES.items():
        for const in _string_constants(tree):
            if isinstance(const.value, str):
                words = set(re.findall(r"[A-Za-z0-9_\-]+", const.value.lower()))
                hit = words & ATTACK_TOOLS
                assert not hit, f"{_rel(path)}:{const.lineno} references {hit}"


def test_no_management_frame_templates():
    """No deauth (0xC0) / disassoc (0xA0) frame-control byte templates in package code."""
    for path, tree in TREES.items():
        for const in _string_constants(tree):
            if isinstance(const.value, bytes):
                assert not re.search(rb"[\xc0\xa0]\x00", const.value), f"{_rel(path)}:{const.lineno}"


# Single source of truth: the runtime allow-list enforced by CommandRunner, plus notify-send
# (run by the desktop notifier, fixed arguments).
ALLOWED_HOST_COMMANDS = [entry.pattern for entry in COMMAND_ALLOW_LIST] + [("notify-send", None)]


def _literal_argv(node: ast.List) -> list[object] | None:
    out: list[object] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            out.append(None)  # variable part (interface name, channel, ...)
    return out


def _matches(argv: list[object], pattern: tuple) -> bool:
    if argv[0] == "notify-send" and pattern[0] == "notify-send":
        return True
    if len(argv) != len(pattern):
        return False
    for got, want in zip(argv, pattern):
        if want is None:
            continue
        if isinstance(want, (set, frozenset)):
            if got is not None and got not in want:
                return False
            continue
        if got != want:
            return False
    return True


def test_host_commands_are_allow_listed():
    """Every literal command line starting with iw/ip/nmcli/notify-send is on the allow-list."""
    seen = 0
    for path, tree in TREES.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.List) and node.elts:
                first = node.elts[0]
                if isinstance(first, ast.Constant) and first.value in {"iw", "ip", "nmcli", "notify-send",
                                                                         "iwconfig", "ifconfig", "airmon-ng"}:
                    argv = _literal_argv(node)
                    seen += 1
                    assert any(_matches(argv, p) for p in ALLOWED_HOST_COMMANDS), \
                        f"{_rel(path)}:{node.lineno} runs non-allow-listed command {argv}"
    assert seen >= 8


# -- No handshake cracking exists ---------------------------------------------------------------------

def test_no_key_derivation_or_mic_verification():
    banned_calls = {"pbkdf2_hmac", "hmac.new", "hashlib.pbkdf2_hmac", "scrypt"}
    banned_defs = re.compile(r"(pmk|ptk|kck|kek|_mic\b|^mic_|derive_?key|verify_?mic|compute_?mic|crack|"
                             r"psk_?from|passphrase_?to)", re.I)
    for path, tree in TREES.items():
        for call in _calls(tree):
            name = _call_name(call)
            assert name not in banned_calls and not name.endswith(".pbkdf2_hmac"), \
                f"{_rel(path)}:{call.lineno} calls {name}"
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not banned_defs.search(node.name), f"{_rel(path)}:{node.lineno} defines {node.name}"


def test_no_handshake_export_formats():
    banned = ("hccapx", "hc22000", ".22000", "wpa*01*", "wpa*02*", "hccap", "pmkid_export",
              "handshake.cap", "handshake.pcap")
    for path, tree in TREES.items():
        for const in _string_constants(tree):
            if isinstance(const.value, str):
                low = const.value.lower()
                for b in banned:
                    assert b not in low, f"{_rel(path)}:{const.lineno} contains {b!r}"


def test_no_binary_file_writes():
    """Nothing in the package writes binary files (no pcap/handshake export)."""
    for path, tree in TREES.items():
        for call in _calls(tree):
            name = _call_name(call)
            if name in ("open", "io.open") or name.endswith(".open"):
                modes = [a.value for a in call.args[1:2] if isinstance(a, ast.Constant)]
                modes += [k.value.value for k in call.keywords
                          if k.arg == "mode" and isinstance(k.value, ast.Constant)]
                for mode in modes:
                    if isinstance(mode, str) and "b" in mode:
                        assert not set(mode) & {"w", "a", "x", "+"}, \
                            f"{_rel(path)}:{call.lineno} opens a file with mode {mode!r}"
            assert not name.endswith("write_bytes"), f"{_rel(path)}:{call.lineno} calls {name}"


# -- No password dictionary functionality exists -----------------------------------------------------

def test_no_password_guessing_functionality():
    banned_defs = re.compile(r"(wordlist|dictionary|brute|guess|candidate_?pass|mutat|permut|"
                             r"password_?(gen|list|recover|crack)|recover_?pass|keyspace)", re.I)
    banned_calls = {"itertools.product", "itertools.permutations",
                    "itertools.combinations_with_replacement", "product", "permutations"}
    for path, tree in TREES.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not banned_defs.search(node.name), f"{_rel(path)}:{node.lineno} defines {node.name}"
        for call in _calls(tree):
            assert _call_name(call) not in banned_calls, f"{_rel(path)}:{call.lineno}"


def test_psk_is_never_accepted_as_input():
    """No CLI option or config field takes the Wi-Fi passphrase."""
    for path, tree in TREES.items():
        for const in _string_constants(tree):
            if isinstance(const.value, str) and const.value.startswith("--"):
                assert not re.search(r"(psk|passphrase|wifi-password|wpa-key)", const.value, re.I), \
                    f"{_rel(path)}:{const.lineno} defines option {const.value}"
    from daybreak import config as cfg_mod
    import dataclasses
    for obj in vars(cfg_mod).values():
        if dataclasses.is_dataclass(obj) and isinstance(obj, type):
            for f in dataclasses.fields(obj):
                assert not re.search(r"(psk|passphrase|wifi_password)", f.name, re.I), f"{obj.__name__}.{f.name}"


# -- Runtime safety declarations --------------------------------------------------------------------

def test_safety_defaults_are_passive():
    from daybreak.config import SafetyConfig
    s = SafetyConfig()
    assert s.passive_only is True and s.packet_injection is False
    assert s.transmit_management_frames is False


@pytest.mark.parametrize("flags", [
    {"passive_only": False}, {"packet_injection": True}, {"transmit_management_frames": True},
    {"passive_only": "true"},
])
def test_enforce_passive_rejects(flags):
    from daybreak.safety import SafetyViolation, enforce_passive
    with pytest.raises(SafetyViolation):
        enforce_passive(flags)


# -- Operator scripts ------------------------------------------------------------------------------

SCRIPTS = sorted((PKG.parent / "scripts").glob("*.sh"))
_SUDO_AT_COMMAND = re.compile(r"(?:^|[;&|({]|\$\(|\b(?:then|do|else)\b)\s*sudo\b((?:\$\([^)]*\)|[^;&|)])*)")
_ALLOWED_SUDO = [
    re.compile(r'^\s*"\$DAYBREAK" -c "\$CONFIG" "\$@"\s*$'),          # daybreak-wids itself (guarded)
    re.compile(r'^\s*(-n )?kill -INT "\$MON_PID"( 2>/dev/null)?\s*$'),  # stop its own monitor
    re.compile(r'^\s*chown -R -h "\$\(id -u\):\$\(id -g\)" var( 2>/dev/null)?\s*$'),  # hand back var/
    re.compile(r"^\s*-n -v( 2>/dev/null)?\s*$"),                        # keep the timestamp alive
]
_MUTATING_NET = re.compile(r"\b(iw|ip|nmcli|iwconfig|ifconfig|rfkill)\b[^|;\n]*\b(set|add|del|delete|flush|"
                           r"down|up|connect|disconnect|radio|modify|reapply|rescan|scan|wifi|on|off)\b")
_ATTACK_TOOLS = re.compile(r"\b(aireplay|aircrack|airmon|airodump|mdk[34]|hcxdumptool|hcxpcapngtool|hashcat|"
                           r"john|bettercap|wifite|reaver|bully|hostapd|tcpdump|tshark|dumpcap|scapy)\b", re.I)


def test_operator_scripts_only_escalate_daybreak_itself():
    """scripts/*.sh never run interface-changing tools or attack tools; sudo is used only for
    daybreak-wids itself, to stop its own monitor, to hand var/ back, and to keep sudo alive."""
    assert SCRIPTS
    for path in SCRIPTS:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            code = re.sub(r"\s+#\s.*$", "", line)
            assert not _ATTACK_TOOLS.search(code), f"{path.name}:{lineno}: {line.strip()}"
            assert not _MUTATING_NET.search(code), f"{path.name}:{lineno} changes an interface: {line.strip()}"
            for m in _SUDO_AT_COMMAND.finditer(code):
                assert any(p.match(m.group(1)) for p in _ALLOWED_SUDO), \
                    f"{path.name}:{lineno} escalates something else: sudo{m.group(1)}"
