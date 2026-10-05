"""RSN / WPA / RSNXE element parsers -> :class:`SecurityProfile`.

Only capability fields are read (suites, counts, RSN capability bits). PMKID
lists that may follow are skipped and never stored.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from ..models import SecurityProfile
from .ieee80211 import MS_TYPE_WPA, MS_TYPE_WPS, OUI_IEEE, OUI_MICROSOFT

CIPHER_SUITES = {
    0: "USE-GROUP", 1: "WEP40", 2: "TKIP", 4: "CCMP-128", 5: "WEP104", 6: "BIP-CMAC-128",
    7: "GROUP-NOT-ALLOWED", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256", 11: "BIP-GMAC-128",
    12: "BIP-GMAC-256", 13: "BIP-CMAC-256",
}
AKM_SUITES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
    7: "TDLS", 8: "SAE", 9: "FT-SAE", 10: "AP-PEER-KEY", 11: "802.1X-SUITE-B",
    12: "802.1X-SUITE-B-192", 13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384",
    16: "FT-FILS-SHA256", 17: "FT-FILS-SHA384", 18: "OWE", 19: "FT-PSK-SHA384", 20: "PSK-SHA384",
    22: "802.1X-SHA384", 24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY",
}
WPA1_AKMS = {1: "802.1X", 2: "PSK"}
WPA1_CIPHERS = {0: "USE-GROUP", 1: "WEP40", 2: "TKIP", 4: "CCMP-128", 5: "WEP104"}

RSN_CAP_MFPR = 0x0040
RSN_CAP_MFPC = 0x0080


class RsnParseError(ValueError):
    pass


@dataclass
class RsnInfo:
    version: int
    group_cipher: str | None = "CCMP-128"
    pairwise: list[str] = field(default_factory=lambda: ["CCMP-128"])
    akms: list[str] = field(default_factory=lambda: ["802.1X"])
    capabilities: int = 0
    pmkid_count: int = 0
    group_mgmt_cipher: str | None = None

    @property
    def mfp_capable(self) -> bool:
        return bool(self.capabilities & RSN_CAP_MFPC)

    @property
    def mfp_required(self) -> bool:
        return bool(self.capabilities & RSN_CAP_MFPR)


def _suite(raw: bytes, oui: bytes, table: Mapping[int, str]) -> str:
    if raw[:3] == oui:
        return table.get(raw[3], f"{oui.hex(':')}:{raw[3]}")
    return f"VENDOR-{raw[:3].hex(':')}:{raw[3]}"


def _suite_list(data: bytes, off: int, oui: bytes, table: Mapping[int, str], what: str) -> tuple[list[str], int]:
    if off + 2 > len(data):
        raise RsnParseError(f"truncated {what} count")
    (count,) = struct.unpack_from("<H", data, off)
    off += 2
    if off + 4 * count > len(data):
        raise RsnParseError(f"truncated {what} list ({count} entries)")
    items = [_suite(data[off + 4 * i: off + 4 * i + 4], oui, table) for i in range(count)]
    return items, off + 4 * count


def parse_rsn_ie(data: bytes) -> RsnInfo:
    """Parse an RSN element payload (without element ID and length)."""
    if len(data) < 2:
        raise RsnParseError("RSN element too short")
    (version,) = struct.unpack_from("<H", data, 0)
    if version != 1:
        raise RsnParseError(f"unsupported RSN version {version}")
    info = RsnInfo(version=version)
    off = 2
    if off + 4 <= len(data):
        info.group_cipher = _suite(data[off:off + 4], OUI_IEEE, CIPHER_SUITES)
        off += 4
    elif off != len(data):
        raise RsnParseError("truncated group cipher")
    if off < len(data):
        info.pairwise, off = _suite_list(data, off, OUI_IEEE, CIPHER_SUITES, "pairwise cipher")
    if off < len(data):
        info.akms, off = _suite_list(data, off, OUI_IEEE, AKM_SUITES, "AKM")
    if off + 2 <= len(data):
        (info.capabilities,) = struct.unpack_from("<H", data, off)
        off += 2
    if off + 2 <= len(data):
        (info.pmkid_count,) = struct.unpack_from("<H", data, off)
        off += 2 + 16 * info.pmkid_count  # skipped, never stored
        if off > len(data):
            raise RsnParseError("truncated PMKID list")
    if off + 4 <= len(data):
        info.group_mgmt_cipher = _suite(data[off:off + 4], OUI_IEEE, CIPHER_SUITES)
    return info


def parse_wpa1_ie(data: bytes) -> RsnInfo:
    """Parse a WPA (vendor 00:50:F2 type 1) element payload *after* OUI and type."""
    if len(data) < 2:
        raise RsnParseError("WPA element too short")
    (version,) = struct.unpack_from("<H", data, 0)
    if version != 1:
        raise RsnParseError(f"unsupported WPA version {version}")
    info = RsnInfo(version=1, group_cipher="TKIP", pairwise=["TKIP"], akms=["802.1X"])
    off = 2
    if off + 4 <= len(data):
        info.group_cipher = _suite(data[off:off + 4], OUI_MICROSOFT, WPA1_CIPHERS)
        off += 4
    if off < len(data):
        info.pairwise, off = _suite_list(data, off, OUI_MICROSOFT, WPA1_CIPHERS, "WPA pairwise")
    if off < len(data):
        info.akms, off = _suite_list(data, off, OUI_MICROSOFT, WPA1_AKMS, "WPA AKM")
    return info


def parse_rsnxe(data: bytes) -> dict[str, bool]:
    if not data:
        return {}
    b0 = data[0]
    return {"protected_twt": bool(b0 & 0x10), "sae_h2e": bool(b0 & 0x20)}


def security_from_elements(privacy: bool, elements: Mapping[int, Sequence[bytes]]) -> tuple[SecurityProfile, list[str]]:
    """Build a profile from parsed elements; returns (profile, list of malformed element names)."""
    malformed: list[str] = []
    rsn: RsnInfo | None = None
    wpa1: RsnInfo | None = None
    wps = None
    for payload in elements.get(48, ()):
        try:
            rsn = parse_rsn_ie(payload)
        except RsnParseError:
            malformed.append("rsn")
        break
    for payload in elements.get(221, ()):
        if len(payload) >= 4 and payload[:3] == OUI_MICROSOFT:
            if payload[3] == MS_TYPE_WPA and wpa1 is None:
                try:
                    wpa1 = parse_wpa1_ie(payload[4:])
                except RsnParseError:
                    malformed.append("wpa")
            elif payload[3] == MS_TYPE_WPS:
                wps = True
    rsnx = {}
    for payload in elements.get(244, ()):
        rsnx = parse_rsnxe(payload)
        break
    akms: list[str] = []
    pairwise: list[str] = []
    for info in (rsn, wpa1):
        if info:
            akms += [a for a in info.akms if a not in akms]
            pairwise += [c for c in info.pairwise if c not in pairwise]
    profile = SecurityProfile(
        privacy=privacy or rsn is not None or wpa1 is not None,
        rsn=rsn is not None or "rsn" in malformed,
        wpa1=wpa1 is not None,
        akms=tuple(akms),
        pairwise_ciphers=tuple(pairwise),
        group_cipher=(rsn or wpa1).group_cipher if (rsn or wpa1) else None,
        group_mgmt_cipher=rsn.group_mgmt_cipher if rsn else None,
        mfp_capable=bool(rsn and rsn.mfp_capable),
        mfp_required=bool(rsn and rsn.mfp_required),
        sae_h2e=rsnx.get("sae_h2e") if rsnx else None,
        wps=wps,
        source="ie",
    )
    return profile, malformed
