"""IEEE 802.11 constants used by the metadata parser."""

from __future__ import annotations

TYPE_MGMT, TYPE_CTRL, TYPE_DATA, TYPE_EXT = 0, 1, 2, 3

MGMT_ASSOC_REQ = 0
MGMT_ASSOC_RESP = 1
MGMT_REASSOC_REQ = 2
MGMT_REASSOC_RESP = 3
MGMT_PROBE_REQ = 4
MGMT_PROBE_RESP = 5
MGMT_BEACON = 8
MGMT_DISASSOC = 10
MGMT_AUTH = 11
MGMT_DEAUTH = 12
MGMT_ACTION = 13

FC_TODS = 0x01
FC_FROMDS = 0x02
FC_RETRY = 0x08
FC_PROTECTED = 0x40
FC_ORDER = 0x80

CAP_PRIVACY = 0x0010

EID_SSID = 0
EID_DS_PARAMS = 3
EID_COUNTRY = 7
EID_HT_CAP = 45
EID_RSN = 48
EID_MMIE = 76
EID_VHT_CAP = 191
EID_RSNX = 244
EID_VENDOR = 221
EID_EXTENSION = 255
EXT_HE_CAP = 35
EXT_EHT_CAP = 108

OUI_IEEE = b"\x00\x0f\xac"
OUI_MICROSOFT = b"\x00\x50\xf2"
MS_TYPE_WPA = 1
MS_TYPE_WPS = 4

LLC_SNAP_EAPOL = bytes.fromhex("aaaa03000000888e")
EAPOL_TYPE_EAP = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3

# EAPOL-Key "Key Information" bits (the only part of a key frame we read).
KI_PAIRWISE = 0x0008
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200

AUTH_ALGORITHMS = {0: "open", 1: "shared-key", 2: "ft", 3: "sae", 4: "fils-sk", 5: "fils-sk-pfs",
                   6: "fils-pk", 7: "pasn"}

REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving",
    4: "Disassociated due to inactivity",
    5: "AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting (re)association is not authenticated",
    10: "Power capability element unacceptable",
    11: "Supported channels element unacceptable",
    12: "Disassociated due to BSS transition management",
    13: "Invalid element",
    14: "Message integrity code (MIC) failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Element in 4-way handshake differs",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    25: "TDLS direct-link teardown: peer unreachable",
    26: "TDLS direct-link teardown: unspecified",
    27: "Disassociated: session terminated by SSP request",
    28: "Disassociated: no SSP roaming agreement",
    29: "Requested service rejected (cipher suite or AKM)",
    30: "Requested service not authorized in this location",
    31: "TS deleted: QoS AP lacks sufficient bandwidth",
    32: "Disassociated for unspecified, QoS-related reason",
    33: "Disassociated: QoS AP lacks sufficient bandwidth",
    34: "Disassociated: excessive frames need to be acknowledged",
    35: "Disassociated: STA transmitting outside TXOP limits",
    36: "Requested from peer STA: STA leaving BSS or resetting",
    37: "Requested from peer STA: does not want to use the mechanism",
    38: "Requested from peer STA: setup required",
    39: "Requested from peer STA: timeout",
    45: "Peer STA does not support the requested cipher suite",
    46: "Disassociated: authorized access limit reached",
    47: "Disassociated: external service requirements",
    48: "Invalid FT Action frame count",
    49: "Invalid PMKID",
    50: "Invalid MDE",
    51: "Invalid FTE",
}
# 52-72 are defined (mesh, link/channel, PASN, ...) but not named here.
_VALID_REASON = set(range(1, 40)) | set(range(45, 73))


def is_valid_reason(code: int | None) -> bool:
    return code is not None and code in _VALID_REASON


def reason_text(code: int | None) -> str:
    if code is None:
        return "unknown (encrypted or absent)"
    if code in REASON_CODES:
        return REASON_CODES[code]
    return "defined (unnamed)" if code in _VALID_REASON else "reserved/invalid"


def freq_to_channel(freq: int | float | None) -> tuple[int | None, str | None]:
    """Map a centre frequency (MHz) to ``(channel, band)``; band is "2.4", "5" or "6"."""
    if freq is None:
        return None, None
    f = int(round(freq))
    if f == 2484:
        return 14, "2.4"
    if 2407 < f < 2484:
        return (f - 2407) // 5, "2.4"
    if f == 5935:
        return 2, "6"
    if 5950 < f <= 7125:
        return (f - 5950) // 5, "6"
    if 4910 <= f <= 4980:
        return (f - 4000) // 5, "5"
    if 5000 <= f < 5950:
        return (f - 5000) // 5, "5"
    return None, None
