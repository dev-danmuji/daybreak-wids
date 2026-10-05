"""Wi-Fi passphrase / router hygiene guidance (no passphrase input, ever).

daybreak-wids does not ask for, receive, store, test or log the network's
PSK. This module produces an operator checklist; where something can be
observed passively (WPS advertisement, WPA3/PMF state) the observation is
shown next to the checklist item.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import SecurityProfile


@dataclass
class PolicyItem:
    key: str
    title: str
    guidance: str
    observed: str | None = None      # passive observation, if any
    status: str = "check"            # ok | attention | check

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title, "guidance": self.guidance,
                "observed": self.observed, "status": self.status}


def policy_checklist(profile: SecurityProfile | None = None) -> list[PolicyItem]:
    items = [
        PolicyItem(
            "wpa3", "Use WPA3-SAE",
            "SAE is not vulnerable to offline dictionary attacks on captured handshakes. Use WPA3-only, "
            "or WPA2/WPA3 transition while WPA2-only clients remain."),
        PolicyItem(
            "pmf", "Protected Management Frames",
            "Enable PMF (802.11w); set it to 'required' once all clients support it. PMF makes clients "
            "ignore spoofed deauthentication/disassociation frames."),
        PolicyItem(
            "passphrase", "Long, random passphrase",
            "Use at least 20 random characters from a password manager, or a 5-6 word randomly chosen "
            "passphrase. Do not derive it from the SSID, address, phone number or names, and do not "
            "reuse it elsewhere. Rotate it when people with access leave."),
        PolicyItem(
            "default-psk", "No router default Wi-Fi password",
            "If the passphrase is the one printed on the router label or from the ISP setup, change it; "
            "default passphrases follow predictable patterns."),
        PolicyItem(
            "admin", "Router administration",
            "Change the default admin password, disable remote administration, and keep the firmware "
            "up to date."),
        PolicyItem(
            "wps", "Disable WPS",
            "WPS PIN provisioning can be brute-forced; disable WPS (including push-button) on the router."),
        PolicyItem(
            "guest", "Separate untrusted devices",
            "Put guests and IoT devices on a separate SSID/VLAN with its own passphrase."),
    ]
    if profile is not None:
        by_key = {i.key: i for i in items}
        if profile.has_sae and not profile.has_psk:
            by_key["wpa3"].observed, by_key["wpa3"].status = f"{profile.mode} advertised", "ok"
        else:
            by_key["wpa3"].observed, by_key["wpa3"].status = f"{profile.mode} advertised", "attention"
        pmf = by_key["pmf"]
        pmf.observed = f"PMF {profile.pmf}"
        pmf.status = "ok" if profile.mfp_required else "attention"
        if profile.wps:
            by_key["wps"].observed, by_key["wps"].status = "WPS element present in beacons", "attention"
        elif profile.source == "ie":
            by_key["wps"].observed, by_key["wps"].status = "no WPS element in beacons", "ok"
    return items


def render_checklist(items: list[PolicyItem], ssid: str | None = None) -> str:
    head = f"Password & router policy checklist{f' for {ssid}' if ssid else ''}"
    lines = [head, "=" * len(head),
             "daybreak-wids never asks for or stores your Wi-Fi passphrase.", ""]
    marks = {"ok": "[ok]", "attention": "[!!]", "check": "[  ]"}
    for item in items:
        lines.append(f"{marks[item.status]} {item.title}")
        if item.observed:
            lines.append(f"      observed: {item.observed}")
        lines.append(f"      {item.guidance}")
    return "\n".join(lines)
