"""Static knowledge about the Oraimo Necklace Lite.

Everything in this module comes from the capture analysis in
``necklace_report.md`` (btmon capture ``necklace.cfa``). Values here are
*reference* data: the controller compares them with what BlueZ reports at
runtime, and never treats them as proof that a capability works right now.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_ADDRESS = "28:52:E0:0F:92:0A"

# Bluetooth SIG base UUID suffix used by 16-bit service UUIDs.
_SIG_SUFFIX = "-0000-1000-8000-00805f9b34fb"

# The JieLi proprietary SPP service. It was advertised in SDP but never opened
# in the capture. The agent never opens, connects to, or writes to it.
JIELI_CUSTOM_SPP_UUID = "fe010000-1234-5678-abcd-00805f9b34fb"
BLOCKED_UUIDS = frozenset({JIELI_CUSTOM_SPP_UUID})


def sig_uuid(short: int) -> str:
    return f"{short:08x}{_SIG_SUFFIX}"


@dataclass(frozen=True)
class ServiceInfo:
    uuid: str
    name: str
    description: str  # Arabic
    capture_status: str  # "used" | "advertised" | "blocked"


# Services the headset advertised in SDP (report section 4a).
KNOWN_SERVICES: dict[str, ServiceInfo] = {
    s.uuid: s
    for s in (
        ServiceInfo(sig_uuid(0x110B), "A2DP Sink", "استقبال الصوت (A2DP 1.3)", "used"),
        ServiceInfo(sig_uuid(0x110D), "A2DP", "توزيع الصوت المتقدم", "used"),
        ServiceInfo(sig_uuid(0x110E), "AVRCP", "التحكم عن بعد بالصوت والفيديو (AVRCP 1.5)", "used"),
        ServiceInfo(sig_uuid(0x110F), "AVRCP Controller", "وحدة تحكم AVRCP (الفئة 1)", "used"),
        ServiceInfo(sig_uuid(0x110C), "AVRCP Target", "هدف AVRCP (الفئة 2 — مستوى الصوت)", "used"),
        ServiceInfo(sig_uuid(0x111E), "HFP", "المكالمات دون استخدام اليدين (HFP 1.8)", "used"),
        ServiceInfo(sig_uuid(0x1203), "Generic Audio", "صوت عام", "used"),
        ServiceInfo(sig_uuid(0x1124), "HID", "جهاز إدخال HID (معلن فقط)", "advertised"),
        ServiceInfo(sig_uuid(0x1101), "SPP", "منفذ تسلسلي RFCOMM 1 (معلن فقط)", "advertised"),
        ServiceInfo(sig_uuid(0x1200), "PnP Information", "معلومات تعريف الجهاز", "used"),
        ServiceInfo(
            JIELI_CUSTOM_SPP_UUID,
            "JieLi SPP",
            "خدمة JieLi الخاصة RFCOMM 10 — محظورة ولا يتم التواصل معها",
            "blocked",
        ),
    )
}


@dataclass(frozen=True)
class DeviceProfile:
    """Reference identity of the headset, as observed in the capture."""

    name: str = "oraimo Necklace Lite"
    address: str = DEFAULT_ADDRESS
    oui_vendor: str = "Layon International Electronic & Telecom Co., Ltd"
    chipset_vendor: str = "Zhuhai Jieli Technology Co., Ltd"
    vendor_id: int = 0x05D6
    vendor_id_source: int = 0x0001  # Bluetooth SIG
    product_id: int = 0x000A
    version: int = 0x0240
    connection_type: str = "BR/EDR"
    avrcp_version: str = "1.5"
    avctp_version: str = "1.4"
    a2dp_version: str = "1.3"
    hfp_version: str = "1.8"
    hid_version: str = "1.0"
    avrcp_ct_features: str = "الفئة 1 (تشغيل/إيقاف)"
    avrcp_tg_features: str = "الفئة 2 (مستوى الصوت المطلق)"
    headset_tg_events: tuple[str, ...] = (
        "EVENT_PLAYBACK_STATUS_CHANGED",
        "EVENT_BATT_STATUS_CHANGED",
        "EVENT_VOLUME_CHANGED",
    )
    verified_passthrough: tuple[str, ...] = ("PLAY", "PAUSE")
    sdp_service_names: tuple[str, ...] = ("JL_A2DP", "JL_HFP", "JL_HID", "JL_SPP")
    profiles: tuple[str, ...] = field(
        default=("A2DP 1.3", "AVRCP 1.5", "HFP 1.8", "HID 1.0 (معلن)", "SPP (معلن)")
    )


PROFILE = DeviceProfile()

_MODALIAS_RE = re.compile(
    r"^(?P<src>bluetooth|usb):v(?P<vid>[0-9A-Fa-f]{4})p(?P<pid>[0-9A-Fa-f]{4})d(?P<ver>[0-9A-Fa-f]{4})$"
)


def parse_modalias(value: str | None) -> dict | None:
    """Parse BlueZ Device1.Modalias, e.g. ``bluetooth:v05D6p000Ad0240``."""
    if not value:
        return None
    m = _MODALIAS_RE.match(value.strip())
    if not m:
        return None
    return {
        "source": m.group("src"),
        "vendor_id": int(m.group("vid"), 16),
        "product_id": int(m.group("pid"), 16),
        "version": int(m.group("ver"), 16),
    }


def modalias_matches_profile(parsed: dict | None) -> bool | None:
    if parsed is None:
        return None
    return (
        parsed["source"] == "bluetooth"
        and parsed["vendor_id"] == PROFILE.vendor_id
        and parsed["product_id"] == PROFILE.product_id
        and parsed["version"] == PROFILE.version
    )


def describe_uuids(uuids: list[str] | None) -> list[dict]:
    out = []
    for raw in uuids or []:
        u = raw.lower()
        info = KNOWN_SERVICES.get(u)
        out.append(
            {
                "uuid": u,
                "name": info.name if info else None,
                "description": info.description if info else "خدمة غير معروفة",
                "blocked": u in BLOCKED_UUIDS,
            }
        )
    return out


def has_uuid(uuids: list[str] | None, short: int) -> bool:
    target = sig_uuid(short)
    return any(u.lower() == target for u in (uuids or []))


def normalize_address(addr: str) -> str:
    addr = addr.strip().upper()
    if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", addr):
        raise ValueError(f"invalid Bluetooth address: {addr!r}")
    return addr


def battery_level(percentage: int | None) -> str:
    if percentage is None:
        return "unknown"
    if percentage >= 80:
        return "full"
    if percentage >= 40:
        return "good"
    if percentage >= 15:
        return "low"
    return "critical"


# AVRCP absolute volume is 0..127 (report section 12 / 20).
VOLUME_MAX_RAW = 127
# The capture showed one headset step as 127 -> 120. A 1/16 step (8) is used
# for "up"/"down"; the headset may round to its own steps.
VOLUME_STEP_RAW = 8


def raw_to_percent(raw: int | None) -> int | None:
    if raw is None:
        return None
    return round(max(0, min(VOLUME_MAX_RAW, raw)) * 100 / VOLUME_MAX_RAW)


def percent_to_raw(percent: float) -> int:
    percent = max(0.0, min(100.0, float(percent)))
    return round(percent * VOLUME_MAX_RAW / 100)
