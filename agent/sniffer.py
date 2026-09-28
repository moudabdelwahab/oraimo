"""Passive Bluetooth traffic decoder (btsnoop files only).

This module never talks to Bluetooth hardware. It reads btsnoop files written
by ``btmon -w`` (Linux monitor format, datalink 2001) or Android HCI snoop
logs (H4, datalink 1002), reassembles L2CAP, and decodes the protocols seen
in the capture: HCI, L2CAP signaling, SDP, RFCOMM/HFP, AVCTP/AVRCP, AVDTP,
HID and ATT. Every packet is classified as standard, documented extension,
vendor-specific, or unknown. Link keys and PIN codes are masked.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from . import device as dev
from . import hid

log = logging.getLogger("necklace.sniffer")

BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_EPOCH_US = 0x00DCDDB30F2F8000  # microseconds between 0 AD and 1970 (verified against tshark)
DLT_H4 = 1002
DLT_MONITOR = 2001
SIG_COMPANY = 0x001958
JIELI_UUID = bytes.fromhex(dev.JIELI_CUSTOM_SPP_UUID.replace("-", ""))  # recognised in SDP only; never contacted

CLASS_LABELS = {
    "standard": "قياسي",
    "extension": "امتداد موثّق من طرف ثالث",
    "vendor": "خاص بالمصنّع",
    "controller_vendor": "خاص بشريحة الحاسوب",
    "unknown": "غير معروف",
}
DIR_LABELS = {"tx": "الحاسوب ← السماعة", "rx": "السماعة ← الحاسوب", None: "—"}

PSM_NAMES = {0x0001: "SDP", 0x0003: "RFCOMM", 0x000F: "BNEP", 0x0011: "HID Control", 0x0013: "HID Interrupt",
             0x0017: "AVCTP", 0x0019: "AVDTP", 0x001B: "AVCTP Browsing", 0x001F: "ATT", 0x0027: "EATT"}

HCI_COMMANDS = {
    0x0401: "Inquiry", 0x0405: "Create Connection", 0x0406: "Disconnect", 0x0409: "Accept Connection Request",
    0x040B: "Link Key Request Reply", 0x040C: "Link Key Request Negative Reply", 0x040D: "PIN Code Request Reply",
    0x0411: "Authentication Requested", 0x0413: "Set Connection Encryption", 0x0419: "Remote Name Request",
    0x041B: "Read Remote Supported Features", 0x041C: "Read Remote Extended Features",
    0x041D: "Read Remote Version Information", 0x0428: "Setup Synchronous Connection",
    0x0429: "Accept Synchronous Connection Request", 0x042B: "IO Capability Request Reply",
    0x042C: "User Confirmation Request Reply", 0x0803: "Sniff Mode", 0x0804: "Exit Sniff Mode",
    0x080B: "Switch Role", 0x080D: "Write Link Policy Settings", 0x0C03: "Reset", 0x0C1A: "Write Scan Enable",
    0x1001: "Read Local Version Information", 0x1009: "Read BD_ADDR", 0x1408: "Read Encryption Key Size",
}
HCI_EVENTS = {
    0x01: "Inquiry Complete", 0x03: "Connection Complete", 0x04: "Connection Request", 0x05: "Disconnection Complete",
    0x06: "Authentication Complete", 0x07: "Remote Name Request Complete", 0x08: "Encryption Change",
    0x0B: "Read Remote Supported Features Complete", 0x0C: "Read Remote Version Information Complete",
    0x0E: "Command Complete", 0x0F: "Command Status", 0x12: "Role Change", 0x13: "Number of Completed Packets",
    0x14: "Mode Change", 0x16: "PIN Code Request", 0x17: "Link Key Request", 0x18: "Link Key Notification",
    0x1B: "Max Slots Change", 0x23: "Read Remote Extended Features Complete", 0x2C: "Synchronous Connection Complete",
    0x2F: "Extended Inquiry Result", 0x31: "IO Capability Request", 0x32: "IO Capability Response",
    0x33: "User Confirmation Request", 0x36: "Simple Pairing Complete", 0x3E: "LE Meta", 0xFF: "Vendor Specific",
}
NOISE_EVENTS = {0x13}

AVCTP_CTYPES = {0x0: "CONTROL", 0x1: "STATUS", 0x2: "SPECIFIC_INQUIRY", 0x3: "NOTIFY", 0x4: "GENERAL_INQUIRY",
                0x8: "NOT_IMPLEMENTED", 0x9: "ACCEPTED", 0xA: "REJECTED", 0xB: "IN_TRANSITION", 0xC: "STABLE",
                0xD: "CHANGED", 0xF: "INTERIM"}
PASSTHROUGH_OPS = {
    0x00: "SELECT", 0x01: "UP", 0x02: "DOWN", 0x03: "LEFT", 0x04: "RIGHT", 0x09: "ROOT_MENU", 0x0D: "EXIT",
    0x40: "POWER", 0x41: "VOLUME_UP", 0x42: "VOLUME_DOWN", 0x43: "MUTE", 0x44: "PLAY", 0x45: "STOP", 0x46: "PAUSE",
    0x47: "RECORD", 0x48: "REWIND", 0x49: "FAST_FORWARD", 0x4A: "EJECT", 0x4B: "FORWARD", 0x4C: "BACKWARD",
    0x7E: "VENDOR_UNIQUE",
}
PASSTHROUGH_AR = {"PLAY": "تشغيل", "PAUSE": "إيقاف مؤقت", "STOP": "إيقاف", "FORWARD": "التالي", "BACKWARD": "السابق",
                  "VOLUME_UP": "رفع الصوت", "VOLUME_DOWN": "خفض الصوت", "MUTE": "كتم الصوت", "POWER": "الطاقة",
                  "FAST_FORWARD": "تقديم سريع", "REWIND": "ترجيع"}
AVRCP_PDUS = {
    0x10: "GetCapabilities", 0x11: "ListPlayerApplicationSettingAttributes", 0x12: "ListPlayerApplicationSettingValues",
    0x13: "GetCurrentPlayerApplicationSettingValue", 0x14: "SetPlayerApplicationSettingValue",
    0x15: "GetPlayerApplicationSettingAttributeText", 0x16: "GetPlayerApplicationSettingValueText",
    0x17: "InformDisplayableCharacterSet", 0x18: "InformBatteryStatusOfCT", 0x20: "GetElementAttributes",
    0x30: "GetPlayStatus", 0x31: "RegisterNotification", 0x40: "RequestContinuingResponse",
    0x41: "AbortContinuingResponse", 0x50: "SetAbsoluteVolume", 0x60: "SetAddressedPlayer", 0x74: "PlayItem",
    0x90: "AddToNowPlaying",
}
AVRCP_EVENTS = {
    0x01: "PLAYBACK_STATUS_CHANGED", 0x02: "TRACK_CHANGED", 0x03: "TRACK_REACHED_END", 0x04: "TRACK_REACHED_START",
    0x05: "PLAYBACK_POS_CHANGED", 0x06: "BATT_STATUS_CHANGED", 0x07: "SYSTEM_STATUS_CHANGED",
    0x08: "PLAYER_APPLICATION_SETTING_CHANGED", 0x09: "NOW_PLAYING_CONTENT_CHANGED", 0x0A: "AVAILABLE_PLAYERS_CHANGED",
    0x0B: "ADDRESSED_PLAYER_CHANGED", 0x0C: "UIDS_CHANGED", 0x0D: "VOLUME_CHANGED",
}
PLAY_STATUS = {0: "STOPPED", 1: "PLAYING", 2: "PAUSED", 3: "FWD_SEEK", 4: "REV_SEEK", 0xFF: "ERROR"}
BATT_STATUS = {0: "NORMAL", 1: "WARNING", 2: "CRITICAL", 3: "EXTERNAL", 4: "FULL_CHARGE"}
AVDTP_SIGNALS = {0x01: "DISCOVER", 0x02: "GET_CAPABILITIES", 0x03: "SET_CONFIGURATION", 0x04: "GET_CONFIGURATION",
                 0x05: "RECONFIGURE", 0x06: "OPEN", 0x07: "START", 0x08: "CLOSE", 0x09: "SUSPEND", 0x0A: "ABORT",
                 0x0B: "SECURITY_CONTROL", 0x0C: "GET_ALL_CAPABILITIES", 0x0D: "DELAYREPORT"}
AVDTP_MSG = {0: "Command", 1: "General Reject", 2: "Accept", 3: "Reject"}
CODECS = {0x00: "SBC", 0x01: "MPEG-1,2 Audio", 0x02: "AAC", 0x04: "ATRAC", 0xFF: "Vendor codec"}
SDP_PDUS = {1: "ErrorResponse", 2: "ServiceSearchRequest", 3: "ServiceSearchResponse",
            4: "ServiceAttributeRequest", 5: "ServiceAttributeResponse",
            6: "ServiceSearchAttributeRequest", 7: "ServiceSearchAttributeResponse"}
L2CAP_SIG = {0x01: "Command Reject", 0x02: "Connection Request", 0x03: "Connection Response",
             0x04: "Configure Request", 0x05: "Configure Response", 0x06: "Disconnection Request",
             0x07: "Disconnection Response", 0x08: "Echo Request", 0x09: "Echo Response",
             0x0A: "Information Request", 0x0B: "Information Response"}
RFCOMM_FRAMES = {0x2F: "SABM", 0x63: "UA", 0x0F: "DM", 0x43: "DISC", 0xEF: "UIH"}
RFCOMM_MCC = {0x20: "PN", 0x08: "Test", 0x28: "FCon", 0x18: "FCoff", 0x38: "MSC", 0x04: "NSC", 0x24: "RPN", 0x14: "RLS"}
HID_TYPES = {0x0: "HANDSHAKE", 0x1: "HID_CONTROL", 0x4: "GET_REPORT", 0x5: "SET_REPORT", 0x6: "GET_PROTOCOL",
             0x7: "SET_PROTOCOL", 0xA: "DATA"}
ATT_OPS = {0x01: "Error Response", 0x02: "Exchange MTU Request", 0x03: "Exchange MTU Response",
           0x04: "Find Information Request", 0x05: "Find Information Response", 0x08: "Read By Type Request",
           0x09: "Read By Type Response", 0x0A: "Read Request", 0x0B: "Read Response",
           0x10: "Read By Group Type Request", 0x11: "Read By Group Type Response", 0x12: "Write Request",
           0x13: "Write Response", 0x1B: "Handle Value Notification", 0x1D: "Handle Value Indication",
           0x1E: "Handle Value Confirmation", 0x52: "Write Command"}


@dataclass
class Packet:
    seq: int
    ts: float                     # unix time (seconds)
    hci: str                      # CMD | EVT | ACL | SCO | ISO
    direction: str | None         # tx (host->controller/remote) | rx
    protocol: str
    summary: str                  # Arabic, human readable
    classification: str = "standard"
    handle: int | None = None
    address: str | None = None
    cid: int | None = None
    psm: int | None = None
    channel: str | None = None    # e.g. "AVCTP (PSM 0x17, CID 0x0045)"
    opcode: str | None = None
    raw: str = ""                 # hex of the protocol payload (masked if sensitive)
    fields: dict = field(default_factory=dict)
    media: bool = False
    noise: bool = False

    def to_json(self) -> dict:
        return {
            "seq": self.seq, "ts": self.ts, "hci": self.hci, "direction": self.direction,
            "direction_label": DIR_LABELS.get(self.direction, "—"), "protocol": self.protocol,
            "summary": self.summary, "classification": self.classification,
            "classification_label": CLASS_LABELS[self.classification], "handle": self.handle,
            "address": self.address, "cid": self.cid, "psm": self.psm, "channel": self.channel,
            "opcode": self.opcode, "raw": self.raw, "fields": self.fields,
        }


def hexs(b: bytes, limit: int = 96) -> str:
    s = b[:limit].hex(" ")
    return s + (" …" if len(b) > limit else "")


def bdaddr(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in reversed(b[:6]))


def uuid_str(b: bytes) -> str:
    if len(b) == 2:
        return f"0000{b.hex()}-0000-1000-8000-00805f9b34fb"
    if len(b) == 4:
        return f"{b.hex()}-0000-1000-8000-00805f9b34fb"
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ============================================================ SDP data elements
def parse_de(buf: bytes, pos: int = 0):
    """Parse one SDP data element. Returns (value, next_pos). Values: ('uint', n), ('uuid', str), ..."""
    d = buf[pos]
    typ, sz = d >> 3, d & 7
    pos += 1
    if typ == 0:
        return ("nil", None), pos
    if sz < 5:
        n = (1, 2, 4, 8, 16)[sz]
    else:
        lb = (1, 2, 4)[sz - 5]
        n = int.from_bytes(buf[pos:pos + lb], "big")
        pos += lb
    data = buf[pos:pos + n]
    pos += n
    if typ == 1:
        return ("uint", int.from_bytes(data, "big")), pos
    if typ == 2:
        return ("int", int.from_bytes(data, "big", signed=True)), pos
    if typ == 3:
        return ("uuid", uuid_str(data)), pos
    if typ in (4, 8):
        return ("text", data), pos
    if typ == 5:
        return ("bool", bool(data[0]) if data else False), pos
    if typ in (6, 7):
        items, p = [], 0
        while p < len(data):
            v, p = parse_de(data, p)
            items.append(v)
        return ("seq", items), pos
    return ("unknown", data), pos


def short_uuid(u: str) -> str:
    return u[4:8] if u.endswith("-0000-1000-8000-00805f9b34fb") and u.startswith("0000") else u


def interpret_record(attrs: dict[int, tuple]) -> dict:
    """Turn SDP attributes into a service description (shared with the sdptool XML parser)."""
    svc: dict = {"handle": None, "classes": [], "protocols": [], "l2cap_psm": None, "rfcomm_channel": None,
                 "profiles": [], "name": None, "features": None, "hid_descriptor": None, "extra": {}}
    for aid, (t, v) in attrs.items():
        if aid == 0x0000 and t == "uint":
            svc["handle"] = v
        elif aid == 0x0001 and t == "seq":
            svc["classes"] = [x[1] for x in v if x[0] == "uuid"]
        elif aid == 0x0004 and t == "seq":
            for proto in v:
                if proto[0] != "seq" or not proto[1] or proto[1][0][0] != "uuid":
                    continue
                pu = proto[1][0][1]
                params = [x[1] for x in proto[1][1:] if x[0] == "uint"]
                svc["protocols"].append({"uuid": pu, "short": short_uuid(pu), "params": params})
                if short_uuid(pu) == "0100" and params:
                    svc["l2cap_psm"] = params[0]
                if short_uuid(pu) == "0003" and params:
                    svc["rfcomm_channel"] = params[0]
        elif aid == 0x0009 and t == "seq":
            for p in v:
                if p[0] == "seq" and len(p[1]) >= 2 and p[1][0][0] == "uuid":
                    svc["profiles"].append({"uuid": p[1][0][1], "version": p[1][1][1]})
        elif aid == 0x0100 and t == "text":
            svc["name"] = v.decode("utf-8", "replace").rstrip("\x00")
        elif aid == 0x0311 and t == "uint":
            svc["features"] = v
        elif aid == 0x0206 and t == "seq":
            for d in v:
                if d[0] == "seq" and len(d[1]) >= 2 and d[1][1][0] == "text":
                    svc["hid_descriptor"] = d[1][1][1].hex()
        elif aid in (0x0200, 0x0201, 0x0202, 0x0203, 0x0205) and t == "uint":
            svc["extra"][f"0x{aid:04X}"] = v
    return svc


def parse_attribute_lists(blob: bytes) -> list[dict]:
    """Parse the AttributeLists of an SDP ServiceSearchAttributeResponse."""
    (t, seq), _ = parse_de(blob, 0)
    records = []
    for rec in seq if t == "seq" else []:
        if rec[0] != "seq":
            continue
        items = rec[1]
        attrs = {}
        for i in range(0, len(items) - 1, 2):
            if items[i][0] == "uint":
                attrs[items[i][1]] = items[i + 1]
        records.append(interpret_record(attrs))
    return records


# ============================================================ decoder
class Decoder:
    """Stateful decoder for one btsnoop stream."""

    def __init__(self, target_address: str | None = None, on_services: Callable[[list[dict]], None] | None = None):
        self.target = target_address.upper() if target_address else None
        self.seq = 0
        self.handles: dict[int, dict] = {}
        self.pending: dict[tuple, tuple] = {}
        self.frags: dict[tuple, bytearray] = {}
        self.sdp_parts: dict[tuple, bytearray] = {}
        self.services: list[dict] = []
        self.rfcomm_roles = {4: "HFP", 1: "SPP", 10: "JieLi"}  # from the capture; updated from SDP when seen
        self.on_services = on_services
        self.stats = {"records": 0, "media": 0, "noise": 0, "packets": 0}

    # -- per-handle state
    def _h(self, handle: int) -> dict:
        return self.handles.setdefault(handle, {"address": None, "rx": {}, "tx": {}, "avdtp": 0, "media_cids": set()})

    def _pkt(self, **kw) -> Packet:
        self.seq += 1
        return Packet(seq=self.seq, **kw)

    def feed(self, datalink: int, flags: int, ts_us: int, data: bytes) -> Packet | None:
        self.stats["records"] += 1
        ts = (ts_us - BTSNOOP_EPOCH_US) / 1e6
        if datalink == DLT_MONITOR:
            op = flags & 0xFFFF
            kind = {2: ("CMD", "tx"), 3: ("EVT", "rx"), 4: ("ACL", "tx"), 5: ("ACL", "rx"),
                    6: ("SCO", "tx"), 7: ("SCO", "rx"), 18: ("ISO", "tx"), 19: ("ISO", "rx")}.get(op)
            if kind is None:
                return None
            body = data
        elif datalink == DLT_H4:
            if not data:
                return None
            kind = {1: ("CMD", "tx"), 2: ("ACL", None), 3: ("SCO", None), 4: ("EVT", "rx"), 5: ("ISO", None)}.get(data[0])
            if kind is None:
                return None
            kind = (kind[0], kind[1] or ("rx" if flags & 1 else "tx"))
            body = data[1:]
        else:
            return None
        try:
            if kind[0] == "CMD":
                p = self._cmd(ts, body)
            elif kind[0] == "EVT":
                p = self._evt(ts, body)
            elif kind[0] == "ACL":
                p = self._acl(ts, kind[1], body)
            else:
                p = self._pkt(ts=ts, hci=kind[0], direction=kind[1], protocol=kind[0], summary="صوت متزامن (SCO/ISO)",
                              media=True, raw="")
        except (IndexError, struct.error, ValueError) as exc:
            p = self._pkt(ts=ts, hci=kind[0], direction=kind[1], protocol="?", summary=f"تعذر فك الحزمة ({exc})",
                          classification="unknown", raw=hexs(body))
        if p is None:
            return None
        if p.media:
            self.stats["media"] += 1
        elif p.noise:
            self.stats["noise"] += 1
        else:
            self.stats["packets"] += 1
        return p

    # -- HCI
    def _cmd(self, ts, b):
        opcode, plen = struct.unpack_from("<HB", b)
        params = bytearray(b[3:3 + plen])
        name = HCI_COMMANDS.get(opcode)
        ogf = opcode >> 10
        cls = "controller_vendor" if ogf == 0x3F else "standard"
        masked = False
        if opcode in (0x040B, 0x040D) and len(params) > 6:
            params[6:] = b"\x00" * (len(params) - 6)
            masked = True
        label = name or f"OGF 0x{ogf:02X} OCF 0x{opcode & 0x3FF:03X}"
        summary = f"أمر HCI: {label}"
        if cls == "controller_vendor":
            summary = f"أمر HCI خاص بشريحة الحاسوب (0x{opcode:04X})"
        raw = hexs(bytes(params)) + (" [المفتاح مخفي]" if masked else "")
        handle = struct.unpack_from("<H", params)[0] & 0x0FFF if opcode in (0x0406, 0x0411, 0x0413, 0x041B, 0x041C, 0x0803, 0x0804, 0x1408) and len(params) >= 2 else None
        return self._pkt(ts=ts, hci="CMD", direction="tx", protocol="HCI", opcode=f"0x{opcode:04X} {label}",
                         summary=summary, classification=cls, raw=raw, handle=handle,
                         address=self.handles.get(handle, {}).get("address") if handle is not None else None)

    def _evt(self, ts, b):
        code, plen = b[0], b[1]
        p = bytearray(b[2:2 + plen])
        name = HCI_EVENTS.get(code, f"Event 0x{code:02X}")
        summary = f"حدث HCI: {name}"
        cls = "controller_vendor" if code == 0xFF else "standard"
        handle = None
        fields: dict = {}
        masked = False
        if code == 0x03 and len(p) >= 9:
            status, handle = p[0], struct.unpack_from("<H", p, 1)[0] & 0x0FFF
            addr = bdaddr(p[3:9])
            if status == 0:
                self.handles[handle] = {"address": addr, "rx": {}, "tx": {}, "avdtp": 0, "media_cids": set()}
            summary = f"اكتمل الاتصال بـ {addr} (handle {handle})" if status == 0 else f"فشل الاتصال بـ {addr} (0x{status:02X})"
            fields = {"address": addr, "status": status}
        elif code == 0x05 and len(p) >= 4:
            handle = struct.unpack_from("<H", p, 1)[0] & 0x0FFF
            summary = f"انقطع الاتصال (handle {handle}، السبب 0x{p[3]:02X})"
            fields = {"reason": p[3]}
        elif code in (0x0E, 0x0F) and len(p) >= 3:
            op = struct.unpack_from("<H", p, 1 if code == 0x0E else 2)[0]
            summary = f"{'اكتمل' if code == 0x0E else 'حالة'} أمر HCI: {HCI_COMMANDS.get(op, f'0x{op:04X}')}"
        elif code == 0x14 and len(p) >= 6:
            handle = struct.unpack_from("<H", p, 1)[0] & 0x0FFF
            mode = {0: "نشط", 1: "Hold", 2: "Sniff", 3: "Park"}.get(p[3], str(p[3]))
            interval = struct.unpack_from("<H", p, 4)[0] * 0.625
            summary = f"تغير وضع الطاقة: {mode}" + (f" ({interval:.0f} ms)" if p[3] == 2 else "")
        elif code == 0x18 and len(p) >= 22:
            p[6:22] = b"\x00" * 16
            masked = True
        elif code == 0x3E and p:
            sub = p[0]
            summary = f"حدث LE (subevent 0x{sub:02X})"
            if sub in (0x01, 0x0A) and len(p) >= 12:
                handle = struct.unpack_from("<H", p, 2)[0] & 0x0FFF
                addr = bdaddr(p[6:12])
                if p[1] == 0:
                    self.handles[handle] = {"address": addr, "rx": {}, "tx": {}, "avdtp": 0, "media_cids": set()}
                summary = f"اتصال LE مع {addr}"
        elif code in (0x06, 0x08, 0x0B, 0x1B, 0x23) and len(p) >= 3:
            handle = struct.unpack_from("<H", p, 1)[0] & 0x0FFF
        if code == 0xFF:
            summary = "حدث HCI خاص بشريحة الحاسوب"
        return self._pkt(ts=ts, hci="EVT", direction="rx", protocol="HCI", opcode=f"0x{code:02X} {name}", summary=summary,
                         classification=cls, raw=hexs(bytes(p)) + (" [المفتاح مخفي]" if masked else ""), handle=handle,
                         address=self.handles.get(handle, {}).get("address") if handle is not None else None,
                         fields=fields, noise=code in NOISE_EVENTS)

    # -- ACL / L2CAP
    def _acl(self, ts, direction, b):
        hdr, dlen = struct.unpack_from("<HH", b)
        handle, pb = hdr & 0x0FFF, (hdr >> 12) & 3
        data = b[4:4 + dlen]
        key = (handle, direction)
        if pb == 1:  # continuation
            buf = self.frags.get(key)
            if buf is None:
                return None
            buf += data
        else:
            buf = bytearray(data)
            self.frags[key] = buf
        if len(buf) < 4:
            return None
        l2len = struct.unpack_from("<H", buf)[0]
        if len(buf) < l2len + 4:
            return None  # wait for more fragments
        self.frags.pop(key, None)
        cid = struct.unpack_from("<H", buf, 2)[0]
        payload = bytes(buf[4:4 + l2len])
        return self._l2cap(ts, direction, handle, cid, payload)

    def _l2cap(self, ts, direction, handle, cid, payload):
        st = self._h(handle)
        addr = st["address"]
        base = dict(ts=ts, hci="ACL", direction=direction, handle=handle, address=addr, cid=cid)
        if cid == 0x0001:
            return self._l2sig(base, st, direction, payload)
        if cid == 0x0004:
            return self._att(base, payload, 0x001F)
        if cid in (0x0005, 0x0006):
            return self._pkt(**base, protocol="LE" if cid == 5 else "SMP", channel=f"CID 0x{cid:04X}",
                             summary="إشارات LE" if cid == 5 else "SMP (إقران LE)", raw=hexs(payload))
        info = st[direction].get(cid)
        psm = info["psm"] if info else None
        role = info.get("role") if info else None
        chan = f"{PSM_NAMES.get(psm, f'PSM 0x{psm:04X}') if psm is not None else 'PSM غير معروف'} (CID 0x{cid:04X})"
        base.update(psm=psm, channel=chan)
        if psm == 0x0001:
            return self._sdp(base, handle, direction, payload)
        if psm == 0x0003:
            return self._rfcomm(base, payload)
        if psm == 0x0017:
            return self._avctp(base, payload)
        if psm == 0x001B:
            return self._pkt(**base, protocol="AVRCP Browsing", opcode=f"PDU 0x{payload[3]:02X}" if len(payload) > 3 else None,
                             summary="AVRCP: قناة التصفح", raw=hexs(payload))
        if psm == 0x0019:
            if role == "media":
                return self._pkt(**base, protocol="A2DP media", summary="حزمة وسائط A2DP (RTP)", raw=hexs(payload, 16), media=True)
            return self._avdtp(base, payload)
        if psm in (0x0011, 0x0013):
            return self._hid(base, payload, psm)
        if psm == 0x001F:
            return self._att(base, payload, psm)
        return self._pkt(**base, protocol="L2CAP", summary=f"بيانات L2CAP على قناة غير معروفة ({len(payload)} بايت)",
                         classification="unknown", raw=hexs(payload))

    def _l2sig(self, base, st, direction, p):
        cmds = []
        pos = 0
        while pos + 4 <= len(p):
            code, ident, ln = struct.unpack_from("<BBH", p, pos)
            data = p[pos + 4:pos + 4 + ln]
            pos += 4 + ln
            name = L2CAP_SIG.get(code, f"0x{code:02X}")
            text = name
            if code == 0x02 and len(data) >= 4:
                psm, scid = struct.unpack_from("<HH", data)
                self.pending[(base["handle"], direction, ident)] = (psm, scid)
                text = f"طلب فتح قناة {PSM_NAMES.get(psm, f'PSM 0x{psm:04X}')} (PSM 0x{psm:04X})"
            elif code == 0x03 and len(data) >= 8:
                dcid, scid, result = struct.unpack_from("<HHH", data)
                req_dir = "rx" if direction == "tx" else "tx"
                req = self.pending.pop((base["handle"], req_dir, ident), None)
                if req and result == 0:
                    psm, req_cid = req
                    role = None
                    if psm == 0x0019:
                        role = "signaling" if st["avdtp"] % 2 == 0 else "media"
                        st["avdtp"] += 1
                    info = {"psm": psm, "role": role}
                    # packets to the requester are addressed to req_cid, to the responder to dcid
                    to_requester = "rx" if req_dir == "tx" else "tx"
                    st[to_requester][req_cid] = info
                    st[req_dir][dcid] = info
                elif req and result == 1:
                    self.pending[(base["handle"], req_dir, ident)] = req  # pending: keep waiting
                text = {0: "تم فتح القناة", 1: "القناة قيد الانتظار", 2: "PSM غير مدعوم", 3: "رُفض: حماية",
                        4: "رُفض: لا موارد"}.get(result, f"النتيجة 0x{result:04X}")
                text = f"رد فتح القناة: {text}"
            elif code == 0x06 and len(data) >= 4:
                text = "طلب إغلاق قناة"
            elif code == 0x07:
                text = "تم إغلاق القناة"
            cmds.append(text)
        return self._pkt(**base, protocol="L2CAP", channel="L2CAP signaling (CID 0x0001)",
                         opcode=L2CAP_SIG.get(p[0], "?") if p else None, summary="L2CAP: " + "؛ ".join(cmds),
                         raw=hexs(p))

    # -- SDP
    def _sdp(self, base, handle, direction, p):
        pdu, tid, plen = struct.unpack_from(">BHH", p)
        name = SDP_PDUS.get(pdu, f"0x{pdu:02X}")
        summary = f"SDP: {name}"
        fields = {}
        if pdu == 0x07 and len(p) >= 7:
            cnt = struct.unpack_from(">H", p, 5)[0]
            chunk = p[7:7 + cnt]
            cont = p[7 + cnt:]
            key = (handle, direction)
            buf = self.sdp_parts.setdefault(key, bytearray())
            buf += chunk
            if not cont or cont[0] == 0:
                blob = bytes(self.sdp_parts.pop(key))
                try:
                    recs = parse_attribute_lists(blob)
                except (IndexError, ValueError):
                    recs = []
                if recs:
                    self._learn_services(recs)
                    fields["services"] = recs
                    summary = f"SDP: استجابة تتضمن {len(recs)} خدمة"
            else:
                summary = "SDP: استجابة جزئية (يتبعها المزيد)"
        elif pdu == 0x06:
            summary = "SDP: طلب بحث عن الخدمات وسماتها"
        return self._pkt(**base, protocol="SDP", opcode=f"0x{pdu:02X} {name}", summary=summary, raw=hexs(p), fields=fields)

    def _learn_services(self, recs):
        known = {r["handle"]: r for r in self.services}
        for r in recs:
            known[r["handle"]] = r
            if r["rfcomm_channel"] is not None:
                classes = [short_uuid(c) for c in r["classes"]]
                if JIELI_UUID.hex() in "".join(c.replace("-", "") for c in r["classes"]):
                    self.rfcomm_roles[r["rfcomm_channel"]] = "JieLi"
                elif "111e" in classes or "111f" in classes:
                    self.rfcomm_roles[r["rfcomm_channel"]] = "HFP"
                elif "1101" in classes:
                    self.rfcomm_roles[r["rfcomm_channel"]] = "SPP"
        self.services = list(known.values())
        if self.on_services:
            self.on_services(self.services)

    # -- RFCOMM
    def _rfcomm(self, base, p):
        addr, ctrl = p[0], p[1]
        dlci = addr >> 2
        ch = dlci >> 1
        ftype = ctrl & 0xEF
        fname = RFCOMM_FRAMES.get(ftype, f"0x{ftype:02X}")
        pos = 2
        if p[pos] & 1:
            length = p[pos] >> 1
            pos += 1
        else:
            length = (p[pos] >> 1) | (p[pos + 1] << 7)
            pos += 2
        credits = None
        if ftype == 0xEF and ctrl & 0x10 and dlci != 0:
            credits = p[pos]
            pos += 1
        data = p[pos:pos + length]
        role = self.rfcomm_roles.get(ch)
        chan = f"RFCOMM قناة {ch}" + (f" ({role})" if role else "") if dlci else "RFCOMM تحكم (DLCI 0)"
        base["channel"] = f"{chan} — {base['channel']}"
        fields = {"dlci": dlci, "server_channel": ch, "frame": fname}
        if dlci == 0:
            if ftype == 0xEF and data:
                mtype = data[0] & 0xFC
                summary = f"RFCOMM: رسالة تحكم {RFCOMM_MCC.get(mtype, hex(mtype))}"
            else:
                summary = f"RFCOMM: {fname} على قناة التحكم"
            return self._pkt(**base, protocol="RFCOMM", opcode=fname, summary=summary, raw=hexs(p), fields=fields)
        if ftype != 0xEF:
            action = {"SABM": "طلب فتح", "UA": "تأكيد", "DM": "رفض", "DISC": "طلب إغلاق"}.get(fname, fname)
            cls = "vendor" if role == "JieLi" else "standard"
            return self._pkt(**base, protocol="RFCOMM", opcode=fname, summary=f"RFCOMM: {action} القناة {ch}" + (f" ({role})" if role else ""),
                             classification=cls, raw=hexs(p), fields=fields)
        if not data:
            return self._pkt(**base, protocol="RFCOMM", opcode="UIH", summary=f"RFCOMM: منح أرصدة ({credits}) للقناة {ch}",
                             raw=hexs(p), fields=fields, noise=True)
        if role == "HFP":
            return self._hfp(base, data, fields, p)
        if role == "JieLi":
            fields["payload"] = data.hex(" ")
            return self._pkt(**base, protocol="JieLi (RFCOMM)", opcode=f"{len(data)} بايت",
                             summary=f"بيانات خدمة JieLi الخاصة — غير مفككة ({len(data)} بايت)",
                             classification="vendor", raw=hexs(data, 256), fields=fields)
        return self._pkt(**base, protocol="SPP" if role == "SPP" else "RFCOMM", opcode=f"{len(data)} بايت",
                         summary=f"بيانات تسلسلية على القناة {ch} ({len(data)} بايت) — محتوى يحدده التطبيق",
                         classification="vendor" if role == "SPP" else "unknown", raw=hexs(data, 256), fields=fields)

    def _hfp(self, base, data, fields, raw):
        text = data.decode("ascii", "replace").replace("\r", " ").replace("\n", " ").strip()
        meaning, cls = hfp_meaning(text)
        fields["at"] = text
        return self._pkt(**base, protocol="HFP", opcode=text.split("=")[0].split(":")[0][:24] or "AT",
                         summary=f"HFP: {text}" + (f" — {meaning}" if meaning else ""), classification=cls,
                         raw=hexs(data), fields=fields)

    # -- AVCTP / AVRCP
    def _avctp(self, base, p):
        hdr = p[0]
        label, ptype, cr = hdr >> 4, (hdr >> 2) & 3, (hdr >> 1) & 1
        if ptype != 0:
            return self._pkt(**base, protocol="AVCTP", opcode="fragment", summary="AVCTP: جزء من رسالة مجزأة",
                             raw=hexs(p))
        pid = struct.unpack_from(">H", p, 1)[0]
        av = p[3:]
        ctype, subunit, opcode = av[0] & 0x0F, av[1], av[2]
        cname = AVCTP_CTYPES.get(ctype, hex(ctype))
        role = "رد" if cr else "أمر"
        fields = {"label": label, "pid": f"0x{pid:04X}", "ctype": cname, "subunit": f"0x{subunit:02X}",
                  "response": bool(cr)}
        if pid != 0x110E:
            return self._pkt(**base, protocol="AVCTP", opcode=f"PID 0x{pid:04X}", summary=f"AVCTP لبروفايل آخر (PID 0x{pid:04X})",
                             classification="unknown", raw=hexs(p), fields=fields)
        if opcode == 0x7C:
            op = av[3]
            released = bool(op & 0x80)
            opid = op & 0x7F
            name = PASSTHROUGH_OPS.get(opid, f"0x{opid:02X}")
            state = "تحرير" if released else "ضغط"
            fields.update(operation=name, operation_id=f"0x{opid:02X}", released=released)
            cls = "standard"
            summary = f"AVRCP PASS THROUGH: {name} ({PASSTHROUGH_AR.get(name, name)}) — {state} [{role} {cname}]"
            if opid == 0x7E:
                cls = "vendor"
                opdata = av[5:5 + av[4]] if len(av) > 4 else b""
                if len(opdata) >= 3:
                    company = int.from_bytes(opdata[:3], "big")
                    fields["company_id"] = f"0x{company:06X}"
                    summary = f"AVRCP VENDOR_UNIQUE (شركة 0x{company:06X}) — {state} [{role}]"
            return self._pkt(**base, protocol="AVRCP", opcode=f"PASS THROUGH 0x{opid:02X} {name}", summary=summary,
                             classification=cls, raw=hexs(p), fields=fields)
        if opcode == 0x00:
            company = int.from_bytes(av[3:6], "big")
            fields["company_id"] = f"0x{company:06X}"
            if company != SIG_COMPANY:
                return self._pkt(**base, protocol="AVRCP", opcode=f"VENDOR DEPENDENT 0x{company:06X}",
                                 summary=f"AVRCP أمر خاص بشركة 0x{company:06X} [{role} {cname}]",
                                 classification="vendor", raw=hexs(p), fields=fields)
            pdu = av[6]
            params = av[10:10 + struct.unpack_from(">H", av, 8)[0]]
            pname = AVRCP_PDUS.get(pdu, f"0x{pdu:02X}")
            fields["pdu"] = pname
            detail = avrcp_detail(pdu, params, bool(cr), ctype, fields)
            return self._pkt(**base, protocol="AVRCP", opcode=f"0x{pdu:02X} {pname}",
                             summary=f"AVRCP: {pname} [{role} {cname}]" + (f" — {detail}" if detail else ""),
                             raw=hexs(p), fields=fields)
        oname = {0x30: "UNIT INFO", 0x31: "SUBUNIT INFO"}.get(opcode, f"0x{opcode:02X}")
        return self._pkt(**base, protocol="AV/C", opcode=oname, summary=f"AV/C: {oname} [{role} {cname}]", raw=hexs(p),
                         fields=fields)

    # -- AVDTP
    def _avdtp(self, base, p):
        hdr = p[0]
        label, ptype, mtype = hdr >> 4, (hdr >> 2) & 3, hdr & 3
        if ptype != 0:
            return self._pkt(**base, protocol="AVDTP", summary="AVDTP: رسالة مجزأة", raw=hexs(p))
        sig = p[1] & 0x3F
        name = AVDTP_SIGNALS.get(sig, f"0x{sig:02X}")
        body = p[2:]
        detail = ""
        fields = {"label": label, "message": AVDTP_MSG[mtype]}
        cls = "standard"
        if sig == 0x01 and mtype == 2:
            seps = []
            for i in range(0, len(body) - 1, 2):
                seps.append({"seid": body[i] >> 2, "in_use": bool(body[i] & 2), "media": body[i + 1] >> 4,
                             "type": "SNK" if body[i + 1] & 0x08 else "SRC"})
            fields["seps"] = seps
            detail = "، ".join(f"SEID {s['seid']} {s['type']}" for s in seps)
        elif sig in (0x02, 0x0C) and mtype == 2 or sig == 0x03 and mtype == 0:
            caps = body[2:] if sig == 0x03 else body
            codec = avdtp_codec(caps)
            if codec:
                fields["codec"] = codec
                detail = codec["name"]
                if codec["type"] == 0xFF:
                    cls = "extension"
        elif sig in (0x02, 0x0C, 0x06, 0x07, 0x08, 0x09) and mtype == 0 and body:
            detail = f"SEID {body[0] >> 2}"
        return self._pkt(**base, protocol="AVDTP", opcode=f"0x{sig:02X} {name}",
                         summary=f"AVDTP: {name} ({AVDTP_MSG[mtype]})" + (f" — {detail}" if detail else ""),
                         classification=cls, raw=hexs(p), fields=fields)

    # -- HID
    def _hid(self, base, p, psm):
        t, param = p[0] >> 4, p[0] & 0x0F
        name = HID_TYPES.get(t, f"0x{t:X}")
        fields = {"type": name}
        summary = f"HID: {name}"
        if t == 0xA and param == 1:
            decoded = hid.decode_input_report(hid.CAPTURED_FIELDS, p[1:])
            fields.update(decoded)
            keys = "، ".join(decoded["pressed"]) or "تحرير كل المفاتيح"
            summary = f"HID: تقرير إدخال (Report ID {decoded['report_id']}) — {keys}"
        return self._pkt(**base, protocol="HID", opcode=name, summary=summary, raw=hexs(p), fields=fields)

    # -- ATT
    def _att(self, base, p, psm):
        op = p[0] if p else 0
        name = ATT_OPS.get(op, f"0x{op:02X}")
        base.setdefault("channel", "ATT")
        base["psm"] = psm
        return self._pkt(**base, protocol="ATT (GATT)", opcode=f"0x{op:02X} {name}", summary=f"GATT: {name}", raw=hexs(p))


def avrcp_detail(pdu: int, params: bytes, response: bool, ctype: int, fields: dict) -> str:
    try:
        if pdu == 0x10:
            if response and len(params) >= 2 and params[0] == 3:
                evs = [AVRCP_EVENTS.get(e, hex(e)) for e in params[2:2 + params[1]]]
                fields["events"] = evs
                return "الأحداث المدعومة: " + "، ".join(evs)
            if response and len(params) >= 2 and params[0] == 2:
                ids = [f"0x{int.from_bytes(params[2 + 3 * i:5 + 3 * i], 'big'):06X}" for i in range(params[1])]
                fields["companies"] = ids
                return "معرّفات الشركات: " + "، ".join(ids)
            if params:
                return {2: "طلب معرّفات الشركات", 3: "طلب الأحداث المدعومة"}.get(params[0], "")
        if pdu == 0x31 and params:
            ev = AVRCP_EVENTS.get(params[0], hex(params[0]))
            fields["event"] = ev
            if not response:
                return f"تسجيل للحدث {ev}"
            val = params[1:]
            if params[0] == 0x0D and val:
                fields["volume"] = val[0] & 0x7F
                return f"{ev}: مستوى الصوت {val[0] & 0x7F}/127"
            if params[0] == 0x01 and val:
                return f"{ev}: {PLAY_STATUS.get(val[0], hex(val[0]))}"
            if params[0] == 0x06 and val:
                return f"{ev}: {BATT_STATUS.get(val[0], hex(val[0]))}"
            return ev
        if pdu == 0x50 and params:
            fields["volume"] = params[0] & 0x7F
            return f"مستوى الصوت {params[0] & 0x7F}/127"
        if pdu == 0x20 and not response:
            return "طلب معلومات المقطع الحالي"
        if pdu == 0x18 and params:
            return f"حالة بطارية وحدة التحكم: {BATT_STATUS.get(params[0], hex(params[0]))}"
    except IndexError:
        return ""
    return ""


def avdtp_codec(caps: bytes) -> dict | None:
    pos = 0
    while pos + 2 <= len(caps):
        cat, ln = caps[pos], caps[pos + 1]
        data = caps[pos + 2:pos + 2 + ln]
        if cat == 0x07 and len(data) >= 2:
            ctype = data[1]
            info = {"type": ctype, "name": CODECS.get(ctype, f"0x{ctype:02X}"), "raw": data.hex()}
            if ctype == 0xFF and len(data) >= 8:
                vid, cid = struct.unpack_from("<IH", data, 2)
                info["name"] = f"Vendor codec (vendor 0x{vid:08X}, codec 0x{cid:04X})"
            return info
        pos += 2 + ln
    return None


def hfp_meaning(text: str) -> tuple[str, str]:
    t = text.upper()
    if t.startswith("AT+IPHONEACCEV="):
        try:
            vals = [int(x) for x in text.split("=", 1)[1].split(",")]
            for i in range(1, len(vals) - 1, 2):
                if vals[i] == 1:
                    return f"امتداد Apple: البطارية {(vals[i + 1] + 1) * 10}%", "extension"
        except ValueError:
            pass
        return "امتداد Apple لحالة الملحق", "extension"
    if t.startswith("AT+XAPL"):
        return "امتداد Apple: تعريف الملحق وميزاته", "extension"
    if t.startswith("+XAPL"):
        return "رد امتداد Apple", "extension"
    table = {
        "AT+BRSF": "تبادل ميزات HFP", "AT+BAC": "الترميزات المدعومة", "AT+CIND": "مؤشرات الهاتف",
        "AT+CMER": "تفعيل تقارير المؤشرات", "AT+CHLD": "المكالمات المتعددة", "AT+BCS": "تأكيد الترميز",
        "AT+CMEE": "تفعيل رموز الأخطاء", "AT+CLIP": "إظهار رقم المتصل", "AT+CCWA": "انتظار المكالمات",
        "AT+NREC": "إلغاء الصدى", "AT+VGS": "مستوى صوت المكالمة", "AT+VGM": "مستوى الميكروفون",
        "AT+BVRA": "المساعد الصوتي", "ATA": "الرد على المكالمة", "AT+CHUP": "إنهاء المكالمة", "AT+BLDN": "إعادة الاتصال بآخر رقم",
        "AT+BIEV": "مؤشر HF (قد يكون البطارية)", "AT+BIND": "مؤشرات HF", "AT+CGMI": "استعلام الشركة المصنعة للهاتف",
        "+CIEV": "تحديث مؤشر", "+BCS": "اختيار الترميز", "+VGS": "ضبط مستوى صوت المكالمة", "OK": "تم", "ERROR": "خطأ",
        "+CME ERROR": "خطأ", "RING": "مكالمة واردة",
    }
    for k, v in table.items():
        if t.startswith(k):
            return v, "standard"
    return "", "standard"


# ============================================================ file reading
class BtsnoopReader:
    """Incremental btsnoop parser: feed bytes, get (flags, ts_us, data) records."""

    def __init__(self):
        self.buf = bytearray()
        self.datalink: int | None = None

    def feed(self, chunk: bytes):
        self.buf += chunk
        out = []
        if self.datalink is None:
            if len(self.buf) < 16:
                return out
            if bytes(self.buf[:8]) != BTSNOOP_MAGIC:
                raise ValueError("ليس ملف btsnoop")
            self.datalink = struct.unpack_from(">I", self.buf, 12)[0]
            if self.datalink not in (DLT_MONITOR, DLT_H4):
                raise ValueError(f"نوع الالتقاط غير مدعوم ({self.datalink})")
            del self.buf[:16]
        while len(self.buf) >= 24:
            _, ilen, flags, _, ts = struct.unpack_from(">IIIIq", self.buf)
            if len(self.buf) < 24 + ilen:
                break
            out.append((flags, ts, bytes(self.buf[24:24 + ilen])))
            del self.buf[:24 + ilen]
        return out


def analyze_bytes(data: bytes, target: str | None = None, limit: int = 5000) -> dict:
    """Decode a whole btsnoop file (used for uploaded captures). Read-only."""
    reader = BtsnoopReader()
    dec = Decoder(target)
    packets = []
    for flags, ts, rec in reader.feed(data):
        p = dec.feed(reader.datalink, flags, ts, rec)
        if p and not p.media and not p.noise:
            packets.append(p)
    addrs = {h["address"] for h in dec.handles.values() if h["address"]}
    if target and target.upper() in addrs:
        tgt_handles = {h for h, s in dec.handles.items() if s["address"] == target.upper()}
        packets = [p for p in packets if p.handle is None or p.handle in tgt_handles or p.hci != "ACL"]
    return {
        "datalink": reader.datalink, "stats": dict(dec.stats), "devices": sorted(addrs),
        "services": dec.services, "rfcomm_roles": {str(k): v for k, v in dec.rfcomm_roles.items()},
        "summary": summarize_packets(packets),
        "packets": [p.to_json() for p in packets[-limit:]],
        "truncated": len(packets) > limit,
    }


def summarize_packets(packets: list[Packet]) -> dict:
    by_proto: dict[str, int] = {}
    by_class: dict[str, int] = {}
    passthrough: dict[str, int] = {}
    avrcp_pdus: dict[str, int] = {}
    events: set[str] = set()
    vendor: list[dict] = []
    for p in packets:
        by_proto[p.protocol] = by_proto.get(p.protocol, 0) + 1
        by_class[p.classification] = by_class.get(p.classification, 0) + 1
        f = p.fields
        if p.protocol == "AVRCP":
            if "operation" in f and not f.get("released") and not f.get("response"):
                k = f"{f['operation']} ({'السماعة' if p.direction == 'rx' else 'الحاسوب'})"
                passthrough[k] = passthrough.get(k, 0) + 1
            if "pdu" in f:
                avrcp_pdus[f["pdu"]] = avrcp_pdus.get(f["pdu"], 0) + 1
            if "event" in f:
                events.add(f["event"])
            for e in f.get("events", []):
                events.add(e)
        if p.classification == "vendor" and len(vendor) < 200:
            vendor.append(p.to_json())
    return {"by_protocol": by_proto, "by_classification": by_class, "passthrough": passthrough,
            "avrcp_pdus": avrcp_pdus, "avrcp_events": sorted(events), "vendor_packets": vendor}


class CaptureTail:
    """Follows a btsnoop file being written by ``btmon -w``. Read-only."""

    def __init__(self, path: str, target: str, on_packet: Callable[[Packet], None],
                 on_services: Callable[[list[dict]], None] | None = None, buffer: int = 4000):
        self.path = path
        self.target = target.upper()
        self.on_packet = on_packet
        self.on_services = on_services
        self.recent: deque[Packet] = deque(maxlen=buffer)
        self.decoder: Decoder | None = None
        self.reader: BtsnoopReader | None = None
        self.pos = 0
        self.inode = None
        self.error: str | None = None
        self.last_packet_ts: float | None = None
        self._task: asyncio.Task | None = None

    def status(self) -> dict:
        exists = os.path.exists(self.path)
        return {
            "path": self.path, "exists": exists, "active": bool(self._task and not self._task.done()) and exists and self.error is None,
            "error": self.error, "datalink": self.reader.datalink if self.reader else None,
            "stats": dict(self.decoder.stats) if self.decoder else None,
            "last_packet_ts": self.last_packet_ts,
            "target_handles": sorted(h for h, s in (self.decoder.handles.items() if self.decoder else []) if s["address"] == self.target),
            "services_seen": len(self.decoder.services) if self.decoder else 0,
        }

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except BaseException:
                pass

    def _reset(self):
        self.decoder = Decoder(self.target, self.on_services)
        self.reader = BtsnoopReader()
        self.pos = 0

    def _relevant(self, p: Packet) -> bool:
        if p.media or p.noise:
            return False
        tgt = [h for h, s in self.decoder.handles.items() if s["address"] == self.target]
        if p.handle is None:
            return p.classification != "standard" or "Create Connection" in (p.opcode or "")
        return not tgt or p.handle in tgt

    async def _run(self):
        self._reset()
        while True:
            try:
                st = os.stat(self.path)
                if self.inode != st.st_ino or st.st_size < self.pos:
                    self.inode = st.st_ino
                    self._reset()
                if st.st_size > self.pos:
                    with open(self.path, "rb") as f:
                        f.seek(self.pos)
                        chunk = f.read(min(st.st_size - self.pos, 4 << 20))
                    self.pos += len(chunk)
                    for flags, ts, rec in self.reader.feed(chunk):
                        p = self.decoder.feed(self.reader.datalink, flags, ts, rec)
                        if p and self._relevant(p):
                            self.recent.append(p)
                            self.last_packet_ts = p.ts
                            self.on_packet(p)
                    self.error = None
                    if st.st_size > self.pos:
                        await asyncio.sleep(0)
                        continue
            except FileNotFoundError:
                self.error = None
            except PermissionError:
                self.error = "permission_denied"
            except ValueError as exc:
                self.error = str(exc)
            except Exception:
                log.exception("capture tail failed")
                self.error = "internal"
            await asyncio.sleep(0.25)

    def window(self, start: float, end: float) -> list[Packet]:
        return [p for p in self.recent if start <= p.ts <= end]
