"""TEST-ONLY: write synthetic btsnoop (btmon monitor format) records.

Used to exercise the passive decoder, the live capture tail and the research
mode without hardware. Packet layouts follow the real capture (report §20).
"""
import struct
import time

EPOCH = 0x00DCDDB30F2F8000
ADDR = "28:52:E0:0F:92:0A"
H = 0x0100  # ACL handle used in the real capture


def header() -> bytes:
    return b"btsnoop\x00" + struct.pack(">II", 1, 2001)


def record(opcode: int, data: bytes, ts: float | None = None) -> bytes:
    us = int((ts if ts is not None else time.time()) * 1e6) + EPOCH
    return struct.pack(">IIIIq", len(data), len(data), opcode, 0, us) + data


def addr_le(addr: str = ADDR) -> bytes:
    return bytes(int(x, 16) for x in reversed(addr.split(":")))


def conn_complete(handle=H, addr=ADDR, ts=None) -> bytes:
    p = bytes([0]) + struct.pack("<H", handle) + addr_le(addr) + bytes([1, 0])
    return record(3, bytes([0x03, len(p)]) + p, ts)


def link_key_reply(ts=None) -> bytes:
    p = addr_le() + bytes(range(0xA0, 0xB0))
    return record(2, struct.pack("<HB", 0x040B, len(p)) + p, ts)


def acl(direction: str, cid: int, payload: bytes, handle=H, ts=None) -> bytes:
    l2 = struct.pack("<HH", len(payload), cid) + payload
    hdr = struct.pack("<HH", handle | (2 << 12), len(l2))
    return record(4 if direction == "tx" else 5, hdr + l2, ts)


def l2cap_open(psm: int, host_cid: int, remote_cid: int, ident: int, ts=None) -> bytes:
    req = struct.pack("<BBHHH", 0x02, ident, 4, psm, host_cid)
    rsp = struct.pack("<BBHHHHH", 0x03, ident, 8, remote_cid, host_cid, 0, 0)
    return acl("tx", 1, req, ts=ts) + acl("rx", 1, rsp, ts=ts)


# channel ids chosen like the real capture
AVCTP_HOST, AVCTP_REMOTE = 0x0045, 0x0070
RFCOMM_HOST, RFCOMM_REMOTE = 0x0041, 0x006C
HID_HOST, HID_REMOTE = 0x0046, 0x0071


def setup(ts=None) -> bytes:
    return (conn_complete(ts=ts) + link_key_reply(ts=ts)
            + l2cap_open(0x17, AVCTP_HOST, AVCTP_REMOTE, 11, ts)
            + l2cap_open(0x03, RFCOMM_HOST, RFCOMM_REMOTE, 4, ts)
            + l2cap_open(0x13, HID_HOST, HID_REMOTE, 14, ts))


def passthrough(op: int, label: int = 6, ts=None) -> bytes:
    """Headset -> host PASS THROUGH press + release, plus host ACCEPTED responses."""
    out = b""
    for state in (0x00, 0x80):
        cmd = bytes([label << 4, 0x11, 0x0E, 0x00, 0x48, 0x7C, op | state, 0x00])
        rsp = bytes([(label << 4) | 2, 0x11, 0x0E, 0x09, 0x48, 0x7C, op | state, 0x00])
        out += acl("rx", AVCTP_HOST, cmd, ts=ts) + acl("tx", AVCTP_REMOTE, rsp, ts=ts)
        label = (label + 1) & 0xF
    return out


def volume_changed(vol: int, ts=None) -> bytes:
    p = bytes([0x12, 0x11, 0x0E, 0x0D, 0x48, 0x00, 0x00, 0x19, 0x58, 0x31, 0x00, 0x00, 0x02, 0x0D, vol])
    return acl("rx", AVCTP_HOST, p, ts=ts)


def set_absolute_volume(vol: int, accepted=True, ts=None) -> bytes:
    cmd = bytes([0x30, 0x11, 0x0E, 0x00, 0x48, 0x00, 0x00, 0x19, 0x58, 0x50, 0x00, 0x00, 0x01, vol])
    rsp = bytes([0x32, 0x11, 0x0E, 0x09 if accepted else 0x0A, 0x48, 0x00, 0x00, 0x19, 0x58, 0x50, 0x00, 0x00, 0x01, vol])
    return acl("tx", AVCTP_REMOTE, cmd, ts=ts) + acl("rx", AVCTP_HOST, rsp, ts=ts)


def rfcomm_uih(channel: int, data: bytes, direction="rx", ts=None) -> bytes:
    dlci = channel * 2
    addr = (dlci << 2) | (0 if direction == "rx" else 2) | 1
    frame = bytes([addr, 0xEF, (len(data) << 1) | 1]) + data + b"\x00"
    return acl(direction, RFCOMM_HOST if direction == "rx" else RFCOMM_REMOTE, frame, ts=ts)


def rfcomm_sabm(channel: int, direction="rx", ts=None) -> bytes:
    addr = ((channel * 2) << 2) | 3
    return acl(direction, RFCOMM_HOST if direction == "rx" else RFCOMM_REMOTE, bytes([addr, 0x3F, 0x01, 0x00]), ts=ts)


def hid_report(report: bytes, ts=None) -> bytes:
    return acl("rx", HID_HOST, bytes([0xA1]) + report, ts=ts)


def to_android_h4(monitor_file: bytes) -> bytes:
    """Re-encode a monitor-format (2001) file as an Android HCI snoop log (H4, 1002)."""
    out = bytearray(b"btsnoop\x00" + struct.pack(">II", 1, 1002))
    pos = 16
    h4 = {2: (1, 2), 3: (4, 3), 4: (2, 0), 5: (2, 1)}  # monitor opcode -> (H4 type, flags)
    while pos + 24 <= len(monitor_file):
        olen, ilen, flags, drops, ts = struct.unpack_from(">IIIIq", monitor_file, pos)
        data = monitor_file[pos + 24:pos + 24 + ilen]
        pos += 24 + ilen
        if (flags & 0xFFFF) in h4:
            t, f = h4[flags & 0xFFFF]
            rec = bytes([t]) + data
            out += struct.pack(">IIIIq", len(rec), len(rec), f, 0, ts) + rec
    return bytes(out)
