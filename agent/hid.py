"""HID report-descriptor parsing (read-only analysis of advertised data).

The headset's descriptor comes from SDP attribute 0x0206 in the capture
(report section 13a). Parsing it tells us what the device *could* send; it
does not show that any report was ever exchanged.
"""

from __future__ import annotations

# Report descriptor advertised by the headset (SDP attr 0x0206, 81 bytes).
CAPTURED_DESCRIPTOR = bytes.fromhex(
    "050c0901a1018502751095021501268c0219012a8c028100c0"
    "050c0901a101850315002501750195"
    "0d0a23020a21020ab10109b809b609cd09b509e209ea09e909300a07030a0803810295"
    "0175 0b8103c0".replace(" ", "")
)

CONSUMER_USAGES: dict[int, str] = {
    0x01: "Consumer Control", 0x30: "Power", 0x40: "Menu", 0xB0: "Play", 0xB1: "Pause", 0xB2: "Record",
    0xB3: "Fast Forward", 0xB4: "Rewind", 0xB5: "Scan Next Track", 0xB6: "Scan Previous Track",
    0xB7: "Stop", 0xB8: "Eject", 0xCD: "Play/Pause", 0xE2: "Mute", 0xE9: "Volume Up", 0xEA: "Volume Down",
    0x1B1: "AL Screen Saver", 0x221: "AC Search", 0x223: "AC Home", 0x224: "AC Back", 0x225: "AC Forward",
}
USAGE_AR: dict[int, str] = {
    0x30: "تشغيل/إطفاء الجهاز", 0xB5: "المقطع التالي", 0xB6: "المقطع السابق", 0xB8: "إخراج", 0xCD: "تشغيل/إيقاف مؤقت",
    0xE2: "كتم الصوت", 0xE9: "رفع الصوت", 0xEA: "خفض الصوت", 0x1B1: "شاشة التوقف", 0x221: "بحث", 0x223: "الصفحة الرئيسية",
}
PAGE_NAMES = {0x01: "Generic Desktop", 0x07: "Keyboard", 0x0C: "Consumer"}


def usage_name(page: int, usage: int) -> str:
    if page == 0x0C:
        return CONSUMER_USAGES.get(usage, f"Consumer 0x{usage:03X} (غير معرّف في جداولنا)")
    return f"{PAGE_NAMES.get(page, f'Page 0x{page:02X}')} 0x{usage:X}"


def _signed(data: bytes) -> int:
    return int.from_bytes(data, "little", signed=True) if data else 0


def parse_descriptor(desc: bytes) -> list[dict]:
    """Return one entry per input field: report id, size/count, usages, flags."""
    fields: list[dict] = []
    g = {"page": 0, "lmin": 0, "lmax": 0, "size": 0, "count": 0, "report_id": None}
    stack: list[dict] = []
    local: dict = {"usages": [], "umin": None, "umax": None}
    i = 0
    while i < len(desc):
        b = desc[i]
        if b == 0xFE:  # long item
            i += 3 + desc[i + 1]
            continue
        size = (0, 1, 2, 4)[b & 3]
        typ = (b >> 2) & 3
        tag = b >> 4
        data = desc[i + 1:i + 1 + size]
        val = int.from_bytes(data, "little") if data else 0
        i += 1 + size
        if typ == 1:  # global
            if tag == 0: g["page"] = val
            elif tag == 1: g["lmin"] = _signed(data)
            elif tag == 2: g["lmax"] = _signed(data) if size < 2 or val < 0x8000 else val
            elif tag == 7: g["size"] = val
            elif tag == 8: g["report_id"] = val
            elif tag == 9: g["count"] = val
            elif tag == 10: stack.append(dict(g))
            elif tag == 11 and stack: g = stack.pop()
        elif typ == 2:  # local
            if tag == 0: local["usages"].append(val if size < 4 else val & 0xFFFF)
            elif tag == 1: local["umin"] = val
            elif tag == 2: local["umax"] = val
        elif typ == 0:  # main
            if tag in (8, 9, 11):  # input / output / feature
                constant = bool(val & 1)
                variable = bool(val & 2)
                if tag == 8 and not constant:
                    entry = {
                        "report_id": g["report_id"], "page": g["page"], "size": g["size"], "count": g["count"],
                        "logical_min": g["lmin"], "logical_max": g["lmax"],
                        "kind": "variable" if variable else "array",
                    }
                    if local["usages"]:
                        entry["usages"] = [{"usage": u, "name": usage_name(g["page"], u), "ar": USAGE_AR.get(u)}
                                           for u in local["usages"]]
                    elif local["umin"] is not None:
                        entry["usage_range"] = [local["umin"], local["umax"]]
                    fields.append(entry)
            local = {"usages": [], "umin": None, "umax": None}
    return fields


def summarize(fields: list[dict]) -> list[dict]:
    """Human-oriented summary per report ID."""
    out = []
    for f in fields:
        bits = f["size"] * f["count"]
        item = {"report_id": f["report_id"], "kind": f["kind"], "bits": bits, "page": PAGE_NAMES.get(f["page"], hex(f["page"]))}
        if f["kind"] == "variable":
            item["description"] = f"خريطة بتات: {f['count']} مفتاح، بت واحد لكل مفتاح"
            item["usages"] = f.get("usages", [])
        else:
            lo, hi = f.get("usage_range", [f["logical_min"], f["logical_max"]])
            item["description"] = f"مصفوفة: {f['count']} خانة × {f['size']} بت، أي استخدام من 0x{lo:03X} إلى 0x{hi:03X}"
            item["usages"] = []
        out.append(item)
    return out


def decode_input_report(fields: list[dict], report: bytes) -> dict:
    """Decode an input report (first byte = report id) into pressed usages."""
    if not report:
        return {"report_id": None, "pressed": []}
    rid, payload = report[0], report[1:]
    bitpos = 0
    pressed = []
    value = int.from_bytes(payload, "little")
    for f in (x for x in fields if x["report_id"] == rid):
        if f["kind"] == "variable":
            for n, u in enumerate(f.get("usages", [])):
                if (value >> (bitpos + n)) & 1:
                    pressed.append(usage_name(f["page"], u["usage"]))
        else:
            for n in range(f["count"]):
                v = (value >> (bitpos + n * f["size"])) & ((1 << f["size"]) - 1)
                if v:
                    pressed.append(usage_name(f["page"], v))
        bitpos += f["size"] * f["count"]
    return {"report_id": rid, "pressed": pressed}


CAPTURED_FIELDS = parse_descriptor(CAPTURED_DESCRIPTOR)
