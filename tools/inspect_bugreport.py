#!/usr/bin/env python3
"""Read-only inspector: does an Android bug report contain Bluetooth HCI / btsnoop data?

Usage:
    python3 tools/inspect_bugreport.py bugreport-XXXX.zip
    python3 tools/inspect_bugreport.py bugreport-XXXX.zip --json

What it does (and nothing else):
  * opens the zip (or a bugreport .txt) READ-ONLY; writes no files, changes nothing
  * reports device model / Android build
  * reports the Bluetooth snoop-log system properties recorded in the report
  * finds btsnoop files inside the zip and validates their header
  * finds the in-memory "BTSNOOP_LOG_SUMMARY" section and checks whether it decodes
It prints only Bluetooth-related facts. A bug report holds a lot of personal data:
do not share the zip itself.

Standard library only (Python 3.8+).
"""

import argparse
import base64
import binascii
import json
import re
import struct
import sys
import zipfile
import zlib
from datetime import datetime, timezone

BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_EPOCH_US = 0x00DCDDB30F2F8000
DATALINKS = {1001: "HCI unencapsulated", 1002: "HCI UART (H4) — صيغة Android", 2001: "Linux monitor (btmon)"}
PROP_KEYS = (
    "ro.product.model", "ro.product.marketname", "ro.product.brand", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.display.id", "ro.build.version.oplusrom", "ro.build.version.opporom",
    "persist.bluetooth.btsnooplogmode", "persist.bluetooth.btsnoopdefaultmode", "persist.bluetooth.btsnoopenable",
    "persist.bluetooth.btsnooppath", "persist.bluetooth.btsnoopsize", "persist.bluetooth.snooplogfilter.profiles.rfcomm",
)
FILE_HINT = re.compile(r"(btsnoop|snoop|hci|\.cfa$|bluetooth/logs|bt_?log)", re.I)
SUMMARY_RE = re.compile(r"-{2,}\s*BEGIN:BTSNOOP_LOG_SUMMARY[^\n]*\n(.*?)-{2,}\s*END:BTSNOOP_LOG_SUMMARY", re.S)


def _ts(us: int) -> str:
    try:
        return datetime.fromtimestamp(us / 1e6, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "?"


def inspect_btsnoop(data: bytes) -> dict:
    """Validate a btsnoop file and count its records (read-only)."""
    info = {"valid": False, "size": len(data)}
    if len(data) < 16 or data[:8] != BTSNOOP_MAGIC:
        info["reason"] = "not a btsnoop file (bad magic)"
        return info
    version, datalink = struct.unpack_from(">II", data, 8)
    info.update(valid=True, version=version, datalink=datalink, datalink_name=DATALINKS.get(datalink, "?"))
    pos, n, first, last, acl = 16, 0, None, None, 0
    while pos + 24 <= len(data):
        _, ilen, flags, _, ts = struct.unpack_from(">IIIIq", data, pos)
        rec = data[pos + 24:pos + 24 + ilen]
        if len(rec) < ilen:
            info["truncated_tail"] = True
            break
        pos += 24 + ilen
        n += 1
        us = ts - BTSNOOP_EPOCH_US
        first = us if first is None else first
        last = us
        if (datalink == 1002 and rec[:1] == b"\x02") or (datalink == 2001 and (flags & 0xFFFF) in (4, 5)):
            acl += 1
    info.update(records=n, acl_records=acl)
    if n:
        info.update(first=_ts(first), last=_ts(last))
    return info


def decode_snooz(b64_text: str) -> dict:
    """Check the BTSNOOP_LOG_SUMMARY block (Android in-memory HCI ring buffer).

    Layout as produced by AOSP (see system/bt tools/scripts/btsnooz.py): base64 of
    [version:u8][last_timestamp_ms:u64][zlib(records)], each record
    [length:u16][packet_length:u16][delta_ms:u32][type:u8][length-1 bytes].
    If the layout differs on this build, we say so instead of guessing.
    """
    out = {"base64_chars": len(b64_text)}
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", b64_text), validate=False)
    except (binascii.Error, ValueError) as exc:
        out["error"] = f"base64 decode failed: {exc}"
        return out
    out["raw_bytes"] = len(raw)
    if len(raw) < 10:
        out["error"] = "block too short"
        return out
    version = raw[0]
    last_ms = struct.unpack_from("<Q", raw, 1)[0]
    out.update(version=version, last_timestamp=_ts(last_ms * 1000))
    body = None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
        try:
            body = zlib.decompress(raw[9:], wbits)
            break
        except zlib.error:
            continue
    if body is None:
        out["error"] = "zlib decompression failed (format differs on this build)"
        return out
    out["decompressed_bytes"] = len(body)
    pos, n, types, truncated, total_delta = 0, 0, {}, 0, 0
    while pos + 9 <= len(body):
        length, pkt_len, delta, typ = struct.unpack_from("<HHIB", body, pos)
        if length < 1 or pos + 9 + length - 1 > len(body):
            out["parse_stopped_at"] = pos
            break
        pos += 9 + length - 1
        n += 1
        total_delta += delta
        types[f"0x{typ:02X}"] = types.get(f"0x{typ:02X}", 0) + 1
        if length - 1 < pkt_len:
            truncated += 1
    out.update(records=n, record_types=types, truncated_packets=truncated,
               span_seconds=round(total_delta / 1000, 1))
    if n:
        out["first_timestamp"] = _ts((last_ms - total_delta) * 1000)
    return out


def find_main_text(z: zipfile.ZipFile):
    names = z.namelist()
    if "main_entry.txt" in names:
        target = z.read("main_entry.txt").decode(errors="replace").strip()
        if target in names:
            return target
    cands = [n for n in names if re.match(r"(.*/)?bugreport-.*\.txt$", n)]
    return max(cands, key=lambda n: z.getinfo(n).file_size) if cands else None


def inspect_text(text: str) -> dict:
    res: dict = {"properties": {}, "summaries": [], "bluetooth_manager_dump": False, "snoop_lines": []}
    for key in PROP_KEYS:
        m = re.search(r"^\[" + re.escape(key) + r"\]: \[(.*?)\]", text, re.M)
        if m:
            res["properties"][key] = m.group(1)
    m = re.search(r"^Build fingerprint: '?(.*?)'?$", text, re.M)
    if m:
        res["fingerprint"] = m.group(1)
    res["bluetooth_manager_dump"] = bool(re.search(r"DUMP OF SERVICE (bluetooth_manager|bluetooth)\b", text))
    for m in SUMMARY_RE.finditer(text):
        res["summaries"].append(decode_snooz(m.group(1)))
    if not res["summaries"] and "BTSNOOP_LOG_SUMMARY" in text:
        res["summaries"].append({"error": "section marker present but its layout was not recognised"})
    seen = set()
    for line in text.splitlines():
        low = line.lower()
        if ("snoop" in low or "hci log" in low) and len(seen) < 25:
            s = line.strip()[:160]
            if s and s not in seen:
                seen.add(s)
    res["snoop_lines"] = sorted(seen)
    return res


def inspect(path: str) -> dict:
    report: dict = {"input": path, "btsnoop_files": [], "candidate_files": []}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:  # read-only
            report["zip_entries"] = len(z.namelist())
            for name in z.namelist():
                if name.endswith("/") or not FILE_HINT.search(name):
                    continue
                info = z.getinfo(name)
                with z.open(name) as f:
                    head = f.read(16)
                if head[:8] == BTSNOOP_MAGIC:
                    report["btsnoop_files"].append({"name": name, **inspect_btsnoop(z.read(name))})
                else:
                    report["candidate_files"].append({"name": name, "size": info.file_size})
            main = find_main_text(z)
            report["main_text"] = main
            text = z.read(main).decode("utf-8", errors="replace") if main else ""
    else:
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
        report["main_text"] = path
    report.update(inspect_text(text))
    usable_files = [f for f in report["btsnoop_files"] if f.get("valid") and f.get("records")]
    usable_summary = [s for s in report["summaries"] if s.get("records")]
    report["verdict"] = ("full_btsnoop" if usable_files else "summary_only" if usable_summary else "none")
    return report


def print_report(r: dict) -> None:
    p = r["properties"]
    print("=" * 72)
    print("فحص تقرير الأخطاء (Bug Report) — قراءة فقط، لم يُكتب أي ملف")
    print("=" * 72)
    model = p.get("ro.product.marketname") or p.get("ro.product.model") or "?"
    print(f"الجهاز: {model} | Android {p.get('ro.build.version.release', '?')} (SDK {p.get('ro.build.version.sdk', '?')})")
    rom = p.get("ro.build.version.oplusrom") or p.get("ro.build.version.opporom")
    if rom:
        print(f"ColorOS: {rom}")
    print(f"الملف الرئيسي: {r.get('main_text') or 'غير موجود'}")
    print()
    print("1) إعدادات سجل HCI كما سُجلت في التقرير:")
    snoop_props = {k: v for k, v in p.items() if "bluetooth" in k}
    if snoop_props:
        for k, v in snoop_props.items():
            print(f"   {k} = {v}")
    else:
        print("   لم تُسجَّل خصائص btsnoop في التقرير")
    print()
    print("2) ملفات btsnoop داخل التقرير:")
    if r["btsnoop_files"]:
        for f in r["btsnoop_files"]:
            if f.get("valid"):
                print(f"   ✔ {f['name']} — {f['size']} بايت، {f.get('records', 0)} سجل "
                      f"({f.get('acl_records', 0)} ACL)، {f.get('datalink_name')}")
                if f.get("records"):
                    print(f"     من {f.get('first')} إلى {f.get('last')}")
            else:
                print(f"   ✘ {f['name']} — {f.get('reason')}")
    else:
        print("   لا توجد")
    if r["candidate_files"]:
        print("   ملفات أسماؤها توحي بـ Bluetooth لكنها ليست btsnoop:")
        for f in r["candidate_files"][:15]:
            print(f"     - {f['name']} ({f['size']} بايت)")
    print()
    print("3) ملخص HCI من الذاكرة (BTSNOOP_LOG_SUMMARY):")
    print(f"   قسم dumpsys bluetooth_manager موجود: {'نعم' if r['bluetooth_manager_dump'] else 'لا'}")
    if r["summaries"]:
        for i, s in enumerate(r["summaries"], 1):
            if s.get("error"):
                print(f"   [{i}] موجود لكن تعذر فكه: {s['error']}")
            else:
                print(f"   [{i}] نسخة {s.get('version')}، {s.get('records', 0)} سجل، "
                      f"{s.get('truncated_packets', 0)} حزمة مقطوعة، يغطي ~{s.get('span_seconds')} ث "
                      f"(من {s.get('first_timestamp', '?')} إلى {s.get('last_timestamp')})")
                print(f"       أنواع السجلات: {s.get('record_types')}")
    else:
        print("   غير موجود في التقرير")
    print()
    verdict = {
        "full_btsnoop": "النتيجة: يوجد سجل btsnoop كامل — يمكن رفعه إلى «تحليل التقاط محفوظ».",
        "summary_only": "النتيجة: لا يوجد سجل كامل، لكن يوجد ملخص HCI من الذاكرة (قد يكون مقطوعًا/قصيرًا).",
        "none": "النتيجة: التقرير لا يحتوي على بيانات HCI قابلة للاستخدام.",
    }[r["verdict"]]
    print(verdict)
    print("تنبيه: التقرير يحتوي على بيانات شخصية كثيرة — لا تشارك ملف zip نفسه.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only check for Bluetooth HCI data in an Android bug report")
    ap.add_argument("path", help="bugreport-*.zip (or the main bugreport .txt)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    try:
        r = inspect(a.path)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"تعذر فتح الملف: {exc}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print_report(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
