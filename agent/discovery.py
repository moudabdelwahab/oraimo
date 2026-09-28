"""Safe capability discovery: read-only scan, passive research mode, capability matrix.

What this module may do (all read-only or passive):
  * read BlueZ D-Bus objects/properties (GetManagedObjects)
  * run ``sdptool browse --xml`` (standard SDP queries, the same ones BlueZ sends
    on every connection; report frames 60-264)
  * list GATT services/characteristics metadata exposed by BlueZ (never read,
    write or subscribe)
  * read /proc/bus/input/devices and /sys/class/rfkill
  * follow a btsnoop file written by ``btmon`` (passive)
  * perform the already-whitelisted host actions (play/pause/next/previous/
    volume) and correlate the resulting traffic

What it never does: open RFCOMM/L2CAP channels, write GATT characteristics,
send vendor/unknown commands, touch firmware, or change device configuration.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import time
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import device as dev
from . import hid, sniffer
from .errors import AgentError, DBusCallError

if TYPE_CHECKING:  # pragma: no cover
    from .controller import Controller

log = logging.getLogger("necklace.discovery")

HEADSET_WINDOW = 6.0     # seconds to watch after "I will press the headset button"
HOST_WINDOW_BEFORE = 0.3
HOST_WINDOW_AFTER = 3.0

RESEARCH_ACTIONS: dict[str, dict] = {
    "play": {"label": "تشغيل", "host": "play", "headset_op": "PLAY"},
    "pause": {"label": "إيقاف مؤقت", "host": "pause", "headset_op": "PAUSE"},
    "volume_up": {"label": "رفع الصوت", "host": "volume_up", "headset_op": "VOLUME_UP"},
    "volume_down": {"label": "خفض الصوت", "host": "volume_down", "headset_op": "VOLUME_DOWN"},
    "previous": {"label": "السابق", "host": "previous", "headset_op": "BACKWARD"},
    "next": {"label": "التالي", "host": "next", "headset_op": "FORWARD"},
    "mute": {"label": "كتم الصوت", "host": None, "headset_op": "MUTE"},
}

STATUS_LABELS = {
    "confirmed": "مؤكدة", "advertised": "معلنة فقط", "unknown": "غير معروفة",
    "unavailable": "غير متاحة", "present": "موجودة",
}

# Capture-derived reference (report sections 4a, 5, 6, 12, 13).
CAPTURE_SERVICES = [
    {"handle": 0x10001, "name": "JL_A2DP", "classes": [dev.sig_uuid(0x110B)], "l2cap_psm": 0x19, "rfcomm_channel": None,
     "profile": "A2DP 1.3", "features": 0x0001},
    {"handle": 0x10002, "name": None, "classes": [dev.sig_uuid(0x110E), dev.sig_uuid(0x110F)], "l2cap_psm": 0x17,
     "rfcomm_channel": None, "profile": "AVRCP 1.5 (CT)", "features": 0x0001},
    {"handle": 0x10005, "name": None, "classes": [dev.sig_uuid(0x110C)], "l2cap_psm": 0x17, "rfcomm_channel": None,
     "profile": "AVRCP 1.5 (TG)", "features": 0x0002},
    {"handle": 0x10003, "name": "JL_HFP", "classes": [dev.sig_uuid(0x111E), dev.sig_uuid(0x1203)], "l2cap_psm": None,
     "rfcomm_channel": 4, "profile": "HFP 1.8", "features": 0x003F},
    {"handle": 0x10006, "name": "JL_HID", "classes": [dev.sig_uuid(0x1124)], "l2cap_psm": 0x11, "rfcomm_channel": None,
     "profile": "HID 1.0", "features": None},
    {"handle": 0x10004, "name": "JL_SPP", "classes": [dev.sig_uuid(0x1101)], "l2cap_psm": None, "rfcomm_channel": 1,
     "profile": "SPP 1.2", "features": None},
    {"handle": 0x10011, "name": "JL_SPP", "classes": [dev.JIELI_CUSTOM_SPP_UUID], "l2cap_psm": None, "rfcomm_channel": 10,
     "profile": "JieLi 1.0", "features": None},
    {"handle": 0x1000A, "name": None, "classes": [dev.sig_uuid(0x1200)], "l2cap_psm": None, "rfcomm_channel": None,
     "profile": "PnP/DI 1.3", "features": None},
]
CAPTURE_L2CAP = [
    {"psm": 0x0001, "protocol": "SDP", "host_cid": "0x0040", "headset_cid": "0x006B", "note": "أُغلقت بعد البحث"},
    {"psm": 0x0003, "protocol": "RFCOMM (HFP، القناة 4)", "host_cid": "0x0041", "headset_cid": "0x006C", "note": "مفتوحة"},
    {"psm": 0x0019, "protocol": "AVDTP إشارات", "host_cid": "0x0042", "headset_cid": "0x006D", "note": "مفتوحة"},
    {"psm": 0x0019, "protocol": "AVDTP وسائط", "host_cid": "0x0043", "headset_cid": "0x006E", "note": "مفتوحة"},
    {"psm": 0x0017, "protocol": "AVCTP (AVRCP)", "host_cid": "0x0045", "headset_cid": "0x0070", "note": "مفتوحة"},
    {"psm": 0x0011, "protocol": "HID Control", "host_cid": "0x0044", "headset_cid": "0x006F", "note": "أغلقتها السماعة فورًا"},
    {"psm": 0x0013, "protocol": "HID Interrupt", "host_cid": "0x0046", "headset_cid": "0x0071", "note": "أغلقتها السماعة فورًا، ثم رُفضت محاولاتها"},
]
AVRCP_REFERENCE = {
    "headset_tg_events": ["PLAYBACK_STATUS_CHANGED", "BATT_STATUS_CHANGED", "VOLUME_CHANGED"],
    "host_tg_events": ["PLAYBACK_STATUS_CHANGED", "TRACK_CHANGED", "TRACK_REACHED_END", "TRACK_REACHED_START",
                       "PLAYER_APPLICATION_SETTING_CHANGED", "AVAILABLE_PLAYERS_CHANGED", "ADDRESSED_PLAYER_CHANGED"],
    "headset_registered": ["PLAYBACK_STATUS_CHANGED", "TRACK_CHANGED"],
    "host_registered": ["VOLUME_CHANGED"],
    "headset_requests": ["GetCapabilities", "GetElementAttributes", "RegisterNotification"],
    "passthrough_seen": ["PLAY", "PAUSE"],
}


# ============================================================ sdptool XML
def _xml_value(el: ET.Element):
    tag = el.tag
    val = el.get("value", "")
    if tag.startswith("uint"):
        return ("uint", int(val, 16) if val.startswith("0x") else int(val))
    if tag.startswith("int"):
        return ("int", int(val, 16) if val.startswith("0x") else int(val))
    if tag == "uuid":
        v = val.lower()
        if v.startswith("0x"):
            n = int(v, 16)
            return ("uuid", sniffer.uuid_str(n.to_bytes(2 if n <= 0xFFFF else 4, "big")))
        return ("uuid", v)
    if tag in ("text", "url"):
        if el.get("encoding") == "hex":
            return ("text", bytes.fromhex(val))
        return ("text", val.encode())
    if tag == "boolean":
        return ("bool", val == "true")
    if tag in ("sequence", "alternate"):
        return ("seq", [_xml_value(c) for c in el])
    return ("nil", None)


def parse_sdptool_xml(output: str) -> list[dict]:
    records = []
    for block in re.findall(r"<record>.*?</record>", output, flags=re.S):
        try:
            root = ET.fromstring(block)
        except ET.ParseError:
            continue
        attrs = {}
        for a in root.findall("attribute"):
            children = list(a)
            if children:
                attrs[int(a.get("id"), 16)] = _xml_value(children[0])
        records.append(sniffer.interpret_record(attrs))
    return records


def describe_service(svc: dict) -> dict:
    classes = svc.get("classes", [])
    known = [dev.KNOWN_SERVICES.get(c.lower()) for c in classes]
    names = [k.name for k in known if k] or [sniffer.short_uuid(c) for c in classes]
    blocked = any(c.lower() in dev.BLOCKED_UUIDS for c in classes)
    return {**svc, "display": " / ".join(names), "blocked": blocked,
            "handle_hex": f"0x{svc['handle']:05X}" if svc.get("handle") is not None else None}


def parse_proc_input(text: str) -> list[dict]:
    devices, cur = [], {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if cur:
                devices.append(cur)
            cur = {}
            continue
        kind, _, rest = line.partition(": ")
        if kind == "I":
            m = dict(x.split("=", 1) for x in rest.split() if "=" in x)
            cur["bus"] = m.get("Bus")
        elif kind == "N":
            cur["name"] = rest.split("=", 1)[1].strip('"') if "=" in rest else rest
        elif kind == "P":
            cur["phys"] = rest.split("=", 1)[1] if "=" in rest else ""
        elif kind == "U":
            cur["uniq"] = rest.split("=", 1)[1] if "=" in rest else ""
        elif kind == "H":
            cur["handlers"] = rest.split("=", 1)[1].strip() if "=" in rest else ""
    return devices


# ============================================================ discovery
class Discovery:
    def __init__(self, controller: "Controller", capture_path: str):
        self.ctl = controller
        self.capture_path = capture_path
        self.tail = sniffer.CaptureTail(capture_path, controller.address, self._on_packet, self._on_services)
        self.log: deque[dict] = deque(maxlen=2000)
        self._log_id = 0
        self.scan: dict | None = None
        self.scan_running = False
        self.research_active = False
        self.research_started: float | None = None
        self.trials: deque[dict] = deque(maxlen=60)
        self._trial_id = 0
        self.system_events: deque[tuple[float, dict]] = deque(maxlen=500)
        self.observed: dict[str, Any] = {
            "headset_passthrough": {}, "host_passthrough": {}, "set_absolute_volume": None,
            "volume_notifications": 0, "hid_reports": 0, "hid_usages": [], "jieli_frames": 0, "jieli_opened": False,
            "avrcp_events": set(), "avrcp_pdus": set(), "hfp_commands": set(), "codecs": {}, "vendor_packets": 0,
            "sdp_services": [],
        }
        self.analysis: dict | None = None
        self._pending_sab: float | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        try:
            Path(self.capture_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            log.warning("cannot create capture dir: %r", exc)
        self.tail.start()
        self._watch = asyncio.get_running_loop().create_task(self._watch_capture())

    async def stop(self) -> None:
        if getattr(self, "_watch", None):
            self._watch.cancel()
        await self.tail.stop()

    def capture_status(self) -> dict:
        return {**self.tail.status(), "command": f"sudo btmon -w {self.capture_path}"}

    async def _watch_capture(self) -> None:
        """Push capture-source changes (btmon started/stopped, headset seen) to the UI."""
        last = None
        while True:
            await asyncio.sleep(1.0)
            st = self.tail.status()
            key = (st["exists"], st["active"], st["error"], st["datalink"], tuple(st["target_handles"]),
                   (st["stats"] or {}).get("records", 0) // 25, st["services_seen"])
            if key != last:
                last = key
                self._emit({"type": "capture_status", "capture": self.capture_status()})

    # ------------------------------------------------------------------ logging
    def _add_log(self, *, etype: str, channel: str, direction: str, data: str, result: str,
                 classification: str = "standard", ts: float | None = None, raw: str = "", fields: dict | None = None) -> dict:
        self._log_id += 1
        entry = {"id": self._log_id, "ts": ts or time.time(), "type": etype, "channel": channel,
                 "direction": direction, "data": data, "result": result, "classification": classification,
                 "classification_label": sniffer.CLASS_LABELS.get(classification, classification), "raw": raw}
        self.log.append(entry)
        self._emit({"type": "discovery_log", "entry": entry})
        return entry

    def _emit(self, msg: dict) -> None:
        try:
            asyncio.get_running_loop().create_task(self.ctl._broadcast(msg))
        except RuntimeError:
            pass

    # ------------------------------------------------------------------ passive inputs
    def observe_system(self, msg: dict) -> None:
        """Called for every controller broadcast (D-Bus/MPRIS/evdev derived events)."""
        if msg.get("type") in ("connection_changed", "volume_changed", "playback_changed", "stream_changed",
                               "battery_changed", "headset_button", "player_changed"):
            self.system_events.append((time.time(), msg))

    def _on_services(self, services: list[dict]) -> None:
        self.observed["sdp_services"] = services

    def _on_packet(self, p: sniffer.Packet) -> None:
        o = self.observed
        f = p.fields
        if p.protocol == "AVRCP":
            if "operation" in f and not f.get("response") and not f.get("released"):
                bucket = o["headset_passthrough"] if p.direction == "rx" else o["host_passthrough"]
                bucket[f["operation"]] = bucket.get(f["operation"], 0) + 1
            if "pdu" in f:
                o["avrcp_pdus"].add(f["pdu"])
            if f.get("event"):
                o["avrcp_events"].add(f["event"])
            if f.get("pdu") == "SetAbsoluteVolume" and f.get("response"):
                o["set_absolute_volume"] = f.get("ctype") == "ACCEPTED"
            if f.get("event") == "VOLUME_CHANGED" and f.get("ctype") == "CHANGED":
                o["volume_notifications"] += 1
        elif p.protocol == "HID" and f.get("pressed") is not None:
            o["hid_reports"] += 1
            o["hid_usages"] = sorted(set(o["hid_usages"]) | set(f["pressed"]))
        elif p.protocol == "HFP" and p.direction == "rx":
            o["hfp_commands"].add((f.get("at") or "").split("=")[0].split("?")[0][:20])
        elif p.protocol == "AVDTP" and "codec" in f:
            o["codecs"][f["codec"]["name"]] = True
        if p.classification == "vendor":
            o["vendor_packets"] += 1
            if p.protocol.startswith("JieLi"):
                o["jieli_frames"] += 1
        if (p.fields.get("server_channel") == 10 and p.opcode == "SABM"):
            o["jieli_opened"] = True
        self._add_log(etype=p.protocol, channel=p.channel or p.hci, direction=sniffer.DIR_LABELS.get(p.direction, "—"),
                      data=p.summary, result=p.opcode or "", classification=p.classification, ts=p.ts, raw=p.raw)

    # ------------------------------------------------------------------ safe scan
    async def safe_scan(self) -> dict:
        if self.scan_running:
            raise AgentError("connect_in_progress", "scan already running")
        self.scan_running = True
        started = time.time()
        steps: list[dict] = []
        result: dict[str, Any] = {"started_at": started, "steps": steps}
        self._emit({"type": "discovery_scan", "running": True})

        def step(sid, label, status, detail, data=None):
            steps.append({"id": sid, "label": label, "status": status, "detail": detail})
            self._add_log(etype="فحص آمن", channel=label, direction="قراءة فقط", data=detail,
                          result={"ok": "نجح", "skipped": "تم التخطي", "failed": "فشل", "unavailable": "غير متاح"}[status])
            if data is not None:
                result[sid] = data
            self._emit({"type": "discovery_scan", "running": True, "step": steps[-1]})

        try:
            self._add_log(etype="فحص آمن", channel="الوكيل", direction="—",
                          data="بدأ الفحص الآمن: قراءة فقط، لا تُرسل أي أوامر خاصة بالمصنّع", result="بدأ")
            snap = await self.ctl.refresh()
            connected = snap["connection"]["connected"]

            # 1. rfkill + adapter
            rf = []
            for d in sorted(Path("/sys/class/rfkill").glob("rfkill*")) if Path("/sys/class/rfkill").exists() else []:
                try:
                    if (d / "type").read_text().strip() == "bluetooth":
                        rf.append({"name": (d / "name").read_text().strip(), "soft": (d / "soft").read_text().strip() == "1",
                                   "hard": (d / "hard").read_text().strip() == "1"})
                except OSError:
                    pass
            a = snap["bluetooth"]["adapter"]
            step("adapter", "المحول وrfkill", "ok" if a.get("present") else "unavailable",
                 (f"المحول {a.get('address')} {'يعمل' if a.get('powered') else 'متوقف'}" if a.get("present") else "لا يوجد محول")
                 + (f"؛ rfkill: {', '.join(('محظور' if x['soft'] or x['hard'] else 'غير محظور') for x in rf)}" if rf else ""),
                 {"adapter": a, "rfkill": rf})

            # 2. BlueZ objects
            objects = {}
            try:
                objects = await self.ctl.bluez.managed_objects()
                dpath = snap["device"].get("path")
                tree = []
                for path in sorted(objects):
                    if dpath and (path == dpath or path.startswith(dpath + "/")):
                        tree.append({"path": path, "interfaces": sorted(i for i in objects[path]
                                                                        if not i.startswith("org.freedesktop.DBus"))})
                props = {k: v for k, v in (objects.get(dpath, {}).get("org.bluez.Device1") or {}).items()
                         if k in ("Address", "AddressType", "Name", "Alias", "Class", "Appearance", "Icon", "Paired", "Bonded",
                                  "Trusted", "Blocked", "LegacyPairing", "Connected", "ServicesResolved", "Modalias",
                                  "RSSI", "TxPower", "WakeAllowed")}
                step("dbus", "كائنات BlueZ على D-Bus", "ok" if tree else "unavailable",
                     f"{len(tree)} كائن تحت مسار السماعة" if tree else "السماعة غير معروفة لدى BlueZ",
                     {"objects": tree, "device": props})
            except DBusCallError as exc:
                step("dbus", "كائنات BlueZ على D-Bus", "failed", "تعذر قراءة كائنات BlueZ")
                log.warning("scan dbus failed: %s", exc)

            # 3. UUIDs
            uuids = snap["device"].get("uuids") or []
            step("uuids", "UUIDs المعلنة", "ok" if uuids else "unavailable",
                 f"{len(uuids)} UUID من Device1.UUIDs" if uuids else "لا توجد UUIDs (السماعة غير معروفة؟)", uuids)

            # 4. SDP via sdptool
            sdp_records: list[dict] = []
            tool = shutil.which("sdptool")
            if not tool:
                step("sdp", "SDP", "unavailable", "الأداة sdptool غير مثبتة — استُخدمت نتائج الالتقاط كمرجع")
            elif not connected:
                step("sdp", "SDP", "skipped", "السماعة غير متصلة — لم يُرسل استعلام SDP حتى لا يُستدعى الجهاز")
            else:
                errors = []
                for uuid in ("0x0100", "0x1200"):
                    try:
                        out = await self._run([tool, "browse", "--xml", "--uuid", uuid, self.ctl.address], 25)
                        sdp_records += parse_sdptool_xml(out)
                    except AgentError as exc:
                        errors.append(exc.detail or exc.code)
                uniq = {r["handle"]: r for r in sdp_records if r.get("handle") is not None}
                sdp_records = list(uniq.values())
                step("sdp", "SDP", "ok" if sdp_records else "failed",
                     f"{len(sdp_records)} سجل خدمة (sdptool browse --xml)" if sdp_records else "لم تُرجع SDP أي سجل"
                     + (f" ({'; '.join(errors)[:120]})" if errors else ""), [describe_service(r) for r in sdp_records])

            # 5. RFCOMM + L2CAP from SDP (never opened)
            source = sdp_records or CAPTURE_SERVICES
            rf_list = [{"channel": s["rfcomm_channel"], "service": describe_service(s)["display"],
                        "name": s.get("name"), "blocked": describe_service(s)["blocked"],
                        "source": "SDP مباشر" if sdp_records else "الالتقاط"} for s in source if s.get("rfcomm_channel")]
            step("rfcomm", "قنوات RFCOMM", "ok",
                 "، ".join(f"{r['channel']} ({r['service']})" for r in rf_list)
                 + " — معلنة في SDP؛ لم تُفتح أي قناة", rf_list)
            l2 = [{"psm": s["l2cap_psm"], "protocol": sniffer.PSM_NAMES.get(s["l2cap_psm"], hex(s["l2cap_psm"])),
                   "service": describe_service(s)["display"], "source": "SDP مباشر" if sdp_records else "الالتقاط"}
                  for s in source if s.get("l2cap_psm")]
            step("l2cap", "قنوات L2CAP (PSM)", "ok", "، ".join(f"PSM 0x{x['psm']:04X} {x['protocol']}" for x in l2), l2)

            # HID descriptor from live SDP, compared with the capture
            live_hid = next((r["hid_descriptor"] for r in sdp_records if r.get("hid_descriptor")), None)
            if live_hid:
                same = bytes.fromhex(live_hid) == hid.CAPTURED_DESCRIPTOR
                step("hid_sdp", "واصف HID", "ok", "مطابق للالتقاط" if same else "مختلف عن الالتقاط — راجع التفاصيل",
                     {"descriptor": live_hid, "matches_capture": same,
                      "reports": hid.summarize(hid.parse_descriptor(bytes.fromhex(live_hid)))})

            # 6. GATT metadata
            gatt = []
            dpath = snap["device"].get("path")
            for path, ifs in sorted(objects.items()):
                if dpath and path.startswith(dpath + "/") and "org.bluez.GattService1" in ifs:
                    s = ifs["org.bluez.GattService1"]
                    chars = [{"uuid": o["org.bluez.GattCharacteristic1"].get("UUID"),
                              "flags": o["org.bluez.GattCharacteristic1"].get("Flags", [])}
                             for p2, o in sorted(objects.items()) if p2.startswith(path + "/") and "org.bluez.GattCharacteristic1" in o]
                    gatt.append({"uuid": s.get("UUID"), "primary": s.get("Primary"), "characteristics": chars})
            step("gatt", "خدمات GATT", "ok" if gatt else "unavailable",
                 f"{len(gatt)} خدمة GATT معروضة في BlueZ (بيانات وصفية فقط، لم تُقرأ أو تُكتب أي قيمة)" if gatt
                 else "لا توجد خدمات GATT معروضة لهذه السماعة في BlueZ", gatt)

            # 7. input devices
            try:
                devs = parse_proc_input(Path("/proc/bus/input/devices").read_text())
            except OSError:
                devs = None
            if devs is None:
                step("input", "أجهزة الإدخال", "unavailable", "تعذر قراءة /proc/bus/input/devices")
            else:
                names = [n for n in (snap["device"].get("alias"), snap["device"].get("name")) if n]
                mine = []
                for d in devs:
                    if d.get("bus") != "0005":
                        continue
                    nm = d.get("name", "")
                    if (d.get("uniq", "").upper() == self.ctl.address) or any(nm.startswith(n) for n in names):
                        d["kind"] = "AVRCP (BlueZ uinput)" if "AVRCP" in nm.upper() or not d.get("uniq") else "HID"
                        mine.append(d)
                step("input", "أجهزة الإدخال", "ok",
                     "، ".join(f"{d['name']} ← {d['kind']}" for d in mine) if mine else "لا يوجد جهاز إدخال مرتبط بالسماعة", mine)

            # 8. capture status
            st = self.tail.status()
            recs = (st["stats"] or {}).get("records", 0)
            step("capture", "مراقبة حركة Bluetooth", "ok" if st["active"] and recs else "unavailable",
                 f"ملف الالتقاط نشط: {recs} سجل" if st["active"] and recs
                 else "لا يوجد التقاط نشط — شغّل btmon لرؤية الحزم", st)
            result["finished_at"] = time.time()
            result["ok"] = True
            self._add_log(etype="فحص آمن", channel="الوكيل", direction="—", data="انتهى الفحص الآمن دون إرسال أي أوامر خاصة بالمصنّع",
                          result="اكتمل")
        finally:
            self.scan_running = False
        self.scan = result
        self._emit({"type": "discovery_scan", "running": False})
        self._emit({"type": "discovery_changed"})
        return result

    async def _run(self, argv: list[str], timeout: float) -> str:
        if not re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", argv[-1]):
            raise AgentError("bad_request", "address")
        try:
            proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.DEVNULL)
        except OSError as exc:
            raise AgentError("unsupported", repr(exc)) from None
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise AgentError("timeout", " ".join(argv[:2])) from None
        if proc.returncode != 0:
            raise AgentError("dbus_error", err.decode(errors="replace").strip()[:200] or f"exit {proc.returncode}")
        return out.decode(errors="replace")

    # ------------------------------------------------------------------ research mode
    def research_start(self) -> dict:
        self.research_active = True
        self.research_started = time.time()
        cap = self.tail.status()
        self._add_log(etype="وضع البحث", channel="الوكيل", direction="—",
                      data="بدأ وضع البحث" + ("" if cap["active"] else " — لا يوجد التقاط HCI نشط؛ ستُسجل أحداث النظام فقط"),
                      result="بدأ")
        self._emit({"type": "discovery_changed"})
        return {"ok": True, "capture": cap}

    def research_stop(self) -> dict:
        self.research_active = False
        self._add_log(etype="وضع البحث", channel="الوكيل", direction="—", data="انتهى وضع البحث", result="توقف")
        self._emit({"type": "discovery_changed"})
        return {"ok": True}

    def _new_trial(self, action: str, origin: str, start: float, end: float) -> dict:
        if not self.research_active:
            raise AgentError("bad_request", "research mode not active")
        if action not in RESEARCH_ACTIONS:
            raise AgentError("action_not_allowed", action)
        self._trial_id += 1
        trial = {"id": self._trial_id, "action": action, "label": RESEARCH_ACTIONS[action]["label"], "origin": origin,
                 "created": time.time(), "window": [start, end], "status": "pending", "packets": [], "system_events": [],
                 "findings": [], "host_result": None, "error": None, "capture_active": self.tail.status()["active"]}
        self.trials.append(trial)
        self._add_log(etype="وضع البحث", channel="تجربة", direction="—",
                      data=f"تجربة #{trial['id']}: {trial['label']} — "
                           + ("تنفيذ من الحاسوب" if origin == "host" else "بانتظار الضغط على زر السماعة"),
                      result="قيد المراقبة")
        self._emit({"type": "research_trial", "trial": trial})
        return trial

    async def research_headset(self, action: str) -> dict:
        now = time.time()
        trial = self._new_trial(action, "headset", now, now + HEADSET_WINDOW)
        asyncio.get_running_loop().create_task(self._finalize_later(trial, HEADSET_WINDOW + 0.5))
        return {"ok": True, "trial": trial}

    async def research_host(self, action: str) -> dict:
        spec = RESEARCH_ACTIONS.get(action)
        if spec is None:
            raise AgentError("action_not_allowed", action)
        if spec["host"] is None:
            raise AgentError("unsupported", "no safe host-side mute")
        now = time.time()
        trial = self._new_trial(action, "host", now - HOST_WINDOW_BEFORE, now + HOST_WINDOW_AFTER)
        try:
            trial["host_result"] = await self.ctl.perform(spec["host"])
        except AgentError as err:
            trial["error"] = err.message
            trial["status"] = "failed"
            self._add_log(etype="وضع البحث", channel="تجربة", direction="—", data=f"تجربة #{trial['id']}: {err.message}",
                          result="فشل")
            self._emit({"type": "research_trial", "trial": trial})
            raise
        remaining = trial["window"][1] - time.time() + 0.4
        asyncio.get_running_loop().create_task(self._finalize_later(trial, max(0.0, remaining)))
        return {"ok": True, "trial": trial}

    async def _finalize_later(self, trial: dict, delay: float) -> None:
        await asyncio.sleep(delay)
        self.finalize(trial)

    def finalize(self, trial: dict) -> None:
        start, end = trial["window"]
        packets = self.tail.window(start, end)
        trial["packets"] = [p.to_json() for p in packets]
        trial["system_events"] = [{"ts": ts, **m} for ts, m in self.system_events if start <= ts <= end]
        trial["findings"] = self._findings(trial, packets)
        trial["status"] = "done"
        for f in trial["findings"]:
            self._add_log(etype="اكتشاف", channel=f"تجربة #{trial['id']}", direction="—", data=f["text"],
                          result=f["kind_label"], classification=f.get("classification", "standard"))
        self._emit({"type": "research_trial", "trial": trial})
        self._emit({"type": "discovery_changed"})

    def _findings(self, trial: dict, packets: list[sniffer.Packet]) -> list[dict]:
        out = []

        def add(text, kind, classification="standard"):
            out.append({"text": text, "kind": kind, "classification": classification,
                        "kind_label": {"confirmed": "مؤكد", "info": "معلومة", "warning": "تنبيه", "vendor": "خاص بالمصنّع"}[kind]})

        spec = RESEARCH_ACTIONS[trial["action"]]
        seen_ops = set()
        for p in packets:
            f = p.fields
            if p.protocol == "AVRCP" and "operation" in f and not f.get("response") and not f.get("released"):
                who = "السماعة" if p.direction == "rx" else "الحاسوب"
                seen_ops.add((p.direction, f["operation"]))
                add(f"{who} أرسل AVRCP PASS THROUGH: {f['operation']} ({f['operation_id']})", "confirmed")
            elif p.protocol == "AVRCP" and f.get("event") == "VOLUME_CHANGED" and f.get("ctype") == "CHANGED":
                add(f"السماعة أبلغت عن تغير مستوى الصوت إلى {f.get('volume')}/127 (VOLUME_CHANGED)", "confirmed")
            elif p.protocol == "AVRCP" and f.get("pdu") == "SetAbsoluteVolume":
                if f.get("response"):
                    add(f"رد السماعة على SetAbsoluteVolume: {f.get('ctype')} ({f.get('volume')}/127)",
                        "confirmed" if f.get("ctype") == "ACCEPTED" else "warning")
            elif p.protocol == "HID" and f.get("pressed") is not None:
                add(f"السماعة أرسلت تقرير HID: {', '.join(f['pressed']) or 'تحرير'}", "confirmed")
            elif p.protocol == "HFP" and p.direction == "rx":
                add(f"السماعة أرسلت أمر HFP: {f.get('at')}", "info", p.classification)
            elif p.classification == "vendor":
                add(f"حركة خاصة بالمصنّع: {p.summary}", "vendor", "vendor")
            elif p.protocol == "AVDTP" and p.opcode and ("START" in p.opcode or "SUSPEND" in p.opcode):
                add(p.summary, "info")
        if trial["origin"] == "headset" and packets and ("rx", spec["headset_op"]) not in seen_ops:
            if not any(x[0] == "rx" for x in seen_ops):
                add(f"لم تُرسل السماعة أي أمر PASS THROUGH خلال النافذة — قد تنفذ «{spec['label']}» داخليًا أو عبر قناة أخرى",
                    "warning")
        for _, m in [(0, e) for e in trial.get("system_events", [])]:
            if m.get("type") == "headset_button" and m.get("pressed"):
                add(f"جهاز إدخال BlueZ استقبل مفتاح: {m.get('label')}", "info")
            elif m.get("type") == "volume_changed" and m.get("value") is not None:
                add(f"BlueZ حدّث مستوى الصوت إلى {m['value']}%", "info")
            elif m.get("type") == "playback_changed":
                add(f"حالة المشغل تغيرت إلى {m.get('status')}", "info")
        overlapping = [t["id"] for t in self.trials if t is not trial and t["window"][0] < trial["window"][1]
                       and trial["window"][0] < t["window"][1]]
        if overlapping:
            add("نافذة هذه التجربة تتداخل مع التجربة " + "، ".join(f"#{i}" for i in overlapping)
                + " — قد تنتمي بعض الحزم إلى التجربة الأخرى. كرر التجربة منفردة للتأكد", "warning")
        if not trial["capture_active"] and not packets:
            add("لا يوجد التقاط HCI نشط، فلا يمكن رؤية الحزم. شغّل: sudo btmon -w " + self.capture_path, "warning")
        return out

    # ------------------------------------------------------------------ uploaded capture analysis
    async def analyze_upload(self, data: bytes) -> dict:
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, sniffer.analyze_bytes, data, self.ctl.address, 3000)
        except ValueError as exc:
            raise AgentError("bad_request", str(exc)) from None
        s = result["summary"]
        self.analysis = {
            "at": time.time(), "size": len(data), "datalink": result["datalink"], "stats": result["stats"],
            "devices": result["devices"], "services": [describe_service(x) for x in result["services"]],
            "summary": {k: v for k, v in s.items() if k != "vendor_packets"}, "vendor_packets": s["vendor_packets"][:100],
        }
        self._add_log(etype="تحليل التقاط", channel="ملف", direction="قراءة فقط",
                      data=f"حُلّل ملف ({len(data)} بايت): {result['stats']['packets']} حزمة، "
                           f"{s['by_classification'].get('vendor', 0)} حزمة خاصة بالمصنّع", result="اكتمل")
        self._emit({"type": "discovery_changed"})
        return {**self.analysis, "packets": result["packets"], "truncated": result["truncated"]}

    # ------------------------------------------------------------------ views
    def services_view(self, snap: dict) -> list[dict]:
        live_uuids = {u["uuid"] for u in snap["device"].get("uuids", [])}
        sdp_live = {r["handle"]: r for r in (self.scan or {}).get("sdp", [])}
        rows = []
        for ref in CAPTURE_SERVICES:
            live = sdp_live.get(ref["handle"])
            uuid = ref["classes"][0]
            in_bluez = uuid in live_uuids
            if live:
                state, state_label = "present", "الخدمة موجودة (SDP مباشر)"
            elif in_bluez:
                state, state_label = "present", "الخدمة موجودة (BlueZ UUIDs)"
            elif snap["device"].get("known"):
                state, state_label = "unavailable", "الخدمة غير متاحة حاليًا"
            else:
                state, state_label = "unknown", "غير معروف (السماعة غير معروفة لدى BlueZ)"
            desc = describe_service(ref)
            rows.append({
                **desc, "uuid": uuid, "profile": ref["profile"], "state": state, "state_label": state_label,
                "rfcomm_channel": (live or ref).get("rfcomm_channel"), "l2cap_psm": (live or ref).get("l2cap_psm"),
                "psm_name": sniffer.PSM_NAMES.get((live or ref).get("l2cap_psm") or -1),
                "features": (live or ref).get("features"), "live_sdp": bool(live),
                "changed": bool(live and (live.get("rfcomm_channel") != ref["rfcomm_channel"] or live.get("l2cap_psm") != ref["l2cap_psm"])),
            })
        for h, r in sdp_live.items():
            if h not in {x["handle"] for x in CAPTURE_SERVICES}:
                rows.append({**describe_service(r), "uuid": (r.get("classes") or ["?"])[0], "profile": "جديد — لم يظهر في الالتقاط",
                             "state": "present", "state_label": "الخدمة موجودة (جديدة)", "live_sdp": True, "changed": True,
                             "psm_name": sniffer.PSM_NAMES.get(r.get("l2cap_psm") or -1)})
        return rows

    def capability_matrix(self, snap: dict) -> list[dict]:
        o = self.observed
        v = snap.get("verified", {})
        connected = snap["connection"]["connected"]
        rows: list[dict] = []

        def row(fid, name, status, source, method, safe, evidence, safe_ok=True):
            rows.append({"id": fid, "function": name, "status": status, "status_label": STATUS_LABELS[status],
                         "source": source, "method": method, "safe": safe, "safe_ok": safe_ok, "evidence": evidence})

        hp = o["headset_passthrough"]
        row("headset_play_pause", "زر التشغيل/الإيقاف في السماعة", "confirmed", "AVRCP PASS THROUGH",
            "مراقبة (btmon / جهاز إدخال BlueZ)", "نعم",
            "الالتقاط: PLAY 0x44 وPAUSE 0x46 (Frames 2388–2585)"
            + (f"؛ رُصد الآن: {', '.join(f'{k}×{n}' for k, n in hp.items() if k in ('PLAY', 'PAUSE'))}" if any(k in hp for k in ("PLAY", "PAUSE")) else ""))
        row("host_play_pause", "التشغيل/الإيقاف من اللوحة", "confirmed" if "play_pause" in v else "unknown",
            "MPRIS (مشغل الحاسوب)", "BlueZ/MPRIS", "نعم",
            "تحقق أثناء التشغيل" if "play_pause" in v else "لم يُتحقق بعد — استخدم زري التشغيل")
        row("playback_status", "حالة التشغيل (PLAYBACK_STATUS_CHANGED)", "confirmed", "AVRCP", "مراقبة الالتقاط", "نعم",
            "السماعة سجّلت الحدث لدى الحاسوب (Frame 223)")
        row("track_info", "معلومات المقطع (GetElementAttributes)", "confirmed", "AVRCP", "مراقبة الالتقاط", "نعم",
            "السماعة تطلبها من الحاسوب (Frames 204، 244)؛ لا تعرضها (لا شاشة)")
        row("volume_read", "قراءة مستوى الصوت", "confirmed", "AVRCP (VOLUME_CHANGED)", "BlueZ (MediaTransport1.Volume)", "نعم",
            "الالتقاط: 127→120→127 (Frames 2563، 2567)" + ("؛ متاح الآن" if snap["volume"]["available"] else ""))
        vs = "confirmed" if ("volume_write" in v or o["set_absolute_volume"]) else ("advertised" if connected else "unknown")
        row("volume_set", "ضبط مستوى الصوت (SetAbsoluteVolume)", vs, "AVRCP", "BlueZ", "نعم",
            "تحقق أثناء التشغيل" if "volume_write" in v else ("رُصد قبول السماعة للأمر" if o["set_absolute_volume"]
                                                                else "الهدف من الفئة 2 يدعمه نظريًا؛ لم يظهر في الالتقاط"))
        vb = hp.get("VOLUME_UP", 0) + hp.get("VOLUME_DOWN", 0)
        row("volume_buttons", "أزرار الصوت في السماعة", "confirmed" if vb or o["volume_notifications"] else "unknown",
            "AVRCP", "وضع البحث: اضغط الزر وراقب", "نعم",
            ("رُصد PASS THROUGH للصوت" if vb else "")
            or ("السماعة تُبلغ بـ VOLUME_CHANGED (لا PASS THROUGH)" if o["volume_notifications"] else "يُرجّح أنها محلية + إشعار؛ غير مثبت"))
        nx = hp.get("FORWARD", 0) + hp.get("BACKWARD", 0)
        row("next_prev", "التالي/السابق من السماعة", "confirmed" if nx else "unknown", "AVRCP",
            "وضع البحث: جرّب الضغط المزدوج/المطوّل", "نعم",
            f"رُصد: {', '.join(k for k in ('FORWARD', 'BACKWARD') if hp.get(k))}" if nx else "لم يظهر في الالتقاط")
        row("mute", "كتم الصوت", "confirmed" if hp.get("MUTE") else "unknown", "AVRCP", "وضع البحث (من السماعة فقط)", "نعم",
            "رُصد MUTE 0x43" if hp.get("MUTE") else "لا توجد واجهة كتم مؤكدة")
        row("avrcp_events", "أحداث AVRCP المسجلة", "confirmed", "AVRCP", "مراقبة الالتقاط", "نعم",
            "السماعة: PLAYBACK_STATUS، TRACK_CHANGED؛ الحاسوب: VOLUME_CHANGED"
            + (f"؛ رُصد الآن: {', '.join(sorted(o['avrcp_events']))}" if o["avrcp_events"] else ""))
        row("battery_hfp", "البطارية", "confirmed", "HFP (AT+IPHONEACCEV)", "BlueZ (Battery1)", "نعم",
            "الالتقاط: 70%→60%→70%" + (f"؛ الآن {snap['battery']['percentage']}%" if snap["battery"]["available"] else ""))
        row("battery_avrcp", "البطارية عبر AVRCP (BATT_STATUS_CHANGED)",
            "confirmed" if "BATT_STATUS_CHANGED" in o["avrcp_events"] else "advertised", "AVRCP", "تحتاج اختبار (لا يسجّلها BlueZ)",
            "نعم", "معلنة في قدرات هدف السماعة (Frame 229)؛ لم يُسجَّل عليها")
        row("a2dp", "بث الصوت (A2DP SBC)", "confirmed", "A2DP/AVDTP", "BlueZ (MediaTransport1)", "نعم",
            "SBC ‏48kHz، bitpool 2–38 (Frame 140)")
        row("a2dp_seid2", "نقطة A2DP الثانية (SEID 2)", "confirmed" if len(o["codecs"]) > 1 else "unknown", "AVDTP",
            "التقاط مع مسح ذاكرة BlueZ المؤقتة", "نعم",
            ("ترميزات رُصدت: " + "، ".join(o["codecs"])) if o["codecs"] else "لم تُطلب إمكاناتها في الالتقاط")
        row("hfp_calls", "المكالمات (HFP)", "advertised", "HFP 1.8", "تحتاج مكالمة اختبار", "نعم",
            "اتصال HFP مؤكد في الالتقاط؛ أوامر المكالمات لم تظهر"
            + (f"؛ أوامر رُصدت: {', '.join(sorted(x for x in o['hfp_commands'] if x))}" if o["hfp_commands"] else ""))
        hid_state = "confirmed" if o["hid_reports"] else "advertised"
        row("hid", "HID (مفاتيح الوسائط)", hid_state, "SDP/HID",
            "تحتاج اختبار اتصال آمن" if not o["hid_reports"] else "مراقبة تقارير HID", "نعم",
            (f"تقارير رُصدت: {', '.join(o['hid_usages'])}" if o["hid_reports"]
             else "معلن لكنه غير متاح حاليًا / يحتاج اختبار اتصال آمن"))
        row("spp", "المنفذ التسلسلي SPP (RFCOMM 1)", "advertised", "SDP", "تحتاج تحليل", "لا ترسل أوامر مجهولة",
            "معلن فقط؛ لم يُفتح", safe_ok=False)
        probe = self.ctl._rfcomm_last or {}
        jieli_ev = "خدمة مخصصة من الشركة - البروتوكول غير معروف"
        if probe.get("connected"):
            jieli_ev += f"؛ استكشاف: اتصال ناجح، {probe.get('bytes_read', 0)} بايت واردة"
        elif probe.get("state") == "error":
            jieli_ev += f"؛ استكشاف: فشل الاتصال ({probe.get('note', '')})"
        if o["jieli_frames"]:
            jieli_ev += f"؛ رُصدت {o['jieli_frames']} رسالة عليها"
        row("jieli", "خدمة JieLi المخصصة (RFCOMM 10)", "confirmed" if probe.get("connected") else "present", "SDP",
            "تحتاج تحليل (التقاط من تطبيق oraimo)", "لا ترسل أوامر مجهولة", jieli_ev, safe_ok=False)
        gatt = (self.scan or {}).get("gatt")
        row("gatt", "Bluetooth منخفض الطاقة (GATT)", "present" if gatt else "unknown", "GATT",
            "الفحص الآمن (بيانات وصفية فقط)", "نعم (قراءة البيانات الوصفية فقط)",
            f"{len(gatt)} خدمة GATT" if gatt else "لم تُعرض خدمات GATT في BlueZ")
        row("firmware", "معلومات البرنامج الداخلي", "unknown", "PnP/DI", "—", "لا ترسل أوامر مجهولة",
            "الإصدار 0x0240 من سجل PnP فقط؛ لا بروتوكول آمن للمزيد", safe_ok=False)
        return rows

    def view(self, snap: dict) -> dict:
        d = snap["device"]
        live_hid = (self.scan or {}).get("hid_sdp")
        return {
            "device": {
                "name": d.get("alias") or d.get("name") or dev.PROFILE.name, "address": d.get("address") or self.ctl.address,
                "manufacturer": dev.PROFILE.oui_vendor, "chipset": dev.PROFILE.chipset_vendor,
                "modalias": d.get("modalias_parsed"), "connected": snap["connection"]["connected"],
                "connection_state": snap["connection"]["state"], "known": d.get("known", False),
                "profiles": list(dev.PROFILE.profiles), "uuids": d.get("uuids", []),
            },
            "services": self.services_view(snap),
            "l2cap_capture": CAPTURE_L2CAP,
            "avrcp": {
                **AVRCP_REFERENCE,
                "live": {
                    "control_connected": any(r["id"] == "avrcp" and r["status"] == "available" for r in snap["capabilities"]),
                    "volume": snap["volume"], "playback": snap["media"].get("status"),
                    "player": (snap["media"].get("player") or {}).get("identity"),
                    "track": (snap["media"].get("player") or {}).get("metadata"),
                },
                "observed": {"headset_passthrough": self.observed["headset_passthrough"],
                             "events": sorted(self.observed["avrcp_events"]), "pdus": sorted(self.observed["avrcp_pdus"])},
            },
            "hid": {
                "status_label": "معلن لكنه غير متاح حاليًا / يحتاج اختبار اتصال آمن" if not self.observed["hid_reports"]
                else "رُصدت تقارير HID",
                "reports": hid.summarize(hid.CAPTURED_FIELDS), "descriptor": hid.CAPTURED_DESCRIPTOR.hex(" "),
                "live_sdp": live_hid, "observed_reports": self.observed["hid_reports"],
                "capture_notes": ["السماعة أغلقت قناتي HID اللتين فتحهما الحاسوب خلال 29 ms (Frames 216، 222)",
                                  "ثم حاولت فتح HID بنفسها ورفضها BlueZ (Frames 537–568)",
                                  "لم يُتبادل أي تقرير HID في الالتقاط"],
            },
            "jieli": {
                "uuid": dev.JIELI_CUSTOM_SPP_UUID, "rfcomm_channel": 10, "name": "JL_SPP",
                "status_label": "خدمة مخصصة من الشركة - البروتوكول غير معروف",
                "policy": "لا يفتح الوكيل هذه القناة ولا يرسل إليها أي بايت",
                "observed_frames": self.observed["jieli_frames"], "observed_open": self.observed["jieli_opened"],
                "probe_enabled": self.ctl.rfcomm.enabled,
                "probe": self.ctl._rfcomm_last,
            },
            "matrix": self.capability_matrix(snap),
            "scan": self.scan, "scan_running": self.scan_running,
            "research": {"active": self.research_active, "started": self.research_started,
                         "actions": [{"id": k, "label": v["label"], "host": v["host"] is not None}
                                     for k, v in RESEARCH_ACTIONS.items()],
                         "trials": list(self.trials)[-20:],
                         "headset_window": HEADSET_WINDOW},
            "capture": self.capture_status(),
            "analysis": self.analysis,
        }

    def log_entries(self, limit: int = 500) -> list[dict]:
        return list(self.log)[-limit:]

    def clear_log(self) -> None:
        self.log.clear()
