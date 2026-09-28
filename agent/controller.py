"""Controller core: state snapshots, live events, and whitelisted actions.

State is always *read from the OS* (BlueZ / MPRIS). The controller never sets
UI state on its own: every change shown to the user comes from a snapshot
diff, and a capability is reported as working only after the agent observed
it working during this run ("runtime verified").
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from datetime import datetime
from typing import Any, Awaitable, Callable

from . import device as dev
from .bluetooth import BluezAPI, MprisAPI
from .buttons import ButtonWatcher
from . import rfcomm
from .discovery import Discovery
from .errors import AgentError, DBusCallError, map_dbus_error

log = logging.getLogger("necklace.controller")

AGENT_VERSION = "1.0.0"

# The only actions the browser can trigger. Anything else is rejected.
ALLOWED_ACTIONS = frozenset({
    "play", "pause", "next", "previous", "set_volume", "volume_up", "volume_down",
    "reconnect", "select_player", "clear_log",
    # Phase 2: read-only discovery and passive research
    "safe_scan", "research_start", "research_stop", "research_headset", "research_host",
    "analyze_capture", "clear_discovery_log",
    # Phase 3: read-only RFCOMM connection exploration (opt-in, connect + read only).
    "rfcomm_probe",
})
# Discovery actions run outside the action lock (a research "host" trial calls perform() itself).
LOCK_FREE_ACTIONS = frozenset({"safe_scan", "research_start", "research_stop", "research_headset", "research_host",
                               "analyze_capture", "clear_discovery_log", "rfcomm_probe"})
# Explicitly refused, even if a route were ever added by mistake. Note: opening
# RFCOMM for *exploration* is NOT forbidden (see "rfcomm_probe" above) — only
# *sending* unverified data to the device is. Connection and command are split
# deliberately: we may connect and read, we never write, authenticate, or issue
# vendor/RCSP commands, and never touch firmware/OTA/factory-reset.
FORBIDDEN_ACTIONS = frozenset({
    "raw_hci", "raw_l2cap", "raw_avctp", "raw_rfcomm", "raw_sdp",
    "firmware_update", "ota_update", "custom_spp_write", "spp_write", "rfcomm_write",
    "jieli_command", "rcsp_command", "rcsp_auth", "gatt_write", "factory_reset", "vendor_command",
})

A2DP_SINK_UUID = dev.sig_uuid(0x110B)
VERIFY_TIMEOUT = 3.0


def default_capture_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "necklace-controller", "live.btsnoop")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class EventLog:
    def __init__(self, maxlen: int = 500):
        self._entries: deque[dict] = deque(maxlen=maxlen)
        self._next_id = 1

    def add(self, etype: str, message: str, severity: str = "info", data: dict | None = None,
            coalesce_seconds: float = 0.0) -> dict:
        ts = time.time()
        if coalesce_seconds and self._entries:
            last = self._entries[-1]
            if last["type"] == etype and ts - last["_t"] < coalesce_seconds:
                last.update(message=message, data=data or {}, timestamp=now_iso(), _t=ts)
                return last
        entry = {"id": self._next_id, "timestamp": now_iso(), "type": etype, "severity": severity,
                 "message": message, "data": data or {}, "_t": ts}
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def entries(self, limit: int | None = None) -> list[dict]:
        items = list(self._entries)[-limit:] if limit else list(self._entries)
        return [{k: v for k, v in e.items() if not k.startswith("_")} for e in items]

    def clear(self) -> None:
        self._entries.clear()


def public(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if not k.startswith("_")}


class Controller:
    def __init__(self, address: str = dev.DEFAULT_ADDRESS, adapter: str | None = None,
                 bind: str = "127.0.0.1:8765", enable_buttons: bool = True, capture_path: str | None = None,
                 allow_rfcomm_probe: bool = False):
        self.address = dev.normalize_address(address)
        self.adapter_name = adapter
        self.bind = bind
        self.log = EventLog()
        self.bluez = BluezAPI(self._on_signal, self._on_bus_state)
        self.mpris = MprisAPI(self._on_signal, self._on_bus_state)
        self.buttons = ButtonWatcher(self._on_button, self._on_bus_state) if enable_buttons else None
        self._subscribers: set[Callable[[dict], Awaitable[None]]] = set()
        self._snapshot: dict | None = None
        self._last_bz: dict | None = None
        self._refresh_lock = asyncio.Lock()
        self._refresh_pending: asyncio.TimerHandle | None = None
        self._action_lock = asyncio.Lock()
        self._connecting = False
        self._connect_error: str | None = None
        self._selected_player: str | None = None
        self._last_active_player: str | None = None
        self._verified: dict[str, str] = {}  # capability -> ISO time verified at runtime
        self._changed = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._started = time.time()
        self.discovery = Discovery(self, capture_path or default_capture_path())
        # Read-only RFCOMM explorer for the JieLi channel. Off unless explicitly enabled.
        self.rfcomm = rfcomm.RfcommExplorer(self.address, rfcomm.DEFAULT_CHANNEL, enabled=allow_rfcomm_probe)
        self._rfcomm_last: dict | None = None

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self.log.add("agent", "بدأ تشغيل الوكيل المحلي", "info", {"version": AGENT_VERSION})
        await self.refresh(initial=True)
        self.discovery.start()
        self._tasks.append(asyncio.get_running_loop().create_task(self._resync_loop()))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        if self.buttons:
            await self.buttons.stop()
        await self.discovery.stop()
        await self.bluez.conn.close()
        await self.mpris.conn.close()

    async def _resync_loop(self) -> None:
        # Safety net only: normal updates arrive via D-Bus signals.
        while True:
            await asyncio.sleep(20)
            try:
                await self.refresh()
            except Exception:
                log.exception("periodic refresh failed")

    # ------------------------------------------------------------------ pub/sub
    def subscribe(self, fn: Callable[[dict], Awaitable[None]]) -> None:
        self._subscribers.add(fn)

    def unsubscribe(self, fn: Callable[[dict], Awaitable[None]]) -> None:
        self._subscribers.discard(fn)

    async def _broadcast(self, message: dict) -> None:
        self.discovery.observe_system(message)
        for fn in list(self._subscribers):
            try:
                await fn(message)
            except Exception:
                self._subscribers.discard(fn)

    async def _emit_log(self, etype, message, severity="info", data=None, coalesce=0.0) -> None:
        entry = self.log.add(etype, message, severity, data, coalesce)
        await self._broadcast({"type": "log", "entry": public(entry)})

    # ------------------------------------------------------------------ signals
    def _on_signal(self, msg) -> None:
        self._schedule_refresh()

    def _on_bus_state(self) -> None:
        self._schedule_refresh()

    def _schedule_refresh(self, delay: float = 0.12) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._refresh_pending is not None:
            return

        def fire():
            self._refresh_pending = None
            loop.create_task(self._safe_refresh())

        self._refresh_pending = loop.call_later(delay, fire)

    async def _safe_refresh(self) -> None:
        try:
            await self.refresh()
        except Exception:
            log.exception("refresh failed")

    def _on_button(self, info: dict) -> None:
        async def emit():
            await self._broadcast({"type": "headset_button", **info})
            if info.get("pressed"):
                self._mark_verified("headset_buttons")
                await self._emit_log("headset_button", f"ضغطة من السماعة: {info['label']}", "info", info)
        asyncio.get_running_loop().create_task(emit())

    # ------------------------------------------------------------------ snapshot
    async def _bluez_state(self) -> dict:
        state: dict[str, Any] = {
            "service": "unknown", "error": None,
            "adapter": {"present": False},
            "device": {"known": False},
            "media_control": None, "battery": None, "transport": None, "input": False,
        }
        try:
            if not await self.bluez.conn.ensure():
                state.update(service="unavailable", error="dbus_unavailable")
                return state
            if not await self.bluez.available():
                state.update(service="unavailable", error="bluez_unavailable")
                return state
            objects = await self.bluez.managed_objects()
        except DBusCallError as exc:
            err = map_dbus_error(exc)
            log.warning("BlueZ query failed: %s", exc)
            state.update(service="unavailable", error=err.code)
            return state
        state["service"] = "available"

        adapters = {p: o["org.bluez.Adapter1"] for p, o in objects.items() if "org.bluez.Adapter1" in o}
        adapter_path = None
        if self.adapter_name:
            adapter_path = next((p for p in adapters if p.endswith("/" + self.adapter_name)), None)
        elif adapters:
            adapter_path = sorted(adapters)[0]
        if adapter_path:
            a = adapters[adapter_path]
            state["adapter"] = {
                "present": True, "path": adapter_path, "address": a.get("Address"),
                "name": a.get("Alias") or a.get("Name"), "powered": bool(a.get("Powered")),
                "power_state": a.get("PowerState"), "discovering": bool(a.get("Discovering")),
            }

        dev_path = None
        for p, o in objects.items():
            d = o.get("org.bluez.Device1")
            if d and str(d.get("Address", "")).upper() == self.address:
                if adapter_path is None or d.get("Adapter") == adapter_path:
                    dev_path = p
                    break
        if dev_path is None:
            return state
        d = objects[dev_path]["org.bluez.Device1"]
        state["device"] = {
            "known": True, "path": dev_path, "address": d.get("Address"), "name": d.get("Name"),
            "alias": d.get("Alias"), "paired": bool(d.get("Paired")), "bonded": bool(d.get("Bonded", d.get("Paired"))),
            "trusted": bool(d.get("Trusted")), "blocked": bool(d.get("Blocked")),
            "connected": bool(d.get("Connected")), "services_resolved": bool(d.get("ServicesResolved")),
            "modalias": d.get("Modalias"), "uuids": list(d.get("UUIDs") or []), "icon": d.get("Icon"),
        }
        o = objects[dev_path]
        if "org.bluez.MediaControl1" in o:
            state["media_control"] = {"connected": bool(o["org.bluez.MediaControl1"].get("Connected"))}
        if "org.bluez.Battery1" in o:
            b = o["org.bluez.Battery1"]
            pct = b.get("Percentage")
            state["battery"] = {"percentage": int(pct) if pct is not None else None, "source": b.get("Source")}
        state["input"] = "org.bluez.Input1" in o
        transports = [(p, x["org.bluez.MediaTransport1"]) for p, x in objects.items()
                      if "org.bluez.MediaTransport1" in x and x["org.bluez.MediaTransport1"].get("Device") == dev_path]
        # Prefer the A2DP sink transport (host is the A2DP source for this headset).
        transports.sort(key=lambda t: str(t[1].get("UUID", "")).lower() != A2DP_SINK_UUID)
        if transports:
            p, t = transports[0]
            state["transport"] = {"path": p, "state": t.get("State"), "uuid": t.get("UUID"),
                                  "codec": t.get("Codec"), "volume": t.get("Volume")}
        return state

    async def _media_state(self) -> dict:
        state: dict[str, Any] = {"available": False, "reason": None, "player": None, "players": [],
                                 "selected": self._selected_player}
        try:
            if not await self.mpris.conn.ensure():
                state["reason"] = "session_bus_unavailable"
                return state
            players = await self.mpris.players()
        except DBusCallError as exc:
            log.warning("MPRIS query failed: %s", exc)
            state["reason"] = map_dbus_error(exc, action="media").code
            return state
        state["players"] = players
        for p in players:
            if p["status"] == "playing":
                self._last_active_player = p["bus_name"]
        chosen = None
        by_name = {p["bus_name"]: p for p in players}
        if self._selected_player and self._selected_player in by_name:
            chosen = by_name[self._selected_player]
        if chosen is None:
            chosen = next((p for p in players if p["status"] == "playing"), None)
        if chosen is None and self._last_active_player in by_name:
            chosen = by_name[self._last_active_player]
        if chosen is None and players:
            chosen = players[0]
        if chosen is None:
            state["reason"] = "no_media_player"
            return state
        state["available"] = True
        state["player"] = chosen
        return state

    def _compose(self, bz: dict, media: dict) -> dict:
        d = bz["device"]
        connected = bool(d.get("connected"))
        if connected:
            conn_state = "connected"
        elif self._connecting:
            conn_state = "connecting"
        elif self._connect_error:
            conn_state = "failed"
        else:
            conn_state = "disconnected"

        bat = bz["battery"] if connected else None
        pct = bat["percentage"] if bat else None
        battery = {"available": pct is not None, "percentage": pct, "level": dev.battery_level(pct),
                   "source": bat.get("source") if bat else None}

        tr = bz["transport"] if connected else None
        raw = tr.get("volume") if tr else None
        volume = {
            "available": raw is not None, "raw": raw, "percent": dev.raw_to_percent(raw),
            "writable": raw is not None, "write_verified": "volume_write" in self._verified,
            "mute_supported": False,
            "reason": None if raw is not None else ("device_disconnected" if not connected else
                                                     "no_transport" if tr is None else "no_absolute_volume"),
        }
        stream = tr.get("state") if tr else None

        pstatus = media["player"]["status"] if media.get("player") else None
        if pstatus not in ("playing", "paused", "stopped"):
            pstatus = "unknown"
        media_out = {**media, "status": pstatus, "stream": stream or "none"}

        buttons = self.buttons.status() if self.buttons else {"available": False, "reason": "disabled"}
        parsed_modalias = dev.parse_modalias(d.get("modalias"))
        device_out = {
            **d,
            "uuids": dev.describe_uuids(d.get("uuids")),
            "modalias_parsed": parsed_modalias,
            "modalias_matches_capture": dev.modalias_matches_profile(parsed_modalias),
            "is_target_address": True,
            "target_address": self.address,
        }
        snap = {
            "updated_at": now_iso(),
            "agent": {"version": AGENT_VERSION, "bind": self.bind, "uptime_s": int(time.time() - self._started)},
            "bluetooth": {"service": bz["service"], "error": bz["error"], "adapter": bz["adapter"],
                          "system_bus": self.bluez.conn.connected, "session_bus": self.mpris.conn.connected},
            "device": device_out,
            "connection": {"state": conn_state, "connected": connected, "type": dev.PROFILE.connection_type,
                           "error": self._connect_error},
            "battery": battery,
            "volume": volume,
            "media": media_out,
            "buttons": buttons,
            "verified": dict(self._verified),
        }
        snap["capabilities"] = self._capabilities(snap, bz)
        return snap

    # ------------------------------------------------------------------ capabilities
    def _capabilities(self, s: dict, bz: dict) -> list[dict]:
        rows: list[dict] = []
        d = s["device"]
        uuids = [u["uuid"] for u in d.get("uuids", [])]
        connected = s["connection"]["connected"]
        v = self._verified

        def row(cid, label, status, detail, evidence=(), verified=False):
            rows.append({"id": cid, "label": label, "status": status, "detail": detail,
                         "evidence": list(evidence), "runtime_verified": verified})

        svc = s["bluetooth"]["service"]
        err = s["bluetooth"]["error"]
        if svc == "available":
            row("bluez", "خدمة BlueZ", "available", "خدمة bluetoothd تعمل ويمكن الوصول إليها عبر D-Bus", ["runtime"], True)
        else:
            row("bluez", "خدمة BlueZ", "unavailable", {
                "dbus_unavailable": "تعذر الاتصال بناقل النظام D-Bus",
                "permission_denied": "تم رفض الإذن بالوصول إلى BlueZ عبر D-Bus",
            }.get(err, "خدمة bluetoothd غير موجودة على ناقل النظام"), ["runtime"])

        a = s["bluetooth"]["adapter"]
        if svc != "available":
            row("adapter", "محول Bluetooth", "unknown", "لا يمكن الفحص دون خدمة BlueZ")
        elif not a.get("present"):
            row("adapter", "محول Bluetooth", "unavailable", "لم يتم العثور على محول Bluetooth", ["runtime"])
        elif not a.get("powered"):
            extra = " (محظور بواسطة rfkill)" if a.get("power_state") == "off-blocked" else ""
            row("adapter", "محول Bluetooth", "unavailable", f"المحول {a.get('address')} متوقف{extra}", ["runtime"])
        else:
            row("adapter", "محول Bluetooth", "available", f"المحول {a.get('address')} يعمل", ["runtime"], True)

        if svc != "available":
            row("discovery", "اكتشاف الجهاز", "unknown", "لا يمكن الفحص دون خدمة BlueZ")
        elif d.get("known"):
            flags = "مقترنة" if d.get("paired") else "غير مقترنة"
            flags += "، موثوقة" if d.get("trusted") else "، غير موثوقة"
            row("discovery", "اكتشاف الجهاز", "available", f"السماعة معروفة لدى BlueZ ({flags})", ["runtime"], True)
        else:
            row("discovery", "اكتشاف الجهاز", "unavailable", f"العنوان {self.address} غير معروف لدى BlueZ — يلزم الاقتران", ["runtime"])

        cs = s["connection"]["state"]
        row("connection", "الاتصال", "available" if connected else ("unknown" if cs == "connecting" else "unavailable"),
            {"connected": "السماعة متصلة (Device1.Connected)", "connecting": "جارٍ الاتصال",
             "failed": "فشلت آخر محاولة اتصال", "disconnected": "السماعة غير متصلة"}[cs], ["runtime"], connected)

        tr = bz["transport"] if connected else None
        if tr:
            row("a2dp", "بث الصوت A2DP", "available",
                f"قناة A2DP مهيأة (الحالة: {tr.get('state')})", ["capture", "runtime"], True)
        else:
            row("a2dp", "بث الصوت A2DP", "unavailable" if not connected else "unknown",
                "السماعة غير متصلة" if not connected else "لا توجد قناة A2DP مهيأة حاليًا", ["capture"])

        mc = bz["media_control"] if connected else None
        if mc and mc.get("connected"):
            row("avrcp", "AVRCP", "available", "قناة AVRCP مفتوحة حسب BlueZ (MediaControl1)", ["capture", "runtime"], True)
        elif connected:
            row("avrcp", "AVRCP", "unknown", "السماعة متصلة لكن BlueZ لا يُظهر قناة AVRCP مفتوحة", ["capture"])
        else:
            row("avrcp", "AVRCP", "unavailable", "السماعة غير متصلة", ["capture"])

        if s["buttons"].get("available"):
            row("headset_buttons", "أزرار السماعة (تشغيل/إيقاف)", "available",
                "تتم مراقبة أزرار السماعة" + (" — وصلت ضغطات فعلية" if "headset_buttons" in v else " — لم تصل ضغطات بعد"),
                ["capture", "runtime"], "headset_buttons" in v)
        else:
            reason = s["buttons"].get("reason")
            row("headset_buttons", "أزرار السماعة (تشغيل/إيقاف)", "unknown", {
                "evdev_missing": "مؤكدة في الالتقاط؛ مراقبتها تتطلب حزمة python-evdev الاختيارية",
                "permission_denied": "مؤكدة في الالتقاط؛ لا توجد صلاحية قراءة /dev/input (مجموعة input)",
                "input_device_not_found": "مؤكدة في الالتقاط؛ لم يُعثر على جهاز إدخال AVRCP الخاص بالسماعة",
                "not_connected": "مؤكدة في الالتقاط؛ السماعة غير متصلة",
                "disabled": "المراقبة معطلة في إعدادات الوكيل",
            }.get(reason, "غير معروف"), ["capture"])

        vol = s["volume"]
        if vol["available"]:
            row("volume_read", "قراءة مستوى الصوت", "available",
                "BlueZ يعرض مستوى الصوت المطلق (MediaTransport1.Volume)", ["capture", "runtime"], True)
            if "volume_write" in v:
                row("volume_write", "التحكم بمستوى الصوت", "available",
                    "تم التحقق أثناء التشغيل: BlueZ حدّث المستوى بعد الطلب", ["runtime"], True)
            else:
                row("volume_write", "التحكم بمستوى الصوت", "unknown",
                    "الواجهة موجودة في BlueZ لكن لم يُتحقق منها بعد — غيّر المستوى للتحقق", ["capture"])
        else:
            why = {"device_disconnected": "السماعة غير متصلة", "no_transport": "لا توجد قناة A2DP مهيأة",
                   "no_absolute_volume": "BlueZ لا يعرض خاصية Volume لهذه القناة"}.get(vol["reason"], "غير متاح")
            row("volume_read", "قراءة مستوى الصوت", "unavailable", why, ["capture"])
            row("volume_write", "التحكم بمستوى الصوت", "unavailable", why, [])
        row("mute", "كتم الصوت", "unavailable",
            "لا توجد واجهة كتم مؤكدة في BlueZ لهذه السماعة (AVRCP يدعم المستوى المطلق فقط)", [])

        bat = s["battery"]
        if bat["available"]:
            src = f" — المصدر: {bat['source']}" if bat.get("source") else ""
            row("battery", "البطارية", "available", f"BlueZ يعرض نسبة البطارية (Battery1){src}", ["capture", "runtime"], True)
        else:
            row("battery", "البطارية", "unavailable" if not connected else "unknown",
                "السماعة غير متصلة" if not connected else
                "مؤكدة في الالتقاط عبر HFP، لكن BlueZ لا يعرض Battery1 حاليًا", ["capture"])

        m = s["media"]
        if m["available"]:
            row("media_player", "مشغل الوسائط (MPRIS)", "available",
                f"المشغل المستهدف: {m['player']['identity']}", ["runtime"], True)
        else:
            row("media_player", "مشغل الوسائط (MPRIS)", "unavailable", {
                "session_bus_unavailable": "تعذر الوصول إلى ناقل جلسة المستخدم",
                "no_media_player": "لا يوجد مشغل وسائط يدعم MPRIS",
            }.get(m["reason"], "غير متاح"), ["runtime"])
        if "play_pause" in v:
            row("play_pause", "التشغيل والإيقاف المؤقت", "available",
                "تم التحقق أثناء التشغيل: تغيرت حالة المشغل بعد الأمر", ["runtime"], True)
        else:
            row("play_pause", "التشغيل والإيقاف المؤقت", "unknown" if m["available"] else "unavailable",
                "لم يُتحقق بعد — استخدم أزرار التشغيل للتحقق" if m["available"] else "لا يوجد مشغل وسائط", [])

        hfp = dev.has_uuid(uuids, 0x111E)
        row("hfp", "HFP", "unknown" if hfp else ("unavailable" if d.get("known") else "unknown"),
            "معلن في SDP؛ قناة HFP تُدار بواسطة PipeWire أو oFono ولا تظهر حالتها عبر BlueZ" if hfp
            else "غير معلن في قائمة خدمات الجهاز", ["capture", "sdp"] if hfp else [])

        hid = dev.has_uuid(uuids, 0x1124) or not d.get("known")
        row("hid", "HID", "unknown" if hid else "unavailable",
            "معلن في SDP، لكن لم يتم تأكيد تبادل HID reports" if hid else "غير معلن في قائمة خدمات الجهاز",
            ["sdp"] if hid else [])

        row("jieli_spp", "خدمة JieLi الخاصة (RFCOMM 10)", "unavailable",
            "محظورة عمدًا: لا يتم فتح هذه القناة أو الكتابة إليها. البروتوكول غير معروف", ["sdp"])
        return rows

    # ------------------------------------------------------------------ refresh / diff
    async def refresh(self, initial: bool = False) -> dict:
        async with self._refresh_lock:
            bz = await self._bluez_state()
            media = await self._media_state()
            if self.buttons:
                d = bz["device"]
                names = [n for n in (d.get("alias"), d.get("name")) if n]
                try:
                    await self.buttons.sync(bool(d.get("connected")), names, self.address)
                except Exception:
                    log.exception("button watcher sync failed")
            snap = self._compose(bz, media)
            self._last_bz = bz
            prev, self._snapshot = self._snapshot, snap
        events = [] if prev is None else self._diff(prev, snap)
        for etype, payload, message, severity, coalesce in events:
            await self._broadcast({"type": etype, **payload})
            if message:
                await self._emit_log(etype, message, severity, payload, coalesce)
        if initial:
            await self._initial_log(snap)
        if prev is None or events or self._material(prev) != self._material(snap):
            await self._broadcast({"type": "status", "data": snap})
            self._changed.set()
            self._changed = asyncio.Event()
        return snap

    @staticmethod
    def _material(s: dict) -> Any:
        return {k: v for k, v in s.items() if k not in ("updated_at", "agent")}

    async def _initial_log(self, s: dict) -> None:
        bt = s["bluetooth"]
        if bt["service"] != "available":
            await self._emit_log("bluez_changed", "تعذر الوصول إلى خدمة Bluetooth على النظام", "error")
            return
        if not bt["adapter"].get("present"):
            await self._emit_log("adapter_changed", "لم يتم العثور على محول Bluetooth", "error")
        elif not bt["adapter"].get("powered"):
            await self._emit_log("adapter_changed", "Bluetooth متوقف على هذا الجهاز", "warning")
        if not s["device"].get("known"):
            await self._emit_log("device_changed", "السماعة غير مقترنة بهذا الجهاز", "warning")
        elif s["connection"]["connected"]:
            await self._emit_log("connection_changed", "السماعة متصلة", "success")
            if s["battery"]["available"]:
                await self._emit_log("battery_changed", f"مستوى البطارية الحالي: {s['battery']['percentage']}%")
        else:
            await self._emit_log("connection_changed", "السماعة غير متصلة", "info")

    def _diff(self, a: dict, b: dict) -> list[tuple]:
        ev: list[tuple] = []
        ab, bb = a["bluetooth"], b["bluetooth"]
        if ab["service"] != bb["service"]:
            ok = bb["service"] == "available"
            ev.append(("bluez_changed", {"available": ok, "error": bb["error"]},
                       "خدمة Bluetooth متاحة" if ok else "تعذر الوصول إلى خدمة Bluetooth على النظام",
                       "success" if ok else "error", 0))
        aa, ba = ab["adapter"], bb["adapter"]
        if (aa.get("present"), aa.get("powered")) != (ba.get("present"), ba.get("powered")) and bb["service"] == "available":
            if not ba.get("present"):
                msg, sev = "لم يتم العثور على محول Bluetooth", "error"
            elif ba.get("powered"):
                msg, sev = "تم تشغيل Bluetooth", "success"
            else:
                msg, sev = "تم إيقاف Bluetooth على هذا الجهاز", "warning"
            ev.append(("adapter_changed", {"present": ba.get("present"), "powered": ba.get("powered")}, msg, sev, 0))
        ad, bd = a["device"], b["device"]
        if ad.get("known") != bd.get("known") and bb["service"] == "available":
            ev.append(("device_changed", {"known": bd.get("known")},
                       "تم العثور على السماعة لدى BlueZ" if bd.get("known") else "أُزيلت السماعة من قائمة أجهزة BlueZ",
                       "info" if bd.get("known") else "warning", 0))
        ac, bc = a["connection"], b["connection"]
        if ac["state"] != bc["state"]:
            msg, sev = {
                "connected": ("تم الاتصال بالسماعة", "success"),
                "connecting": ("جارٍ الاتصال بالسماعة", "info"),
                "disconnected": ("انقطع الاتصال بالسماعة", "warning"),
                "failed": ("فشل الاتصال بالسماعة", "error"),
            }[bc["state"]]
            if bc["state"] == "disconnected" and ac["state"] in ("connecting", "failed"):
                msg, sev = "السماعة غير متصلة", "info"
            ev.append(("connection_changed", {"connected": bc["connected"], "state": bc["state"]}, msg, sev, 0))
        abat, bbat = a["battery"], b["battery"]
        if abat["percentage"] != bbat["percentage"]:
            if bbat["percentage"] is not None:
                ev.append(("battery_changed", {"value": bbat["percentage"], "level": bbat["level"]},
                           f"تم تحديث مستوى البطارية: {bbat['percentage']}%",
                           "warning" if bbat["level"] in ("low", "critical") else "info", 0))
            elif bc["connected"]:
                ev.append(("battery_changed", {"value": None, "level": "unknown"},
                           "لم تعد قراءة البطارية متاحة", "warning", 0))
            else:
                ev.append(("battery_changed", {"value": None, "level": "unknown"}, None, "info", 0))
        av, bv = a["volume"], b["volume"]
        if av["raw"] != bv["raw"]:
            if bv["raw"] is not None:
                ev.append(("volume_changed", {"value": bv["percent"], "raw": bv["raw"]},
                           f"تغير مستوى الصوت إلى {bv['percent']}%", "info", 2.0))
            else:
                ev.append(("volume_changed", {"value": None, "raw": None}, None, "info", 0))
        am, bm = a["media"], b["media"]
        if am["status"] != bm["status"] or (am.get("player") or {}).get("bus_name") != (bm.get("player") or {}).get("bus_name"):
            if bm["status"] != am["status"]:
                msg = {"playing": "تم تشغيل الوسائط", "paused": "تم إيقاف الوسائط مؤقتًا",
                       "stopped": "توقفت الوسائط", "unknown": "حالة التشغيل غير معروفة"}[bm["status"]]
                ev.append(("playback_changed", {"status": bm["status"]}, msg, "info", 0))
            if bm.get("player") and (am.get("player") or {}).get("bus_name") != bm["player"]["bus_name"]:
                ev.append(("player_changed", {"player": bm["player"]["identity"]},
                           f"مشغل الوسائط المستهدف: {bm['player']['identity']}", "info", 0))
            elif not bm.get("player") and am.get("player"):
                ev.append(("player_changed", {"player": None}, "لم يعد هناك مشغل وسائط متاح", "warning", 0))
        if am["stream"] != bm["stream"]:
            msg = None
            if bm["stream"] == "active":
                msg = "بدأ بث الصوت إلى السماعة"
            elif am["stream"] == "active":
                msg = "توقف بث الصوت إلى السماعة"
            ev.append(("stream_changed", {"state": bm["stream"]}, msg, "info", 0))
        if [(r["id"], r["status"]) for r in a["capabilities"]] != [(r["id"], r["status"]) for r in b["capabilities"]]:
            ev.append(("capabilities_changed", {}, None, "info", 0))
        return ev

    async def snapshot(self, fresh: bool = False) -> dict:
        if fresh or self._snapshot is None:
            return await self.refresh()
        return self._snapshot

    async def _wait_for(self, predicate: Callable[[dict], bool], timeout: float = VERIFY_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            snap = await self.refresh()
            if predicate(snap):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                await asyncio.wait_for(self._changed.wait(), min(remaining, 0.5))
            except asyncio.TimeoutError:
                pass

    def _mark_verified(self, cap: str) -> bool:
        if cap in self._verified:
            return False
        self._verified[cap] = now_iso()
        return True

    # ------------------------------------------------------------------ actions
    async def perform(self, action: str, **params) -> dict:
        if action in FORBIDDEN_ACTIONS or action not in ALLOWED_ACTIONS:
            log.warning("rejected action %r", action)
            raise AgentError("action_not_allowed", action)
        handler = getattr(self, f"_act_{action}")
        if action in LOCK_FREE_ACTIONS:
            return await handler(**params)
        async with self._action_lock:
            return await handler(**params)

    def _require_bluez_device(self, s: dict, *, need_connected: bool = True) -> dict:
        bt = s["bluetooth"]
        if bt["service"] != "available":
            raise AgentError(bt["error"] or "bluez_unavailable")
        if not bt["adapter"].get("present"):
            raise AgentError("adapter_missing")
        if not bt["adapter"].get("powered"):
            raise AgentError("adapter_off")
        if not s["device"].get("known"):
            raise AgentError("device_not_found")
        if need_connected and not s["connection"]["connected"]:
            raise AgentError("device_disconnected")
        return s["device"]

    async def _media_command(self, cmd: str) -> dict:
        s = await self.refresh()
        m = s["media"]
        if not m["available"]:
            raise AgentError(m["reason"] or "no_media_player")
        player = m["player"]
        if not player.get("can_control", True) or not player.get("can_play" if cmd == "play" else "can_pause"):
            raise AgentError("unsupported", f"player {player['bus_name']} cannot {cmd}")
        target = "playing" if cmd == "play" else "paused"
        await self._emit_log("action", "طلب تشغيل من لوحة التحكم" if cmd == "play" else "طلب إيقاف مؤقت من لوحة التحكم")
        try:
            await (self.mpris.play if cmd == "play" else self.mpris.pause)(player["bus_name"])
        except DBusCallError as exc:
            log.warning("MPRIS %s failed: %s", cmd, exc)
            raise map_dbus_error(exc, action="media") from None
        self._last_active_player = player["bus_name"]
        ok = await self._wait_for(lambda x: x["media"]["status"] == target
                                  or (cmd == "pause" and x["media"]["status"] == "stopped"))
        if ok and self._mark_verified("play_pause"):
            await self._emit_log("verified", "تم التحقق أثناء التشغيل: أوامر التشغيل والإيقاف تعمل", "success")
            await self.refresh()
        if not ok:
            await self._emit_log("action", "أُرسل الأمر لكن لم يتأكد تغير حالة المشغل", "warning")
        s = await self.snapshot()
        return {"ok": True, "verified": ok, "status": s["media"]["status"], "player": player["identity"]}

    async def _act_play(self) -> dict:
        return await self._media_command("play")

    async def _act_pause(self) -> dict:
        return await self._media_command("pause")

    async def _set_volume_raw(self, raw: int) -> dict:
        s = await self.refresh()
        self._require_bluez_device(s)
        tr = (self._last_bz or {}).get("transport") if s["volume"]["available"] else None
        tr_path = tr["path"] if tr else None
        if not tr_path:
            raise AgentError("volume_unavailable", s["volume"]["reason"])
        raw = max(0, min(dev.VOLUME_MAX_RAW, int(raw)))
        try:
            await self.bluez.set_transport_volume(tr_path, raw)
        except DBusCallError as exc:
            log.warning("set volume failed: %s", exc)
            err = map_dbus_error(exc)
            raise AgentError("volume_unavailable" if err.code in ("unsupported", "dbus_error") else err.code, str(exc)) from None
        ok = await self._wait_for(lambda x: x["volume"]["raw"] == raw)
        if ok and self._mark_verified("volume_write"):
            await self._emit_log("verified", "تم التحقق أثناء التشغيل: التحكم بمستوى الصوت يعمل", "success")
            await self.refresh()
        s = await self.snapshot()
        return {"ok": True, "verified": ok, "requested_raw": raw, "raw": s["volume"]["raw"], "percent": s["volume"]["percent"]}

    async def _act_set_volume(self, percent: Any = None) -> dict:
        if isinstance(percent, bool) or not isinstance(percent, (int, float)) or not 0 <= percent <= 100:
            raise AgentError("bad_request", f"percent={percent!r}")
        return await self._set_volume_raw(dev.percent_to_raw(percent))

    async def _act_volume_up(self) -> dict:
        s = await self.refresh()
        if s["volume"]["raw"] is None:
            self._require_bluez_device(s)
            raise AgentError("volume_unavailable")
        return await self._set_volume_raw(s["volume"]["raw"] + dev.VOLUME_STEP_RAW)

    async def _act_volume_down(self) -> dict:
        s = await self.refresh()
        if s["volume"]["raw"] is None:
            self._require_bluez_device(s)
            raise AgentError("volume_unavailable")
        return await self._set_volume_raw(s["volume"]["raw"] - dev.VOLUME_STEP_RAW)

    async def _act_reconnect(self) -> dict:
        s = await self.refresh()
        d = self._require_bluez_device(s, need_connected=False)
        path = d["path"]
        was_connected = s["connection"]["connected"]
        self._connecting = True
        self._connect_error = None
        await self.refresh()
        try:
            if was_connected:
                await self._emit_log("action", "طلب إعادة الاتصال: قطع الاتصال الحالي أولًا")
                try:
                    await self.bluez.device_disconnect(path)
                except DBusCallError as exc:
                    log.warning("disconnect before reconnect failed: %s", exc)
                self._connecting = False
                await self._wait_for(lambda x: not x["connection"]["connected"], 8.0)
                self._connecting = True
                await self.refresh()
            else:
                await self._emit_log("action", "طلب الاتصال بالسماعة")
            try:
                await self.bluez.device_connect(path)
            except DBusCallError as exc:
                if exc.name == "org.bluez.Error.AlreadyConnected":
                    pass
                else:
                    err = map_dbus_error(exc, action="connect")
                    log.warning("connect failed: %s", exc)
                    self._connect_error = err.code
                    raise err from None
        finally:
            self._connecting = False
            await self.refresh()
        ok = await self._wait_for(lambda x: x["connection"]["connected"], 5.0)
        if not ok:
            self._connect_error = "connect_failed"
            await self.refresh()
            raise AgentError("connect_failed", "Connect() returned but device not connected")
        return {"ok": True, "connected": True}

    async def _skip(self, cmd: str) -> dict:
        s = await self.refresh()
        m = s["media"]
        if not m["available"]:
            raise AgentError(m["reason"] or "no_media_player")
        player = m["player"]
        if not player.get("can_control", True) or not player.get("can_go_next" if cmd == "next" else "can_go_previous"):
            raise AgentError("unsupported", f"player {player['bus_name']} cannot {cmd}")
        await self._emit_log("action", "طلب المقطع التالي من لوحة التحكم" if cmd == "next" else "طلب المقطع السابق من لوحة التحكم")
        try:
            await (self.mpris.next if cmd == "next" else self.mpris.previous)(player["bus_name"])
        except DBusCallError as exc:
            raise map_dbus_error(exc, action="media") from None
        return {"ok": True, "verified": None, "player": player["identity"]}

    async def _act_next(self) -> dict:
        return await self._skip("next")

    async def _act_previous(self) -> dict:
        return await self._skip("previous")

    # -- discovery (read-only / passive); see discovery.py for the safety rules
    async def _act_safe_scan(self) -> dict:
        return await self.discovery.safe_scan()

    async def _act_research_start(self) -> dict:
        return self.discovery.research_start()

    async def _act_research_stop(self) -> dict:
        return self.discovery.research_stop()

    async def _act_research_headset(self, trial_action: Any = None) -> dict:
        if not isinstance(trial_action, str) or len(trial_action) > 32:
            raise AgentError("bad_request", "action")
        return await self.discovery.research_headset(trial_action)

    async def _act_research_host(self, trial_action: Any = None) -> dict:
        if not isinstance(trial_action, str) or len(trial_action) > 32:
            raise AgentError("bad_request", "action")
        return await self.discovery.research_host(trial_action)

    async def _act_analyze_capture(self, data: bytes = b"") -> dict:
        if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
            raise AgentError("bad_request", "empty capture")
        return await self.discovery.analyze_upload(bytes(data))

    async def _act_clear_discovery_log(self) -> dict:
        self.discovery.clear_log()
        return {"ok": True}

    async def _act_rfcomm_probe(self, read_seconds: Any = rfcomm.READ_SECONDS_DEFAULT) -> dict:
        """Open RFCOMM 10 read-only, observe for a window, close. Never writes.

        Connection/exploration is allowed; sending any byte (RCSP command,
        authentication, vendor command) is not — see FORBIDDEN_ACTIONS.
        """
        if isinstance(read_seconds, bool) or not isinstance(read_seconds, (int, float)):
            raise AgentError("bad_request", f"read_seconds={read_seconds!r}")
        if not 0.5 <= float(read_seconds) <= rfcomm.READ_SECONDS_MAX:
            raise AgentError("bad_request", f"read_seconds must be 0.5..{rfcomm.READ_SECONDS_MAX:g}")
        if self.rfcomm.enabled:
            await self._emit_log("action", f"استكشاف RFCOMM {self.rfcomm.channel}: فتح اتصال للقراءة فقط (لا إرسال)")
        result = await self.rfcomm.probe(float(read_seconds))
        result["checked_at"] = now_iso()
        self._rfcomm_last = result
        if result.get("connected"):
            self.discovery.observed["jieli_opened"] = True
            await self._emit_log("verified" if result.get("ok") else "action",
                                 f"RFCOMM {result['channel']}: {result.get('note', '')}",
                                 "success" if result.get("ok") else "warning")
        elif result.get("state") not in ("disabled", "unsupported"):
            await self._emit_log("action", f"RFCOMM {result['channel']}: {result.get('note', '')}", "warning")
        return result

    async def _act_select_player(self, bus_name: Any = None) -> dict:
        if bus_name in (None, "", "auto"):
            self._selected_player = None
        else:
            if not isinstance(bus_name, str) or not bus_name.startswith("org.mpris.MediaPlayer2."):
                raise AgentError("bad_request", f"bus_name={bus_name!r}")
            s = await self.refresh()
            if bus_name not in {p["bus_name"] for p in s["media"]["players"]}:
                raise AgentError("player_not_found", bus_name)
            self._selected_player = bus_name
        s = await self.refresh()
        return {"ok": True, "selected": self._selected_player,
                "player": (s["media"].get("player") or {}).get("identity")}

    async def _act_clear_log(self) -> dict:
        self.log.clear()
        entry = self.log.add("log_cleared", "تم مسح السجل", "info")
        await self._broadcast({"type": "log_cleared", "entry": public(entry)})
        return {"ok": True}
