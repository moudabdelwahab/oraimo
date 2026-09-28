"""Optional, read-only observer for headset button presses.

When the headset sends an AVRCP PASS THROUGH command (the capture verified
PLAY 0x44 and PAUSE 0x46), BlueZ turns it into a key event on a uinput device
it creates for the connection. This module finds that input device and reads
it passively: it never grabs the device (so the desktop still receives the
keys) and never writes to it.

It needs the optional ``evdev`` package and read access to /dev/input/event*
(usually membership in the ``input`` group). Without those, the feature is
reported as unavailable; nothing else is affected.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

log = logging.getLogger("necklace.buttons")

try:  # optional dependency
    import evdev  # type: ignore
    from evdev import ecodes  # type: ignore
except Exception:  # pragma: no cover - depends on host
    evdev = None
    ecodes = None

BUS_BLUETOOTH = 0x05

# Linux key codes BlueZ uses for AVRCP passthrough operations (see BlueZ
# profiles/audio/avctp.c key_map). Only PLAY and PAUSE were observed in the
# capture; other keys are listed so an unexpected press is still labelled.
KEY_LABELS: dict[int, tuple[str, str]] = {
    200: ("play", "تشغيل"),            # KEY_PLAYCD      <- AVRCP PLAY
    201: ("pause", "إيقاف مؤقت"),      # KEY_PAUSECD     <- AVRCP PAUSE
    164: ("play_pause", "تشغيل/إيقاف"),  # KEY_PLAYPAUSE
    166: ("stop", "إيقاف"),            # KEY_STOPCD
    163: ("next", "التالي"),           # KEY_NEXTSONG
    165: ("previous", "السابق"),       # KEY_PREVIOUSSONG
    115: ("volume_up", "رفع الصوت"),   # KEY_VOLUMEUP
    114: ("volume_down", "خفض الصوت"),  # KEY_VOLUMEDOWN
    113: ("mute", "كتم الصوت"),        # KEY_MUTE
    208: ("fast_forward", "تقديم سريع"),  # KEY_FASTFORWARD
    168: ("rewind", "ترجيع"),          # KEY_REWIND
}
VERIFIED_IN_CAPTURE = {"play", "pause"}


def matches_headset(name: str, bustype: int, device_names: list[str], address: str,
                    phys: str = "", uniq: str = "") -> bool:
    """Decide whether an input device is BlueZ's AVRCP device for the headset."""
    if bustype != BUS_BLUETOOTH:
        return False
    lname = (name or "").lower()
    addr = address.lower()
    if addr and (addr in (uniq or "").lower()):
        return True
    for dn in device_names:
        if dn and lname.startswith(dn.lower()):
            return True
    return False


def describe_key(code: int) -> dict:
    key, label = KEY_LABELS.get(code, (f"key_{code}", f"زر غير معروف ({code})"))
    return {"key": key, "label": label, "code": code, "verified_in_capture": key in VERIFIED_IN_CAPTURE}


class ButtonWatcher:
    def __init__(self, on_button: Callable[[dict], None], on_state: Callable[[], None]):
        self._on_button = on_button
        self._on_state = on_state
        self._task: asyncio.Task | None = None
        self._device = None
        self.node: str | None = None
        self.reason: str | None = None if evdev else "evdev_missing"
        self.events_seen = 0

    @property
    def available(self) -> bool:
        return self._task is not None and not self._task.done()

    def status(self) -> dict:
        return {"available": self.available, "reason": None if self.available else self.reason,
                "device_node": self.node, "events_seen": self.events_seen}

    async def sync(self, connected: bool, device_names: list[str], address: str) -> None:
        """Attach to the headset input device while connected, detach otherwise."""
        if evdev is None:
            self.reason = "evdev_missing"
            return
        if not connected:
            await self.stop()
            self.reason = "not_connected"
            return
        if self.available:
            return
        found = None
        permission_denied = False
        for path in evdev.list_devices():
            try:
                dev = evdev.InputDevice(path)
            except PermissionError:
                permission_denied = True
                continue
            except OSError:
                continue
            if matches_headset(dev.name, dev.info.bustype, device_names, address, dev.phys or "", dev.uniq or ""):
                found = dev
                break
            dev.close()
        if found is None:
            # /dev/input is often root:input 0660; without access we cannot see names.
            self.reason = "permission_denied" if permission_denied else "input_device_not_found"
            return
        self._device = found
        self.node = found.path
        self.reason = None
        self._task = asyncio.get_running_loop().create_task(self._read(found))
        log.info("watching headset buttons on %s (%s)", found.path, found.name)
        self._on_state()

    async def _read(self, dev) -> None:
        try:
            async for ev in dev.async_read_loop():
                if ev.type == ecodes.EV_KEY and ev.value in (0, 1):
                    info = describe_key(ev.code)
                    info["pressed"] = ev.value == 1
                    self.events_seen += 1
                    self._on_button(info)
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self.node = None
            self.reason = "input_device_not_found"
            try:
                dev.close()
            except Exception:
                pass
            self._on_state()

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except BaseException:
                pass
        self._task = None
        self.node = None
