"""D-Bus access to BlueZ (system bus) and MPRIS media players (session bus).

Only stable, documented OS-level interfaces are used:

* org.bluez.Adapter1 / Device1 / MediaControl1 / MediaTransport1 / Battery1
  (read-only, except Device1.Connect/Disconnect and MediaTransport1.Volume)
* org.mpris.MediaPlayer2.Player (Play / Pause only)

There is deliberately no raw HCI, L2CAP, AVCTP or RFCOMM socket code in this
agent. See docs/protocol-status.md.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus

from .errors import DBusCallError

log = logging.getLogger("necklace.dbus")

BLUEZ = "org.bluez"
DBUS = "org.freedesktop.DBus"
PROPS = "org.freedesktop.DBus.Properties"
OBJMGR = "org.freedesktop.DBus.ObjectManager"
MPRIS_PREFIX = "org.mpris.MediaPlayer2."
MPRIS_PATH = "/org/mpris/MediaPlayer2"
MPRIS_ROOT = "org.mpris.MediaPlayer2"
MPRIS_PLAYER = "org.mpris.MediaPlayer2.Player"

DEFAULT_TIMEOUT = 5.0


def unwrap(value: Any) -> Any:
    """Recursively convert dbus-fast Variants into plain Python values."""
    if isinstance(value, Variant):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return list(value)
    return value


class BusConnection:
    """A lazily (re)connected D-Bus connection with signal subscriptions."""

    def __init__(self, bus_type: BusType, label: str, match_rules: list[str],
                 on_signal: Callable[[Message], None], on_state: Callable[[], None]):
        self.bus_type = bus_type
        self.label = label
        self.match_rules = match_rules
        self._on_signal = on_signal
        self._on_state = on_state
        self._bus: MessageBus | None = None
        self._lock = asyncio.Lock()
        self.last_error: str | None = None

    @property
    def connected(self) -> bool:
        return self._bus is not None and self._bus.connected

    async def ensure(self) -> bool:
        if self.connected:
            return True
        async with self._lock:
            if self.connected:
                return True
            try:
                bus = await asyncio.wait_for(MessageBus(bus_type=self.bus_type).connect(), DEFAULT_TIMEOUT)
            except Exception as exc:  # socket missing, auth failure, env unset...
                if self.last_error != repr(exc):
                    log.warning("%s bus unavailable: %r", self.label, exc)
                self.last_error = repr(exc)
                self._bus = None
                return False
            self._bus = bus
            self.last_error = None
            bus.add_message_handler(self._handle)
            for rule in self.match_rules:
                try:
                    await self._raw_call(DBUS, "/org/freedesktop/DBus", DBUS, "AddMatch", "s", [rule])
                except Exception as exc:
                    log.warning("%s AddMatch failed (%s): %r", self.label, rule, exc)
            asyncio.get_running_loop().create_task(self._watch_disconnect(bus))
            log.info("connected to %s bus", self.label)
            return True

    async def _watch_disconnect(self, bus: MessageBus) -> None:
        try:
            await bus.wait_for_disconnect()
        except Exception as exc:
            log.warning("%s bus disconnected: %r", self.label, exc)
        if self._bus is bus:
            self._bus = None
            self._on_state()

    def _handle(self, msg: Message):
        if msg.message_type == MessageType.SIGNAL:
            try:
                self._on_signal(msg)
            except Exception:
                log.exception("signal handler failed")
        return None

    async def _raw_call(self, dest, path, iface, member, signature="", body=(), timeout=DEFAULT_TIMEOUT):
        bus = self._bus
        if bus is None:
            raise DBusCallError("org.freedesktop.DBus.Error.Disconnected", f"{self.label} bus not connected")
        msg = Message(destination=dest, path=path, interface=iface, member=member,
                      signature=signature, body=list(body))
        try:
            reply = await asyncio.wait_for(bus.call(msg), timeout)
        except asyncio.TimeoutError:
            raise DBusCallError("org.freedesktop.DBus.Error.Timeout", f"{member} timed out") from None
        except (EOFError, ConnectionError, OSError) as exc:
            raise DBusCallError("org.freedesktop.DBus.Error.Disconnected", repr(exc)) from None
        if reply is None:
            raise DBusCallError("org.freedesktop.DBus.Error.NoReply", member)
        if reply.message_type == MessageType.ERROR:
            text = reply.body[0] if reply.body and isinstance(reply.body[0], str) else ""
            raise DBusCallError(reply.error_name or "unknown", text)
        return [unwrap(v) for v in reply.body]

    async def call(self, dest, path, iface, member, signature="", body=(), timeout=DEFAULT_TIMEOUT):
        if not await self.ensure():
            raise DBusCallError("org.freedesktop.DBus.Error.Disconnected", self.last_error or "no bus")
        return await self._raw_call(dest, path, iface, member, signature, body, timeout)

    async def name_has_owner(self, name: str) -> bool:
        (owned,) = await self.call(DBUS, "/org/freedesktop/DBus", DBUS, "NameHasOwner", "s", [name])
        return bool(owned)

    async def list_names(self) -> list[str]:
        (names,) = await self.call(DBUS, "/org/freedesktop/DBus", DBUS, "ListNames")
        return list(names)

    async def get_all(self, dest, path, iface) -> dict:
        (props,) = await self.call(dest, path, PROPS, "GetAll", "s", [iface])
        return props

    async def close(self) -> None:
        if self._bus is not None:
            self._bus.disconnect()
            self._bus = None


class BluezAPI:
    """Thin wrapper around the BlueZ objects this controller is allowed to touch."""

    MATCH_RULES = [
        f"type='signal',sender='{BLUEZ}',interface='{PROPS}',member='PropertiesChanged',path_namespace='/org/bluez'",
        f"type='signal',sender='{BLUEZ}',interface='{OBJMGR}'",
        f"type='signal',sender='{DBUS}',interface='{DBUS}',member='NameOwnerChanged',arg0='{BLUEZ}'",
    ]

    def __init__(self, on_signal: Callable[[Message], None], on_state: Callable[[], None]):
        self.conn = BusConnection(BusType.SYSTEM, "system", self.MATCH_RULES, on_signal, on_state)

    async def available(self) -> bool:
        return await self.conn.name_has_owner(BLUEZ)

    async def managed_objects(self) -> dict[str, dict[str, dict]]:
        (objs,) = await self.conn.call(BLUEZ, "/", OBJMGR, "GetManagedObjects")
        return objs

    async def device_connect(self, path: str, timeout: float = 45.0) -> None:
        await self.conn.call(BLUEZ, path, "org.bluez.Device1", "Connect", timeout=timeout)

    async def device_disconnect(self, path: str, timeout: float = 15.0) -> None:
        await self.conn.call(BLUEZ, path, "org.bluez.Device1", "Disconnect", timeout=timeout)

    async def set_transport_volume(self, transport_path: str, raw: int) -> None:
        raw = max(0, min(127, int(raw)))
        await self.conn.call(BLUEZ, transport_path, PROPS, "Set", "ssv",
                             ["org.bluez.MediaTransport1", "Volume", Variant("q", raw)])


class MprisAPI:
    """Play/Pause for desktop media players via MPRIS on the session bus."""

    MATCH_RULES = [
        f"type='signal',sender='{DBUS}',interface='{DBUS}',member='NameOwnerChanged',arg0namespace='org.mpris.MediaPlayer2'",
        f"type='signal',interface='{PROPS}',member='PropertiesChanged',path='{MPRIS_PATH}'",
    ]

    def __init__(self, on_signal: Callable[[Message], None], on_state: Callable[[], None]):
        self.conn = BusConnection(BusType.SESSION, "session", self.MATCH_RULES, on_signal, on_state)

    async def players(self) -> list[dict]:
        names = [n for n in await self.conn.list_names() if n.startswith(MPRIS_PREFIX)]
        out = []
        for name in sorted(names):
            try:
                player = await self.conn.get_all(name, MPRIS_PATH, MPRIS_PLAYER)
            except DBusCallError as exc:
                log.debug("skipping MPRIS player %s: %s", name, exc)
                continue
            try:
                root = await self.conn.get_all(name, MPRIS_PATH, MPRIS_ROOT)
            except DBusCallError:
                root = {}
            out.append({
                "bus_name": name,
                "identity": root.get("Identity") or name[len(MPRIS_PREFIX):],
                "status": str(player.get("PlaybackStatus", "")).lower() or "unknown",
                "can_play": bool(player.get("CanPlay", False)),
                "can_pause": bool(player.get("CanPause", False)),
                "can_control": bool(player.get("CanControl", True)),
                "can_go_next": bool(player.get("CanGoNext", False)),
                "can_go_previous": bool(player.get("CanGoPrevious", False)),
                "metadata": _metadata(player.get("Metadata")),
            })
        return out

    async def play(self, bus_name: str) -> None:
        await self.conn.call(bus_name, MPRIS_PATH, MPRIS_PLAYER, "Play")

    async def pause(self, bus_name: str) -> None:
        await self.conn.call(bus_name, MPRIS_PATH, MPRIS_PLAYER, "Pause")

    async def next(self, bus_name: str) -> None:
        await self.conn.call(bus_name, MPRIS_PATH, MPRIS_PLAYER, "Next")

    async def previous(self, bus_name: str) -> None:
        await self.conn.call(bus_name, MPRIS_PATH, MPRIS_PLAYER, "Previous")


def _metadata(md) -> dict | None:
    if not isinstance(md, dict):
        return None
    artist = md.get("xesam:artist")
    if isinstance(artist, list):
        artist = ", ".join(str(a) for a in artist)
    length = md.get("mpris:length")
    out = {"title": md.get("xesam:title"), "artist": artist, "album": md.get("xesam:album"),
           "length_s": round(length / 1e6) if isinstance(length, int) else None}
    return out if any(out.values()) else None
