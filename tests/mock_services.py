"""TEST-ONLY mock of BlueZ and an MPRIS player on private D-Bus buses.

This is NOT used by the agent. It mimics the subset of the BlueZ D-Bus API the
agent reads, so the agent's logic, API, WebSocket events and UI can be tested
without Bluetooth hardware. Passing these tests does not prove anything about
the real headset.

Run: python -m tests.mock_services --system <addr> --session <addr> [--no-bluez] [--no-mpris]
Control: method calls on org.necklace.Test1 at /org/necklace/test (see _test_call).
"""

from __future__ import annotations

import argparse
import asyncio
import json

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus

PROPS = "org.freedesktop.DBus.Properties"
OBJMGR = "org.freedesktop.DBus.ObjectManager"
ADDR = "28:52:E0:0F:92:0A"
ADAPTER = "/org/bluez/hci0"
DEVICE = f"{ADAPTER}/dev_{ADDR.replace(':', '_')}"
TRANSPORT = f"{DEVICE}/sep1/fd0"
SIG = "-0000-1000-8000-00805f9b34fb"
UUIDS = [f"0000{x}{SIG}" for x in ("110b", "110c", "110e", "110f", "111e", "1124", "1101", "1200", "1203")]
UUIDS.append("fe010000-1234-5678-abcd-00805f9b34fb")


class MockObjects:
    """Generic object store: {path: {iface: {prop: (signature, value)}}}."""

    def __init__(self, bus: MessageBus):
        self.bus = bus
        self.objects: dict[str, dict[str, dict[str, tuple[str, object]]]] = {}

    def variants(self, props):
        return {k: Variant(s, v) for k, (s, v) in props.items()}

    async def add(self, path, iface, props, announce=True):
        self.objects.setdefault(path, {})[iface] = dict(props)
        if announce:
            await self.bus.send(Message.new_signal("/", OBJMGR, "InterfacesAdded", "oa{sa{sv}}",
                                                   [path, {iface: self.variants(props)}]))

    async def remove(self, path, iface):
        if path in self.objects and iface in self.objects[path]:
            del self.objects[path][iface]
            if not self.objects[path]:
                del self.objects[path]
            await self.bus.send(Message.new_signal("/", OBJMGR, "InterfacesRemoved", "oas", [path, [iface]]))

    async def set(self, path, iface, name, value, signal=True):
        sig, _ = self.objects[path][iface][name]
        self.objects[path][iface][name] = (sig, value)
        if signal:
            await self.bus.send(Message.new_signal(path, PROPS, "PropertiesChanged", "sa{sv}as",
                                                   [iface, {name: Variant(sig, value)}, []]))

    def get(self, path, iface, name):
        return self.objects[path][iface][name][1]

    def managed(self):
        return {p: {i: self.variants(pr) for i, pr in ifs.items()} for p, ifs in self.objects.items()}


def reply(msg, sig="", body=()):
    return Message.new_method_return(msg, sig, list(body))


def error(msg, name, text=""):
    return Message.new_error(msg, name, text)


class MockBluez:
    def __init__(self, bus: MessageBus):
        self.bus = bus
        self.store = MockObjects(bus)
        self.opts = {"connect_fail": None, "volume_ack": True, "volume_supported": True,
                     "access_denied": False, "battery_on_connect": 70, "connect_delay": 0.2}

    async def setup(self, connected=True, known=True, powered=True):
        s = self.store
        await s.add(ADAPTER, "org.bluez.Adapter1", {
            "Address": ("s", "AC:7B:A1:2B:6E:A6"), "Name": ("s", "mock-host"), "Alias": ("s", "mock-host"),
            "Powered": ("b", powered), "PowerState": ("s", "on" if powered else "off"),
            "Discovering": ("b", False)}, announce=False)
        if known:
            await s.add(DEVICE, "org.bluez.Device1", {
                "Address": ("s", ADDR), "Name": ("s", "oraimo Necklace Lite"), "Alias": ("s", "oraimo Necklace Lite"),
                "Paired": ("b", True), "Bonded": ("b", True), "Trusted": ("b", True), "Blocked": ("b", False),
                "Connected": ("b", False), "ServicesResolved": ("b", False),
                "Modalias": ("s", "bluetooth:v05D6p000Ad0240"), "UUIDs": ("as", UUIDS),
                "Adapter": ("o", ADAPTER), "Icon": ("s", "audio-headset")}, announce=False)
            if connected and powered:
                await self._bring_up(announce=False)

    async def _bring_up(self, announce=True):
        s = self.store
        await s.set(DEVICE, "org.bluez.Device1", "Connected", True, announce)
        await s.set(DEVICE, "org.bluez.Device1", "ServicesResolved", True, announce)
        await s.add(DEVICE, "org.bluez.MediaControl1", {"Connected": ("b", True), "Device": ("o", DEVICE)}, announce)
        if self.opts["battery_on_connect"] is not None:
            await s.add(DEVICE, "org.bluez.Battery1", {"Percentage": ("y", self.opts["battery_on_connect"]),
                                                      "Source": ("s", "HFP")}, announce)
        tprops = {"Device": ("o", DEVICE), "UUID": ("s", f"0000110b{SIG}"), "Codec": ("y", 0),
                  "State": ("s", "idle")}
        if self.opts["volume_supported"]:
            tprops["Volume"] = ("q", 127)
        await s.add(TRANSPORT, "org.bluez.MediaTransport1", tprops, announce)

    async def _bring_down(self):
        s = self.store
        await s.remove(TRANSPORT, "org.bluez.MediaTransport1")
        await s.remove(DEVICE, "org.bluez.Battery1")
        await s.remove(DEVICE, "org.bluez.MediaControl1")
        if DEVICE in s.objects:
            await s.set(DEVICE, "org.bluez.Device1", "ServicesResolved", False)
            await s.set(DEVICE, "org.bluez.Device1", "Connected", False)

    async def handle(self, msg: Message):
        if msg.message_type != MessageType.METHOD_CALL:
            return None
        iface, member, path = msg.interface, msg.member, msg.path
        if path == "/org/necklace/test" and iface == "org.necklace.Test1":
            return await self._test_call(msg)
        if self.opts["access_denied"]:
            return error(msg, "org.freedesktop.DBus.Error.AccessDenied", "Rejected send message (mock policy)")
        s = self.store
        if iface == OBJMGR and member == "GetManagedObjects" and path == "/":
            return reply(msg, "a{oa{sa{sv}}}", [s.managed()])
        if iface == PROPS:
            if path not in s.objects:
                return error(msg, "org.freedesktop.DBus.Error.UnknownObject", path)
            if member == "GetAll":
                return reply(msg, "a{sv}", [s.variants(s.objects[path].get(msg.body[0], {}))])
            if member == "Get":
                props = s.objects[path].get(msg.body[0], {})
                if msg.body[1] not in props:
                    return error(msg, "org.freedesktop.DBus.Error.InvalidArgs", "No such property")
                sig, val = props[msg.body[1]]
                return reply(msg, "v", [Variant(sig, val)])
            if member == "Set":
                iface_name, prop, value = msg.body
                if iface_name == "org.bluez.MediaTransport1" and prop == "Volume" and path == TRANSPORT:
                    if "Volume" not in s.objects.get(path, {}).get(iface_name, {}):
                        return error(msg, "org.freedesktop.DBus.Error.InvalidArgs", "No such property 'Volume'")
                    vol = int(value.value)
                    if vol > 127:
                        return error(msg, "org.bluez.Error.InvalidArguments", "Invalid arguments in method call")
                    if self.opts["volume_ack"]:
                        async def ack():
                            await asyncio.sleep(0.1)
                            if TRANSPORT in s.objects:
                                await s.set(TRANSPORT, "org.bluez.MediaTransport1", "Volume", vol)
                        asyncio.get_running_loop().create_task(ack())
                    return reply(msg)
                return error(msg, "org.freedesktop.DBus.Error.PropertyReadOnly", prop)
        if iface == "org.bluez.Device1" and path == DEVICE and DEVICE in s.objects:
            if member == "Connect":
                if not s.get(ADAPTER, "org.bluez.Adapter1", "Powered"):
                    return error(msg, "org.bluez.Error.NotReady", "Resource Not Ready")
                if s.get(DEVICE, "org.bluez.Device1", "Connected"):
                    return error(msg, "org.bluez.Error.AlreadyConnected", "Already Connected")
                await asyncio.sleep(self.opts["connect_delay"])
                if self.opts["connect_fail"]:
                    name, _, text = self.opts["connect_fail"].partition(":")
                    return error(msg, name, text)
                await self._bring_up()
                return reply(msg)
            if member == "Disconnect":
                await self._bring_down()
                return reply(msg)
        return error(msg, "org.freedesktop.DBus.Error.UnknownMethod", f"{iface}.{member}")

    async def _test_call(self, msg):
        s = self.store
        m, body = msg.member, msg.body
        if m == "SetOptions":
            self.opts.update(json.loads(body[0]))
        elif m == "SetPowered":
            on = bool(body[0])
            if not on:
                await self._bring_down()
            await s.set(ADAPTER, "org.bluez.Adapter1", "Powered", on)
            await s.set(ADAPTER, "org.bluez.Adapter1", "PowerState", "on" if on else "off")
        elif m == "SetConnected":
            await (self._bring_up() if body[0] else self._bring_down())
        elif m == "SetBattery":
            if body[0] < 0:
                await s.remove(DEVICE, "org.bluez.Battery1")
            elif "org.bluez.Battery1" in s.objects.get(DEVICE, {}):
                await s.set(DEVICE, "org.bluez.Battery1", "Percentage", int(body[0]))
            else:
                await s.add(DEVICE, "org.bluez.Battery1", {"Percentage": ("y", int(body[0])), "Source": ("s", "HFP")})
        elif m == "SetVolume":
            await s.set(TRANSPORT, "org.bluez.MediaTransport1", "Volume", int(body[0]))
        elif m == "SetStream":
            await s.set(TRANSPORT, "org.bluez.MediaTransport1", "State", body[0])
        elif m == "RemoveDevice":
            await self._bring_down()
            await s.remove(DEVICE, "org.bluez.Device1")
        else:
            return error(msg, "org.freedesktop.DBus.Error.UnknownMethod", m)
        return reply(msg)


class MockPlayer:
    PATH = "/org/mpris/MediaPlayer2"

    def __init__(self, bus: MessageBus):
        self.bus = bus
        self.store = MockObjects(bus)

    async def setup(self):
        await self.store.add(self.PATH, "org.mpris.MediaPlayer2", {"Identity": ("s", "Mock Player")}, announce=False)
        await self.store.add(self.PATH, "org.mpris.MediaPlayer2.Player", {
            "PlaybackStatus": ("s", "Paused"), "CanPlay": ("b", True), "CanPause": ("b", True),
            "CanControl": ("b", True), "CanGoNext": ("b", True), "CanGoPrevious": ("b", True),
            "Metadata": ("a{sv}", {"xesam:title": Variant("s", "مقطع تجريبي 1"),
                                   "xesam:artist": Variant("as", ["فنان تجريبي"])})}, announce=False)
        self.track = 1

    async def handle(self, msg: Message):
        if msg.message_type != MessageType.METHOD_CALL or msg.path != self.PATH:
            return None
        s = self.store
        if msg.interface == PROPS and msg.member == "GetAll":
            return reply(msg, "a{sv}", [s.variants(s.objects[self.PATH].get(msg.body[0], {}))])
        if msg.interface == "org.mpris.MediaPlayer2.Player" and msg.member in ("Next", "Previous"):
            self.track += 1 if msg.member == "Next" else -1
            await s.set(self.PATH, "org.mpris.MediaPlayer2.Player", "Metadata",
                        {"xesam:title": Variant("s", f"مقطع تجريبي {self.track}"),
                         "xesam:artist": Variant("as", ["فنان تجريبي"])})
            return reply(msg)
        if msg.interface == "org.mpris.MediaPlayer2.Player" and msg.member in ("Play", "Pause", "PlayPause"):
            cur = s.get(self.PATH, "org.mpris.MediaPlayer2.Player", "PlaybackStatus")
            new = {"Play": "Playing", "Pause": "Paused"}.get(msg.member) or ("Paused" if cur == "Playing" else "Playing")
            await s.set(self.PATH, "org.mpris.MediaPlayer2.Player", "PlaybackStatus", new)
            return reply(msg)
        return error(msg, "org.freedesktop.DBus.Error.UnknownMethod", f"{msg.interface}.{msg.member}")


async def serve(system_addr, session_addr, bluez=True, mpris=True, connected=True, known=True, powered=True):
    if bluez:
        sbus = await MessageBus(bus_address=system_addr).connect()
        mb = MockBluez(sbus)
        await mb.setup(connected=connected, known=known, powered=powered)

        def h1(msg):
            if msg.message_type == MessageType.METHOD_CALL and (msg.destination == "org.bluez"):
                asyncio.get_running_loop().create_task(_respond(sbus, mb.handle, msg))
                return True
            return None
        sbus.add_message_handler(h1)
        await sbus.request_name("org.bluez")
    if mpris:
        pbus = await MessageBus(bus_address=session_addr).connect()
        mp = MockPlayer(pbus)
        await mp.setup()

        def h2(msg):
            if msg.message_type == MessageType.METHOD_CALL and msg.destination == "org.mpris.MediaPlayer2.mockplayer":
                asyncio.get_running_loop().create_task(_respond(pbus, mp.handle, msg))
                return True
            return None
        pbus.add_message_handler(h2)
        await pbus.request_name("org.mpris.MediaPlayer2.mockplayer")
    print("READY", flush=True)
    await asyncio.Event().wait()


async def _respond(bus, handler, msg):
    try:
        r = await handler(msg)
    except Exception as exc:  # keep the mock alive
        r = error(msg, "org.freedesktop.DBus.Error.Failed", repr(exc))
    if r is None:
        r = error(msg, "org.freedesktop.DBus.Error.UnknownMethod", msg.member)
    await bus.send(r)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--system", required=True)
    p.add_argument("--session", required=True)
    p.add_argument("--no-bluez", action="store_true")
    p.add_argument("--no-mpris", action="store_true")
    p.add_argument("--disconnected", action="store_true")
    p.add_argument("--unknown-device", action="store_true")
    p.add_argument("--powered-off", action="store_true")
    a = p.parse_args()
    asyncio.run(serve(a.system, a.session, not a.no_bluez, not a.no_mpris,
                      not a.disconnected, not a.unknown_device, not a.powered_off))


if __name__ == "__main__":
    main()
