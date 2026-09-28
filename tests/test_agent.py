"""Agent tests against the TEST-ONLY mock BlueZ/MPRIS (no Bluetooth hardware involved).

These prove the agent's logic, API contract, event stream, error handling and
security policy. They do NOT prove anything about the real headset.
"""

import asyncio
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import pytest

from agent import buttons, device
from agent.controller import ALLOWED_ACTIONS, FORBIDDEN_ACTIONS, Controller
from agent.errors import AgentError

ROOT = Path(__file__).resolve().parent.parent
ARABIC = re.compile(r"[؀-ۿ]")


# ============================================================ helpers
def ws_collect(env, trigger, until, timeout=6.0, origin=None):
    """Open /ws, run trigger(), and collect messages until until(msgs) is true."""

    async def run():
        headers = {"Host": f"127.0.0.1:{env.port}"}
        if origin:
            headers["Origin"] = origin
        msgs = []
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(f"{env.base}/ws", headers=headers) as ws:
                # initial hello/status/log_history
                for _ in range(3):
                    msgs.append(json.loads((await ws.receive(timeout=5)).data))
                await asyncio.get_running_loop().run_in_executor(None, trigger)
                deadline = time.time() + timeout
                while not until(msgs):
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise AssertionError(f"timeout; got types {[m['type'] for m in msgs]}")
                    m = await ws.receive(timeout=remaining)
                    if m.type != aiohttp.WSMsgType.TEXT:
                        raise AssertionError(f"ws closed: {m}")
                    msgs.append(json.loads(m.data))
        return msgs

    return asyncio.run(run())


def has(msgs, type_, **fields):
    return any(m.get("type") == type_ and all(m.get(k) == v for k, v in fields.items()) for m in msgs)


def assert_error(resp, status, code):
    st, body, _ = resp
    assert st == status, (st, body)
    assert body["ok"] is False and body["error"]["code"] == code, body
    assert ARABIC.search(body["error"]["message"]), "error message must be Arabic"
    assert "Traceback" not in json.dumps(body)


# ============================================================ unit tests
def test_modalias_and_profile():
    parsed = device.parse_modalias("bluetooth:v05D6p000Ad0240")
    assert parsed == {"source": "bluetooth", "vendor_id": 0x05D6, "product_id": 0x000A, "version": 0x0240}
    assert device.modalias_matches_profile(parsed) is True
    assert device.modalias_matches_profile(device.parse_modalias("bluetooth:v05D6p000Ad0241")) is False
    assert device.parse_modalias("garbage") is None


def test_volume_and_battery_math():
    assert device.raw_to_percent(127) == 100 and device.raw_to_percent(0) == 0
    assert device.raw_to_percent(120) == 94  # the capture's 127 -> 120 step
    assert device.percent_to_raw(50) == 64 and device.percent_to_raw(150) == 127
    assert [device.battery_level(x) for x in (None, 100, 70, 30, 10)] == ["unknown", "full", "good", "low", "critical"]


def test_uuid_description_marks_jieli_blocked():
    desc = device.describe_uuids(["FE010000-1234-5678-ABCD-00805F9B34FB", device.sig_uuid(0x110E)])
    assert desc[0]["blocked"] is True and desc[1]["blocked"] is False


def test_button_mapping():
    assert buttons.describe_key(200)["key"] == "play" and buttons.describe_key(200)["verified_in_capture"]
    assert buttons.describe_key(201)["key"] == "pause"
    assert buttons.describe_key(163)["verified_in_capture"] is False
    assert buttons.matches_headset("oraimo Necklace Lite (AVRCP)", 5, ["oraimo Necklace Lite"], "28:52:E0:0F:92:0A")
    assert not buttons.matches_headset("oraimo Necklace Lite (AVRCP)", 3, ["oraimo Necklace Lite"], "x")
    assert not buttons.matches_headset("AT Translated Keyboard", 5, ["oraimo Necklace Lite"], "x")


def test_action_whitelist():
    ctl = Controller(enable_buttons=False)
    assert {"play", "pause", "set_volume", "reconnect"} <= ALLOWED_ACTIONS
    assert not (ALLOWED_ACTIONS & FORBIDDEN_ACTIONS)
    for bad in ("raw_hci", "raw_avctp", "raw_rfcomm", "firmware_update", "custom_spp_write", "anything"):
        with pytest.raises(AgentError) as e:
            asyncio.run(ctl.perform(bad))
        assert e.value.code == "action_not_allowed"


def test_agent_never_opens_raw_bluetooth_sockets():
    """Safety guard: only agent/rfcomm.py may touch a Bluetooth socket, and it may only read.

    Every other module stays free of raw HCI/L2CAP/RFCOMM/SPP code paths.
    """
    others = [p for p in (ROOT / "agent").glob("*.py") if p.name != "rfcomm.py"]
    src = "\n".join(p.read_text() for p in others)
    for forbidden in ("AF_BLUETOOTH", "BTPROTO", "RFCOMM(", "ConnectProfile", "ProfileManager1", "RegisterProfile",
                      "HCI_CHANNEL", "socket.socket"):
        assert forbidden not in src, forbidden
    # rfcomm.py is the single, read-only exception: it connects and reads, never sends or authenticates.
    rf = (ROOT / "agent" / "rfcomm.py").read_text()
    code = re.sub(r'""".*?"""', "", rf, flags=re.S)  # ignore docstrings that describe what it does NOT do
    code = re.sub(r"#.*", "", code)
    for forbidden in (".send(", ".sendall(", ".sendto(", ".sendmsg(", ".write(", "makefile(",
                      "getRandomAuthData", "getEncryptedAuthData", "setLinkKey", "startAuth",
                      "packSendBasePacket", "fedcba", "FEDCBA", "HCI_CHANNEL", "BTPROTO_HCI", "BTPROTO_L2CAP"):
        assert forbidden not in code, forbidden
    # the JieLi UUID only appears as a blocked constant in device.py
    for p in (ROOT / "agent").glob("*.py"):
        if p.name != "device.py":
            assert "fe010000" not in p.read_text().lower(), p.name


def test_frontend_static_rules():
    html = (ROOT / "frontend/index.html").read_text()
    js = (ROOT / "frontend/app.js").read_text()
    css = (ROOT / "frontend/styles.css").read_text()
    assert '<html lang="ar" dir="rtl"' in html
    emoji = re.compile("[\U0001F300-\U0001FAFF☀-➿\U0001F000-\U0001F2FF]")
    for name, text in (("html", html), ("js", js), ("css", css)):
        assert not emoji.search(text), f"emoji in {name}"
    assert "<script>" not in html and " style=" not in html, "no inline script/style (CSP)"
    assert not re.search(r"https?://(?!www\.w3\.org)", html + js + css), "no external resources"
    assert ".innerHTML" not in js, "DOM must be built with textContent"
    for label in ("التحكم المتقدم", "لم يتم اكتشاف بروتوكول آمن لهذه الوظيفة بعد", "قيد البحث", "اكتشاف إمكانيات السماعة",
                  "فحص آمن", "وضع البحث", "خدمة مخصصة من الشركة - البروتوكول غير معروف",
                  "معلن لكنه غير متاح حاليًا / يحتاج اختبار اتصال آمن"):
        assert label in html, label


def test_refuses_non_loopback_bind():
    r = subprocess.run([sys.executable, "-m", "agent", "--host", "0.0.0.0", "--port", "1"], cwd=ROOT,
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 2 and "refusing" in r.stderr


# ============================================================ integration: normal operation
def test_startup_status_adapter_device(env):
    s = env.status()
    assert s["bluetooth"]["service"] == "available"
    a = s["bluetooth"]["adapter"]
    assert a["present"] and a["powered"] and a["address"] == "AC:7B:A1:2B:6E:A6"
    d = s["device"]
    assert d["known"] and d["address"] == "28:52:E0:0F:92:0A" and d["modalias_matches_capture"] is True
    assert any(u["blocked"] for u in d["uuids"])
    assert s["connection"] == {"state": "connected", "connected": True, "type": "BR/EDR", "error": None}
    assert s["battery"]["percentage"] == 70 and s["battery"]["level"] == "good"
    assert s["volume"]["raw"] == 127 and s["volume"]["percent"] == 100
    assert s["media"]["available"] and s["media"]["player"]["identity"] == "Mock Player"
    caps = {r["id"]: r for r in s["capabilities"]}
    # Advertised-only things must never be reported as working.
    assert caps["hid"]["status"] == "unknown" and "لم يتم تأكيد تبادل HID reports" in caps["hid"]["detail"]
    assert caps["hfp"]["status"] == "unknown"
    assert caps["jieli_spp"]["status"] == "unavailable"
    assert caps["mute"]["status"] == "unavailable"
    # Writes are "unknown" until verified at runtime.
    assert caps["volume_write"]["status"] == "unknown" and caps["play_pause"]["status"] == "unknown"
    for path in ("/api/device", "/api/battery", "/api/volume", "/api/media", "/api/diagnostics", "/api/events"):
        env.get(path)


def test_volume_set_up_down_and_runtime_verification(env):
    st, body, _ = env.post("/api/volume", {"percent": 50})
    assert st == 200 and body["data"]["verified"] is True and body["data"]["raw"] == 64
    s = env.status()
    assert env.cap(s, "volume_write")["status"] == "available" and env.cap(s, "volume_write")["runtime_verified"]
    st, body, _ = env.post("/api/volume/down")
    assert body["data"]["raw"] == 56
    st, body, _ = env.post("/api/volume/up")
    assert body["data"]["raw"] == 64
    assert_error(env.post("/api/volume", {"percent": 101}), 400, "bad_request")
    assert_error(env.post("/api/volume", {"percent": "50"}), 400, "bad_request")
    assert_error(env.post("/api/volume", {}), 400, "bad_request")


def test_volume_not_acknowledged_is_not_marked_working(env):
    env.mock_options(volume_ack=False)
    st, body, _ = env.post("/api/volume", {"percent": 30})
    assert st == 200 and body["data"]["verified"] is False
    assert env.cap(env.status(), "volume_write")["status"] == "unknown"


def test_play_pause_via_mpris(env):
    st, body, _ = env.post("/api/media/play")
    assert st == 200 and body["data"]["verified"] and body["data"]["status"] == "playing"
    st, body, _ = env.post("/api/media/pause")
    assert body["data"]["status"] == "paused"
    s = env.status()
    assert s["media"]["status"] == "paused" and env.cap(s, "play_pause")["runtime_verified"]


def test_websocket_live_events(env):
    def logged(text):
        return lambda m: any(x["type"] == "log" and text in x["entry"]["message"] for x in m)

    msgs = ws_collect(env, lambda: env.mock_call("SetBattery", "int32:40"),
                      lambda m: has(m, "battery_changed", value=40) and logged("40%")(m))
    assert msgs[0]["type"] == "hello" and msgs[1]["type"] == "status" and msgs[2]["type"] == "log_history"
    assert any(m["type"] == "log" and m["entry"]["message"] == "تم تحديث مستوى البطارية: 40%" for m in msgs)
    msgs = ws_collect(env, lambda: env.mock_call("SetVolume", "uint16:120"),
                      lambda m: has(m, "volume_changed", value=94))
    msgs = ws_collect(env, lambda: env.post("/api/media/play"), lambda m: has(m, "playback_changed", status="playing"))
    msgs = ws_collect(env, lambda: env.mock_call("SetStream", "string:active"),
                      lambda m: has(m, "stream_changed", state="active"))
    msgs = ws_collect(env, lambda: env.mock_call("SetConnected", "boolean:false"),
                      lambda m: any(x["type"] == "status" and x["data"]["connection"]["state"] == "disconnected" for x in m))
    assert has(msgs, "connection_changed", connected=False, state="disconnected")
    assert logged("انقطع الاتصال بالسماعة")(msgs)


def test_websocket_rejects_foreign_origin(env):
    with pytest.raises(aiohttp.WSServerHandshakeError):
        ws_collect(env, lambda: None, lambda m: True, origin="http://evil.example")


# ============================================================ integration: failure modes
def test_disconnected_device(env):
    env.mock_call("SetConnected", "boolean:false")
    s = env.wait_status(lambda s: s["connection"]["state"] == "disconnected")
    assert s["battery"]["available"] is False and s["battery"]["level"] == "unknown"
    assert s["volume"]["available"] is False and s["volume"]["reason"] == "device_disconnected"
    assert_error(env.post("/api/volume", {"percent": 10}), 409, "device_disconnected")
    assert_error(env.post("/api/volume/up"), 409, "device_disconnected")
    # reconnect brings it back
    st, body, _ = env.post("/api/reconnect")
    assert st == 200 and body["data"]["connected"]
    assert env.status()["connection"]["state"] == "connected"


def test_reconnect_failure_sets_failed_state(env):
    env.mock_call("SetConnected", "boolean:false")
    env.mock_options(connect_fail="org.bluez.Error.Failed:br-connection-page-timeout")
    assert_error(env.post("/api/reconnect"), 504, "device_unavailable")
    s = env.status()
    assert s["connection"]["state"] == "failed" and env.cap(s, "connection")["status"] == "unavailable"


def test_bluetooth_disabled(env):
    env.mock_call("SetPowered", "boolean:false")
    s = env.wait_status(lambda s: not s["bluetooth"]["adapter"]["powered"])
    assert s["connection"]["connected"] is False
    assert env.cap(s, "adapter")["status"] == "unavailable"
    assert_error(env.post("/api/reconnect"), 409, "adapter_off")
    assert_error(env.post("/api/volume", {"percent": 10}), 409, "adapter_off")


def test_battery_interface_missing(env):
    env.mock_call("SetBattery", "int32:-1")
    s = env.wait_status(lambda s: not s["battery"]["available"])
    assert s["battery"]["percentage"] is None and env.cap(s, "battery")["status"] == "unknown"


def test_volume_interface_missing(make_env):
    env = make_env("--disconnected")
    env.mock_options(volume_supported=False)
    env.post("/api/reconnect")
    s = env.wait_status(lambda s: s["connection"]["connected"])
    assert s["volume"]["available"] is False and s["volume"]["reason"] == "no_absolute_volume"
    assert_error(env.post("/api/volume", {"percent": 10}), 409, "volume_unavailable")


def test_device_not_paired(make_env):
    env = make_env("--unknown-device")
    s = env.status()
    assert s["device"]["known"] is False and s["connection"]["state"] == "disconnected"
    assert_error(env.post("/api/reconnect"), 404, "device_not_found")


def test_bluez_unavailable_then_recovers(make_env):
    env = make_env("--no-bluez")
    s = env.status()
    assert s["bluetooth"]["service"] == "unavailable" and s["bluetooth"]["error"] == "bluez_unavailable"
    assert_error(env.post("/api/reconnect"), 503, "bluez_unavailable")
    assert_error(env.post("/api/volume", {"percent": 5}), 503, "bluez_unavailable")
    # MPRIS still works without BlueZ
    assert env.post("/api/media/play")[0] == 200
    # bluetoothd "starts": NameOwnerChanged must be picked up without restarting the agent
    env.stop_mock()
    env.start_mock()
    s = env.wait_status(lambda s: s["bluetooth"]["service"] == "available" and s["connection"]["connected"], timeout=8)
    assert s["battery"]["percentage"] == 70


def test_dbus_system_bus_failure(make_env):
    env = make_env(system_address="unix:path=/nonexistent/dbus-socket")
    s = env.status()
    assert s["bluetooth"]["service"] == "unavailable" and s["bluetooth"]["error"] == "dbus_unavailable"
    assert_error(env.post("/api/reconnect"), 503, "dbus_unavailable")


def test_permission_denied(env):
    env.mock_options(access_denied=True)
    env.get("/api/diagnostics?refresh=1")  # policy changes emit no D-Bus signal; re-scan like the UI button
    s = env.status()
    assert s["bluetooth"]["error"] == "permission_denied"
    assert_error(env.post("/api/reconnect"), 403, "permission_denied")


def test_no_media_player(make_env):
    env = make_env("--no-mpris")
    s = env.status()
    assert s["media"]["available"] is False and s["media"]["reason"] == "no_media_player"
    assert s["media"]["status"] == "unknown"
    assert_error(env.post("/api/media/play"), 409, "no_media_player")


# ============================================================ security
def test_security_checks(env):
    port = env.port
    assert_error(env.request("GET", "/api/status", headers={"Host": f"evil.example:{port}"}), 403, "host_denied")
    assert_error(env.post("/api/media/play", headers={"Origin": "http://evil.example"}), 403, "origin_denied")
    assert_error(env.request("GET", "/api/status", headers={"Origin": "http://evil.example"}), 403, "origin_denied")
    assert env.post("/api/media/play", headers={"Origin": f"http://localhost:{port}"})[0] == 200
    assert_error(env.request("POST", "/api/media/play", raw_body=b"a=b",
                             headers={"Content-Type": "application/x-www-form-urlencoded"}), 415, "unsupported_media_type")
    assert_error(env.request("POST", "/api/volume", raw_body=b"{not json", headers={"Content-Type": "application/json"}),
                 400, "bad_request")
    for path in ("/api/raw/hci", "/api/rfcomm", "/api/spp/write", "/api/firmware"):
        assert_error(env.post(path), 404, "not_found")
    assert_error(env.request("GET", "/api/media/play"), 403, "action_not_allowed")
    st, _, headers = env.request("OPTIONS", "/api/media/play", headers={"Origin": f"http://127.0.0.1:{port}"})
    assert st == 204 and not any(h.lower().startswith("access-control") for h in headers)
    _, _, headers = env.request("GET", "/api/status")
    assert "default-src 'self'" in headers["Content-Security-Policy"] and headers["X-Frame-Options"] == "DENY"
    # path traversal on assets
    st, _, _ = env.request("GET", "/assets/../agent/main.py")
    assert st == 404


def test_errors_are_logged_but_not_exposed(env):
    env.mock_call("SetConnected", "boolean:false")
    env.mock_options(connect_fail="org.bluez.Error.Failed:secret-internal-detail")
    st, body, _ = env.post("/api/reconnect")
    assert "secret-internal-detail" not in json.dumps(body)
    time.sleep(0.2)
    assert "secret-internal-detail" in env.agent_output()


def test_clear_log(env):
    assert len(env.get("/api/events")) >= 2
    st, _, _ = env.post("/api/events/clear")
    events = env.get("/api/events")
    assert st == 200 and len(events) == 1 and events[0]["type"] == "log_cleared"
