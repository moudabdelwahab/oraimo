"""Tests for the opt-in, read-only RFCOMM explorer (agent/rfcomm.py + rfcomm_probe).

No test here touches real Bluetooth. Every enabled probe runs against an
injected fake socket that only implements connect/read/close and fails the
test on any other call (send, sendall, write, ...). The real-agent test runs
with default flags, so the probe is disabled and never opens a socket.
"""

import asyncio
import errno
import re
import socket
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from agent import main as agent_main
from agent import rfcomm
from agent.api import create_app
from agent.controller import ALLOWED_ACTIONS, FORBIDDEN_ACTIONS, Controller
from agent.errors import AgentError
from tests.harness import free_port

ROOT = Path(__file__).resolve().parent.parent
ARABIC = re.compile(r"[؀-ۿ]")
ADDR = "28:52:E0:0F:92:0A"
ALLOWED_SOCKET_CALLS = {"settimeout", "connect", "getpeername", "recv", "close"}


# ============================================================ fake socket
class StrictFakeSocket:
    """Implements only connect/read/close. Anything else is recorded and fails the test."""

    def __init__(self, chunks=(), connect_exc=None, recv_forever=None):
        self.chunks = list(chunks)
        self.connect_exc = connect_exc
        self.recv_forever = recv_forever  # "timeout" -> recv always times out; bytes -> always returns them
        self.calls: list[str] = []
        self.forbidden: list[str] = []
        self.connected_to = None
        self.closed = False

    def settimeout(self, _t):
        self.calls.append("settimeout")

    def connect(self, addr):
        self.calls.append("connect")
        if self.connect_exc:
            raise self.connect_exc
        self.connected_to = addr

    def getpeername(self):
        self.calls.append("getpeername")
        return self.connected_to

    def recv(self, n):
        self.calls.append("recv")
        if self.recv_forever == "timeout":
            raise socket.timeout("timed out")
        if isinstance(self.recv_forever, bytes):
            return self.recv_forever[:n]
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        self.calls.append("close")
        self.closed = True

    def __getattr__(self, name):  # only reached for attributes not defined above
        self.forbidden.append(name)
        raise AssertionError(f"RFCOMM explorer touched forbidden socket attribute {name!r}")


def _never_open():
    raise AssertionError("socket must not be opened")


@pytest.fixture
def bt_platform(monkeypatch):
    """Pretend AF_BLUETOOTH exists so the enabled path runs (the socket itself is always fake)."""
    monkeypatch.setattr(rfcomm, "platform_supported", lambda: True)


def probe(sock, read_seconds=1.0, enabled=True):
    ex = rfcomm.RfcommExplorer(ADDR, enabled=enabled, open_socket=lambda: sock)
    return asyncio.run(ex.probe(read_seconds))


def assert_read_only(sock: StrictFakeSocket):
    assert sock.forbidden == [], sock.forbidden
    assert set(sock.calls) <= ALLOWED_SOCKET_CALLS, sock.calls
    assert sock.calls[-1] == "close" and sock.closed


# ============================================================ disabled (default)
def test_disabled_explorer_opens_no_socket():
    ex = rfcomm.RfcommExplorer(ADDR, enabled=False, open_socket=_never_open)
    r = asyncio.run(ex.probe())
    assert r["ok"] is False and r["state"] == "disabled"
    assert "connected" not in r and ARABIC.search(r["note"])


def test_controller_default_is_disabled_and_opens_no_socket():
    ctl = Controller(enable_buttons=False)
    assert ctl.rfcomm.enabled is False
    ctl.rfcomm._open_socket = _never_open
    r = asyncio.run(ctl.perform("rfcomm_probe"))
    assert r["state"] == "disabled" and r["ok"] is False
    assert ctl.discovery.observed["jieli_opened"] is False


def test_cli_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("NECKLACE_ALLOW_RFCOMM_PROBE", raising=False)
    assert agent_main.parse_args([]).allow_rfcomm_probe is False
    assert agent_main.parse_args(["--allow-rfcomm-probe"]).allow_rfcomm_probe is True
    monkeypatch.setenv("NECKLACE_ALLOW_RFCOMM_PROBE", "1")
    assert agent_main.parse_args([]).allow_rfcomm_probe is True


def test_unsupported_platform_opens_no_socket(monkeypatch):
    monkeypatch.setattr(rfcomm, "platform_supported", lambda: False)
    ex = rfcomm.RfcommExplorer(ADDR, enabled=True, open_socket=_never_open)
    r = asyncio.run(ex.probe())
    assert r["ok"] is False and r["state"] == "unsupported"


# ============================================================ enabled: connect + read + close only
def test_enabled_connect_read_close_only(bt_platform):
    sock = StrictFakeSocket(chunks=[b"\x01\x02", b"\x03"])  # then b"" = peer closed
    r = probe(sock)
    assert_read_only(sock)
    assert sock.connected_to == (ADDR, 10)
    assert sock.calls.index("connect") < sock.calls.index("recv")
    assert r["ok"] is True and r["state"] == "connected" and r["connected"] is True
    assert r["bytes_read"] == 3 and r["data_hex"] == "01 02 03"
    assert r["peer_closed"] is True and r["peer"] == ADDR and r["channel"] == 10
    assert "BR/EDR" in r["transport"]


def test_enabled_peer_closes_without_data(bt_platform):
    sock = StrictFakeSocket(chunks=[])
    r = probe(sock)
    assert_read_only(sock)
    assert r["ok"] is True and r["bytes_read"] == 0 and r["peer_closed"] is True
    assert "RcspAuth" in r["note"]


def test_enabled_silent_peer_reads_until_window_ends(bt_platform):
    sock = StrictFakeSocket(recv_forever="timeout")
    r = probe(sock, read_seconds=0.5)
    assert_read_only(sock)
    assert r["ok"] is True and r["state"] == "connected"
    assert r["bytes_read"] == 0 and r["peer_closed"] is False


def test_enabled_read_is_capped(bt_platform):
    sock = StrictFakeSocket(recv_forever=b"\xaa" * 1024)
    r = probe(sock, read_seconds=5.0)
    assert_read_only(sock)
    assert r["bytes_read"] == rfcomm.MAX_READ_BYTES


# ============================================================ failure and timeout states
def test_connect_refused_reports_error(bt_platform):
    sock = StrictFakeSocket(connect_exc=ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
    r = probe(sock)
    assert_read_only(sock)
    assert "recv" not in sock.calls
    assert r["ok"] is False and r["state"] == "error" and r["connected"] is False
    assert r["errno"] == errno.ECONNREFUSED and ARABIC.search(r["note"])


@pytest.mark.parametrize("exc", [socket.timeout("timed out"), OSError(errno.ETIMEDOUT, "Connection timed out")])
def test_connect_timeout_reports_timeout(bt_platform, exc):
    sock = StrictFakeSocket(connect_exc=exc)
    r = probe(sock)
    assert_read_only(sock)
    assert r["ok"] is False and r["state"] == "timeout" and r["connected"] is False
    assert ARABIC.search(r["note"])


def test_host_unreachable_reports_error(bt_platform):
    sock = StrictFakeSocket(connect_exc=OSError(errno.EHOSTDOWN, "Host is down"))
    r = probe(sock)
    assert_read_only(sock)
    assert r["state"] == "error" and r["errno"] == errno.EHOSTDOWN


# ============================================================ no write / auth / RCSP anywhere
def test_explorer_exposes_no_write_or_auth_api():
    names = [n.lower() for n in dir(rfcomm.RfcommExplorer) if not n.startswith("__")]
    for bad in ("send", "write", "auth", "rcsp", "command"):
        assert not any(bad in n for n in names), (bad, names)


def test_command_and_auth_actions_stay_forbidden():
    assert "rfcomm_probe" in ALLOWED_ACTIONS and "rfcomm_probe" not in FORBIDDEN_ACTIONS
    ctl = Controller(enable_buttons=False, allow_rfcomm_probe=True)
    ctl.rfcomm._open_socket = _never_open
    for bad in ("rcsp_command", "rcsp_auth", "rfcomm_write", "spp_write", "custom_spp_write", "jieli_command",
                "vendor_command", "raw_rfcomm", "ota_update", "firmware_update", "factory_reset"):
        assert bad in FORBIDDEN_ACTIONS, bad
        with pytest.raises(AgentError) as e:
            asyncio.run(ctl.perform(bad))
        assert e.value.code == "action_not_allowed"


@pytest.mark.parametrize("value", [True, "5", None, 0.1, 21, -1])
def test_controller_rejects_bad_read_window(value):
    ctl = Controller(enable_buttons=False, allow_rfcomm_probe=True)
    ctl.rfcomm._open_socket = _never_open
    with pytest.raises(AgentError) as e:
        asyncio.run(ctl.perform("rfcomm_probe", read_seconds=value))
    assert e.value.code == "bad_request"


def test_controller_enabled_records_result_and_log(bt_platform):
    ctl = Controller(enable_buttons=False, allow_rfcomm_probe=True)
    sock = StrictFakeSocket(chunks=[b"\x10"])
    ctl.rfcomm._open_socket = lambda: sock
    r = asyncio.run(ctl.perform("rfcomm_probe", read_seconds=1))
    assert_read_only(sock)
    assert r["ok"] is True and r["bytes_read"] == 1 and "checked_at" in r
    assert ctl._rfcomm_last is r
    assert ctl.discovery.observed["jieli_opened"] is True
    assert any("RFCOMM" in e["message"] for e in ctl.log.entries())


# ============================================================ HTTP API (in-process, fake socket)
def _api_call(ctl, body, content_type="application/json"):
    """POST /api/explore/rfcomm on an in-process app (controller startup skipped: no D-Bus)."""

    async def run():
        port = free_port()
        app = create_app(ctl, port=port, frontend_dir=ROOT / "frontend")
        app.on_startup.clear()
        app.on_cleanup.clear()
        async with TestClient(TestServer(app, host="127.0.0.1", port=port)) as client:
            data = body if content_type != "application/json" else None
            kw = {"json": body} if content_type == "application/json" else {"data": data,
                                                                            "headers": {"Content-Type": content_type}}
            resp = await client.post("/api/explore/rfcomm", **kw)
            return resp.status, await resp.json()

    return asyncio.run(run())


def _enabled_ctl(sock):
    ctl = Controller(enable_buttons=False, allow_rfcomm_probe=True)
    ctl.rfcomm._open_socket = lambda: sock
    return ctl


def test_api_success(bt_platform):
    sock = StrictFakeSocket(chunks=[b"\xfe"])
    st, body = _api_call(_enabled_ctl(sock), {"read_seconds": 1})
    assert_read_only(sock)
    assert st == 200 and body["ok"] is True
    d = body["data"]
    assert d["ok"] is True and d["state"] == "connected" and d["bytes_read"] == 1 and d["data_hex"] == "fe"


def test_api_failure(bt_platform):
    sock = StrictFakeSocket(connect_exc=ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
    st, body = _api_call(_enabled_ctl(sock), {"read_seconds": 1})
    assert_read_only(sock)
    assert st == 200 and body["data"]["ok"] is False and body["data"]["state"] == "error"
    assert ARABIC.search(body["data"]["note"])


def test_api_timeout(bt_platform):
    sock = StrictFakeSocket(connect_exc=socket.timeout("timed out"))
    st, body = _api_call(_enabled_ctl(sock), {"read_seconds": 1})
    assert_read_only(sock)
    assert st == 200 and body["data"]["ok"] is False and body["data"]["state"] == "timeout"


def test_api_disabled_by_default():
    ctl = Controller(enable_buttons=False)
    ctl.rfcomm._open_socket = _never_open
    st, body = _api_call(ctl, {})
    assert st == 200 and body["data"]["state"] == "disabled" and body["data"]["ok"] is False


def test_api_bad_request_and_content_type():
    ctl = Controller(enable_buttons=False, allow_rfcomm_probe=True)
    ctl.rfcomm._open_socket = _never_open
    st, body = _api_call(ctl, {"read_seconds": 999})
    assert st == 400 and body["ok"] is False and body["error"]["code"] == "bad_request"
    assert ARABIC.search(body["error"]["message"])
    st, body = _api_call(ctl, b"read_seconds=1", content_type="text/plain")
    assert st == 415 and body["error"]["code"] == "unsupported_media_type"


# ============================================================ real agent process (default flags)
def test_real_agent_probe_disabled_by_default(env):
    st, body, _ = env.post("/api/explore/rfcomm", {"read_seconds": 1})
    assert st == 200 and body["ok"] is True
    assert body["data"]["state"] == "disabled" and body["data"]["ok"] is False
    # existing behaviour untouched: status endpoint and discovery view still work
    assert env.status()["connection"]["connected"] is True
    d = env.get("/api/discovery")
    assert d["jieli"]["probe_enabled"] is False and d["jieli"]["probe"]["state"] == "disabled"
