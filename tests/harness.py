"""TEST-ONLY harness: private D-Bus daemons + mock BlueZ/MPRIS + the real agent process."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Bus:
    def __init__(self):
        self.proc = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1"],
                                     stdout=subprocess.PIPE, text=True)
        self.address = self.proc.stdout.readline().strip()
        if not self.address:
            raise RuntimeError("dbus-daemon did not start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(5)


class Env:
    """One test scenario: two buses, optional mock services, and the agent."""

    def __init__(self):
        self.system = Bus()
        self.session = Bus()
        self.mock: subprocess.Popen | None = None
        self.agent: subprocess.Popen | None = None
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.capture_path = ROOT / "tests" / f".capture-{self.port}.btsnoop"

    # -- processes
    def start_mock(self, *flags: str) -> None:
        self.mock = subprocess.Popen(
            [sys.executable, "-m", "tests.mock_services", "--system", self.system.address,
             "--session", self.session.address, *flags],
            cwd=ROOT, stdout=subprocess.PIPE, text=True)
        line = self.mock.stdout.readline().strip()
        if line != "READY":
            raise RuntimeError(f"mock did not start: {line!r}")

    def stop_mock(self) -> None:
        if self.mock:
            self.mock.send_signal(signal.SIGTERM)
            self.mock.wait(5)
            self.mock = None

    def start_agent(self, *args: str, system_address: str | None = None, extra_env: dict | None = None) -> None:
        env = dict(os.environ)
        # deterministic: the TEST-ONLY sdptool stand-in comes first on PATH
        env["PATH"] = f"{ROOT / 'tests' / 'fake_bin'}:{env.get('PATH', '')}"
        env.update(extra_env or {})
        if "--capture-file" not in args:
            args = (*args, "--capture-file", str(self.capture_path))
        env["DBUS_SYSTEM_BUS_ADDRESS"] = system_address or self.system.address
        env["DBUS_SESSION_BUS_ADDRESS"] = self.session.address
        self.agent_log = open(ROOT / "tests" / f".agent-{self.port}.log", "w")
        self.agent = subprocess.Popen([sys.executable, "-m", "agent", "--port", str(self.port), *args],
                                      cwd=ROOT, env=env, stdout=self.agent_log, stderr=subprocess.STDOUT)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                self.get("/api/health")
                return
            except Exception:
                if self.agent.poll() is not None:
                    raise RuntimeError("agent exited early")
                time.sleep(0.1)
        raise RuntimeError("agent did not start")

    def stop_agent(self) -> None:
        if self.agent:
            self.agent.send_signal(signal.SIGINT)
            try:
                self.agent.wait(8)
            except subprocess.TimeoutExpired:
                self.agent.kill()
            self.agent_log.close()
            self.agent = None

    def stop(self) -> None:
        self.stop_agent()
        self.stop_mock()
        self.capture_path.unlink(missing_ok=True)
        (ROOT / "tests" / f".agent-{self.port}.log").unlink(missing_ok=True)
        self.system.stop()
        self.session.stop()

    def agent_output(self) -> str:
        return (ROOT / "tests" / f".agent-{self.port}.log").read_text()

    # -- mock control (test-only D-Bus interface on the mock)
    def mock_call(self, method: str, *args: str) -> None:
        subprocess.run(["dbus-send", f"--bus={self.system.address}", "--print-reply", "--dest=org.bluez",
                        "/org/necklace/test", f"org.necklace.Test1.{method}", *args],
                       check=True, capture_output=True, timeout=5)

    def mock_options(self, **opts) -> None:
        self.mock_call("SetOptions", f"string:{json.dumps(opts)}")

    # -- HTTP
    def request(self, method: str, path: str, body=None, headers=None, raw_body: bytes | None = None):
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        data = raw_body
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read() or b"null"), dict(r.headers)
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                parsed = json.loads(payload)
            except ValueError:
                parsed = payload.decode(errors="replace")
            return e.code, parsed, dict(e.headers)

    def get(self, path: str, **kw):
        status, body, _ = self.request("GET", path, **kw)
        if status != 200:
            raise RuntimeError(f"GET {path} -> {status} {body}")
        return body["data"] if isinstance(body, dict) and "data" in body else body

    def post(self, path: str, body=None, **kw):
        return self.request("POST", path, body if body is not None else {}, **kw)

    def status(self) -> dict:
        return self.get("/api/status")

    def wait_status(self, pred, timeout: float = 5.0) -> dict:
        deadline = time.time() + timeout
        s = self.status()
        while not pred(s):
            if time.time() > deadline:
                raise AssertionError(f"condition not met; last status: {json.dumps(s, ensure_ascii=False)[:2000]}")
            time.sleep(0.1)
            s = self.status()
        return s

    def cap(self, s: dict, cid: str) -> dict:
        return next(r for r in s["capabilities"] if r["id"] == cid)
