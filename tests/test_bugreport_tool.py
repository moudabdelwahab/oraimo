"""Tests for tools/inspect_bugreport.py (read-only bug report inspector). Synthetic data only."""
import base64
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

from tests import btsnoop_writer as bw

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import inspect_bugreport as ib  # noqa: E402


def _summary_block(n=10):
    recs = b"".join(struct.pack("<HHIB", 7, 6, 50, 0x11) + bytes([0x0E, 4, 1, 3, 0x0C, 0]) for _ in range(n))
    raw = bytes([2]) + struct.pack("<Q", int(time.time() * 1000)) + zlib.compress(recs)
    return "--- BEGIN:BTSNOOP_LOG_SUMMARY (x bytes in) ---\n" + base64.b64encode(raw).decode() + "\n--- END:BTSNOOP_LOG_SUMMARY ---\n"


def _make(tmp_path, *, full=False, summary=False, mode="disabled"):
    text = ("Build fingerprint: 'OPPO/CPH2699/x:16/y/z:user/release-keys'\n"
            "[ro.product.model]: [CPH2699]\n[ro.build.version.release]: [16]\n"
            f"[persist.bluetooth.btsnooplogmode]: [{mode}]\nDUMP OF SERVICE bluetooth_manager:\n")
    if summary:
        text += _summary_block()
    p = tmp_path / "bugreport.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("main_entry.txt", "bugreport-CPH2699.txt")
        z.writestr("bugreport-CPH2699.txt", text)
        if full:
            t = time.time()
            mon = bw.header() + bw.setup(t) + bw.passthrough(0x44, ts=t)
            z.writestr("FS/data/misc/bluetooth/logs/btsnoop_hci.log", bw.to_android_h4(mon))
    return p


def test_full_log_detected(tmp_path):
    r = ib.inspect(str(_make(tmp_path, full=True, summary=True, mode="full")))
    assert r["verdict"] == "full_btsnoop"
    f = r["btsnoop_files"][0]
    assert f["valid"] and f["datalink"] == 1002 and f["acl_records"] > 0
    assert r["properties"]["persist.bluetooth.btsnooplogmode"] == "full"


def test_summary_only_detected(tmp_path):
    r = ib.inspect(str(_make(tmp_path, summary=True)))
    assert r["verdict"] == "summary_only"
    s = r["summaries"][0]
    assert s["records"] == 10 and s["version"] == 2 and s["truncated_packets"] == 0


def test_nothing_found(tmp_path):
    r = ib.inspect(str(_make(tmp_path)))
    assert r["verdict"] == "none" and r["bluetooth_manager_dump"] and not r["summaries"]


def test_corrupt_summary_reported_not_crashing(tmp_path):
    p = tmp_path / "b.txt"
    p.write_text("--- BEGIN:BTSNOOP_LOG_SUMMARY ---\nAAAAAAAAAAAAAAAAAAAAAAAA\n--- END:BTSNOOP_LOG_SUMMARY ---\n")
    r = ib.inspect(str(p))
    assert r["verdict"] == "none" and "error" in r["summaries"][0]


def test_tool_is_read_only():
    src = (Path(__file__).resolve().parent.parent / "tools" / "inspect_bugreport.py").read_text()
    for forbidden in ("adb", "subprocess", "os.system", '"w"', "'w'", ".write(", "extract", "unlink", "setprop"):
        assert forbidden not in src.replace("writes no files", "").replace("write no files", ""), forbidden
