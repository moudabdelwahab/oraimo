"""Phase 2 tests: safe scan, passive decoder, research mode, capability matrix.

Everything runs against TEST-ONLY stand-ins (mock BlueZ, fake sdptool built from
the real capture's SDP bytes, synthetic btsnoop files). No hardware involved.
"""

import re
import time
from pathlib import Path

from agent import discovery, hid, sniffer
from tests import btsnoop_writer as bw

ROOT = Path(__file__).resolve().parent.parent
TARGET = "28:52:E0:0F:92:0A"


# ============================================================ decoder (unit)
def test_decoder_on_synthetic_capture():
    t = time.time()
    data = (bw.header() + bw.setup(t) + bw.passthrough(0x4B, ts=t) + bw.volume_changed(120, ts=t)
            + bw.set_absolute_volume(64, ts=t) + bw.rfcomm_sabm(10, ts=t) + bw.rfcomm_uih(10, b"\xfe\xdc\xba\xc0\x06", ts=t)
            + bw.rfcomm_uih(4, b"AT+IPHONEACCEV=1,1,6\r", ts=t) + bw.hid_report(bytes([3, 0x20, 0, 0]), ts=t))
    r = sniffer.analyze_bytes(data, TARGET)
    pk = r["packets"]
    by = lambda proto: [p for p in pk if p["protocol"] == proto]  # noqa: E731
    assert r["devices"] == [TARGET]
    # passthrough FORWARD (Next) from the headset, standard
    fwd = [p for p in by("AVRCP") if p["fields"].get("operation") == "FORWARD"]
    assert len(fwd) == 4 and all(p["classification"] == "standard" for p in fwd)
    assert fwd[0]["direction"] == "rx" and fwd[0]["opcode"].startswith("PASS THROUGH 0x4B")
    assert r["summary"]["passthrough"] == {"FORWARD (السماعة)": 1}
    assert any(p["fields"].get("volume") == 120 and p["fields"].get("ctype") == "CHANGED" for p in by("AVRCP"))
    assert any(p["fields"].get("pdu") == "SetAbsoluteVolume" and p["fields"].get("ctype") == "ACCEPTED" for p in by("AVRCP"))
    # JieLi channel: vendor-specific, never decoded
    j = [p for p in pk if p["classification"] == "vendor"]
    assert any(p["opcode"] == "SABM" for p in j) and any(p["protocol"] == "JieLi (RFCOMM)" for p in j)
    assert "غير مفككة" in by("JieLi (RFCOMM)")[0]["summary"]
    # HFP Apple battery extension
    hfp = by("HFP")[0]
    assert hfp["classification"] == "extension" and "70%" in hfp["summary"]
    # HID input report decoded with the captured descriptor
    assert by("HID")[0]["fields"]["pressed"] == ["Play/Pause"]
    # link key masked
    lk = next(p for p in pk if p["opcode"] and "Link Key Request Reply" in p["opcode"])
    assert "a0 a1" not in lk["raw"] and "مخفي" in lk["raw"]


def test_decoder_rejects_non_btsnoop():
    try:
        sniffer.analyze_bytes(b"not a capture file at all")
    except ValueError as e:
        assert "btsnoop" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_sdptool_xml_fixture_matches_capture():
    fx = ROOT / "tests" / "fixtures"
    recs = discovery.parse_sdptool_xml((fx / "sdp_l2cap.xml").read_text()) + \
        discovery.parse_sdptool_xml((fx / "sdp_pnp.xml").read_text())
    by = {r["handle"]: r for r in recs}
    assert len(by) == 8
    assert by[0x10011]["rfcomm_channel"] == 10 and by[0x10011]["classes"] == ["fe010000-1234-5678-abcd-00805f9b34fb"]
    assert by[0x10003]["rfcomm_channel"] == 4 and by[0x10004]["rfcomm_channel"] == 1
    assert by[0x10006]["l2cap_psm"] == 0x11 and bytes.fromhex(by[0x10006]["hid_descriptor"]) == hid.CAPTURED_DESCRIPTOR
    assert by[0x10005]["features"] == 2 and by[0x10002]["features"] == 1


def test_discovery_module_has_no_active_or_write_paths():
    src = (ROOT / "agent" / "discovery.py").read_text() + (ROOT / "agent" / "sniffer.py").read_text()
    for forbidden in ("WriteValue", "StartNotify", "AcquireWrite", "AcquireNotify", "ReadValue", "ConnectProfile",
                      "hcitool", "btmgmt", "l2ping", "rfcomm connect", "AF_BLUETOOTH", "socket.socket", "open(self.path, \"w",
                      "open(self.path, 'w"):
        assert forbidden not in src, forbidden
    # the only external command is `sdptool browse --xml --uuid <fixed> <validated address>`
    calls = re.findall(r"self\._run\(\[(.*?)\]", src)
    assert calls and all(c.startswith('tool, "browse", "--xml", "--uuid", uuid') for c in calls), calls


# ============================================================ safe scan (integration)
def test_safe_scan_connected(env, tmp_path):
    log = tmp_path / "sdptool.log"
    env.stop_agent()
    env.start_agent(extra_env={"FAKE_SDPTOOL_LOG": str(log)})
    st, body, _ = env.post("/api/discovery/scan")
    assert st == 200, body
    scan = body["data"]
    steps = {s["id"]: s for s in scan["steps"]}
    assert steps["sdp"]["status"] == "ok" and len(scan["sdp"]) == 8
    assert steps["dbus"]["status"] == "ok" and steps["uuids"]["status"] == "ok"
    assert {r["channel"] for r in scan["rfcomm"]} == {1, 4, 10}
    assert "لم تُفتح أي قناة" in steps["rfcomm"]["detail"]
    assert scan["hid_sdp"]["matches_capture"] is True
    assert steps["gatt"]["status"] == "unavailable"
    # only standard SDP browse queries were issued
    issued = log.read_text().splitlines()
    assert issued == [f"browse --xml --uuid 0x0100 {TARGET}", f"browse --xml --uuid 0x1200 {TARGET}"]
    d = env.get("/api/discovery")
    jl = next(s for s in d["services"] if s["rfcomm_channel"] == 10)
    assert jl["blocked"] and jl["live_sdp"] and jl["state"] == "present"
    assert any(e["type"] == "فحص آمن" and "لا تُرسل أي أوامر" in e["data"] for e in env.get("/api/discovery/log"))


def test_safe_scan_disconnected_skips_sdp(env):
    env.mock_call("SetConnected", "boolean:false")
    env.wait_status(lambda s: not s["connection"]["connected"])
    st, body, _ = env.post("/api/discovery/scan")
    steps = {s["id"]: s for s in body["data"]["steps"]}
    assert steps["sdp"]["status"] == "skipped"
    assert {r["channel"] for r in body["data"]["rfcomm"]} == {1, 4, 10}  # capture reference used
    assert body["data"]["rfcomm"][0]["source"] == "الالتقاط"


def test_safe_scan_without_sdptool(make_env, tmp_path):
    env = make_env(extra_env={"PATH": str(tmp_path)})
    st, body, _ = env.post("/api/discovery/scan")
    assert {s["id"]: s for s in body["data"]["steps"]}["sdp"]["status"] == "unavailable"


def test_safe_scan_sdptool_failure(make_env):
    env = make_env(extra_env={"FAKE_SDPTOOL_FAIL": "1"})
    st, body, _ = env.post("/api/discovery/scan")
    assert st == 200 and {s["id"]: s for s in body["data"]["steps"]}["sdp"]["status"] == "failed"


# ============================================================ matrix & view
def test_capability_matrix_and_views(env):
    d = env.get("/api/discovery")
    m = {r["id"]: r for r in d["matrix"]}
    assert m["headset_play_pause"]["status_label"] == "مؤكدة"
    assert m["volume_read"]["status_label"] == "مؤكدة"
    assert m["battery_hfp"]["status_label"] == "مؤكدة" and m["battery_hfp"]["source"].startswith("HFP")
    assert m["hid"]["status_label"] == "معلنة فقط" and m["hid"]["method"] == "تحتاج اختبار اتصال آمن"
    assert m["jieli"]["status_label"] == "موجودة" and m["jieli"]["safe"] == "لا ترسل أوامر مجهولة" and not m["jieli"]["safe_ok"]
    assert m["volume_set"]["status_label"] == "معلنة فقط"
    assert m["next_prev"]["status_label"] == "غير معروفة"
    # volume write verified at runtime -> confirmed
    env.post("/api/volume", {"percent": 50})
    m = {r["id"]: r for r in env.get("/api/discovery")["matrix"]}
    assert m["volume_set"]["status_label"] == "مؤكدة"
    assert d["hid"]["status_label"] == "معلن لكنه غير متاح حاليًا / يحتاج اختبار اتصال آمن"
    assert d["jieli"]["status_label"] == "خدمة مخصصة من الشركة - البروتوكول غير معروف"
    assert d["jieli"]["rfcomm_channel"] == 10
    assert {r["report_id"] for r in d["hid"]["reports"]} == {2, 3}
    assert "PLAYBACK_STATUS_CHANGED" in d["avrcp"]["headset_registered"]
    assert d["capture"]["command"].startswith("sudo btmon -w ")


# ============================================================ research mode
def test_research_requires_session_and_whitelist(env):
    st, body, _ = env.post("/api/research/headset", {"action": "next"})
    assert st == 400
    env.post("/api/research/start")
    st, body, _ = env.post("/api/research/headset", {"action": "factory_reset"})
    assert st == 403 and body["error"]["code"] == "action_not_allowed"
    st, body, _ = env.post("/api/research/host", {"action": "mute"})
    assert st == 501 and body["error"]["code"] == "unsupported"


def test_research_host_next_uses_mpris(env):
    env.post("/api/research/start")
    st, body, _ = env.post("/api/research/host", {"action": "next"})
    assert st == 200, body
    tid = body["data"]["trial"]["id"]
    deadline = time.time() + 8
    while time.time() < deadline:
        trial = next(t for t in env.get("/api/discovery")["research"]["trials"] if t["id"] == tid)
        if trial["status"] == "done":
            break
        time.sleep(0.3)
    assert trial["status"] == "done"
    assert trial["host_result"]["ok"] and trial["host_result"]["player"] == "Mock Player"
    # no btmon capture in this test -> an honest warning, not a fake result
    assert any("لا يوجد التقاط HCI" in f["text"] for f in trial["findings"])
    assert env.status()["media"]["player"]["metadata"]["title"] == "مقطع تجريبي 2"


def test_research_headset_trial_correlates_live_capture(env):
    """btmon writes a file; the agent tails it; a headset-button trial correlates FORWARD."""
    cap = Path(env.capture_path)
    t = time.time()
    cap.write_bytes(bw.header() + bw.setup(t))
    deadline = time.time() + 5
    while not env.get("/api/discovery")["capture"]["target_handles"] and time.time() < deadline:
        time.sleep(0.2)
    assert env.get("/api/discovery")["capture"]["active"]
    assert env.get("/api/discovery")["capture"]["target_handles"] == [bw.H]
    env.post("/api/research/start")
    st, body, _ = env.post("/api/research/headset", {"action": "next"})
    tid = body["data"]["trial"]["id"]
    time.sleep(0.5)
    with cap.open("ab") as f:  # the user presses "next" on the headset
        now = time.time()
        f.write(bw.passthrough(0x4B, ts=now) + bw.rfcomm_uih(10, b"\x01\x02\x03", ts=now))
    deadline = time.time() + 10
    while time.time() < deadline:
        trial = next(t for t in env.get("/api/discovery")["research"]["trials"] if t["id"] == tid)
        if trial["status"] == "done":
            break
        time.sleep(0.3)
    assert trial["status"] == "done"
    ops = [p["fields"].get("operation") for p in trial["packets"] if p["protocol"] == "AVRCP"]
    assert "FORWARD" in ops
    texts = [f["text"] for f in trial["findings"]]
    assert any("FORWARD (0x4B)" in x for x in texts)
    assert any(f["kind"] == "vendor" for f in trial["findings"])
    for p in trial["packets"]:
        assert {"raw", "protocol", "channel", "opcode", "summary", "classification"} <= set(p)
    m = {r["id"]: r for r in env.get("/api/discovery")["matrix"]}
    assert m["next_prev"]["status_label"] == "مؤكدة"
    assert "رُصدت" in m["jieli"]["evidence"]
    log = env.get("/api/discovery/log")
    assert any(e["classification"] == "vendor" for e in log)


def test_analyze_upload(env):
    t = time.time()
    data = bw.header() + bw.setup(t) + bw.passthrough(0x44, ts=t) + bw.rfcomm_uih(10, b"\xaa\xbb", ts=t)
    st, body, _ = env.request("POST", "/api/capture/analyze", raw_body=data,
                              headers={"Content-Type": "application/octet-stream"})
    assert st == 200, body
    res = body["data"]
    assert res["datalink"] == 2001 and res["summary"]["passthrough"] == {"PLAY (السماعة)": 1}
    assert len(res["vendor_packets"]) == 1
    # wrong content type / garbage are rejected cleanly
    st, body, _ = env.request("POST", "/api/capture/analyze", raw_body=data, headers={"Content-Type": "application/json"})
    assert st == 415
    st, body, _ = env.request("POST", "/api/capture/analyze", raw_body=b"x" * 64,
                              headers={"Content-Type": "application/octet-stream"})
    assert st == 400 and body["error"]["code"] == "bad_request"


def test_json_routes_still_limited(env):
    st, body, _ = env.post("/api/research/headset", {"action": "x" * 5000})
    assert st == 400


def test_overlapping_trials_are_flagged(env):
    env.post("/api/research/start")
    env.post("/api/research/headset", {"action": "next"})
    st, body, _ = env.post("/api/research/host", {"action": "volume_down"})
    tid = body["data"]["trial"]["id"]
    deadline = time.time() + 10
    while time.time() < deadline:
        trial = next(t for t in env.get("/api/discovery")["research"]["trials"] if t["id"] == tid)
        if trial["status"] == "done":
            break
        time.sleep(0.3)
    assert any("تتداخل" in f["text"] and f["kind"] == "warning" for f in trial["findings"])


def test_android_h4_capture_is_decoded():
    """Android HCI snoop logs (datalink 1002) - the format of the official-app capture."""
    t = time.time()
    mon = bw.header() + bw.setup(t) + bw.passthrough(0x44, ts=t) + bw.rfcomm_sabm(10, direction="tx", ts=t) \
        + bw.rfcomm_uih(10, b"\xfe\xdc\xba\x00", direction="tx", ts=t)
    r = sniffer.analyze_bytes(bw.to_android_h4(mon), TARGET)
    assert r["datalink"] == 1002
    assert r["summary"]["passthrough"] == {"PLAY (السماعة)": 1}
    vendor = [p for p in r["packets"] if p["classification"] == "vendor"]
    assert {p["opcode"] for p in vendor} >= {"SABM", "4 بايت"}
    assert all(p["direction"] == "tx" for p in vendor)
