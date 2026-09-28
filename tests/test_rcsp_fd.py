"""Tests for identifying which fd carries RCSP from a passive Frida capture.

Pure offline analysis of NDJSON records: no device, no socket, no send. The
Frida probe (tools/frida_rcsp_probe.js) is observation-only; these tests cover
the decision logic in agent/rcsp_fd.py that turns its capture into a verdict.
"""
import json
import os

from agent import rcsp_fd


def frame(flag: int, opcode: int, payload: bytes) -> bytes:
    """Build one FE DC BA .. EF frame with a big-endian length."""
    from agent import sniffer as s
    body = bytes((flag, opcode)) + len(payload).to_bytes(2, "big") + payload
    return s.RCSP_MAGIC + body + bytes((s.RCSP_END,))


def rec(fd, direction, data, t=None, target=None) -> str:
    obj = {"fd": fd, "dir": direction, "hex": data.hex()}
    if t is not None:
        obj["t"] = t
    if target is not None:
        obj["target"] = target
    return json.dumps(obj)


def test_picks_the_fd_with_rcsp_frames():
    f_cmd = frame(0xC0, 0x01, bytes((1, 0x22, 0xAA)))
    f_rep = frame(0x00, 0x01, bytes((0, 1, 0x22, 0xBB)))
    cap = "\n".join([
        rec(47, "tx", f_cmd, t=1.0, target="socket:[12345]"),
        rec(47, "rx", f_rep, t=1.1, target="socket:[12345]"),
        rec(9, "rx", b"\x00\x01\x02\x03 not rcsp", t=0.5),      # noise fd
        rec(12, "tx", b"GET / HTTP/1.1\r\n", t=0.6),            # unrelated fd
    ])
    verdict = rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(cap))
    assert verdict["rcsp_fd"] == 47
    assert verdict["confidence"] == "high"
    assert verdict["total_frames"] == 2
    cand = verdict["candidates"][0]
    assert cand["fd"] == 47 and cand["commands"] == 1 and cand["replies"] == 1
    assert cand["opcodes"]["DataCmd"] == 2
    assert cand["targets"] == ["socket:[12345]"]
    assert {"tx", "rx"} == set(cand["directions"])
    # the noise fds are reported separately, never as the answer
    assert {c["fd"] for c in verdict["other_fds"]} == {9, 12}


def test_reassembles_frame_split_across_two_reads_on_same_fd():
    f = frame(0xC0, 0x01, bytes((5, 0x22, 0xAA, 0xBB, 0xCC)))
    cap = "\n".join([
        rec(31, "rx", f[:6], t=1.0),
        rec(31, "rx", f[6:], t=1.2),
    ])
    verdict = rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(cap))
    assert verdict["rcsp_fd"] == 31
    assert verdict["candidates"][0]["frames"] == 1


def test_direction_streams_do_not_bleed_into_each_other():
    # a tx fragment and an rx fragment on the same fd must not be spliced into
    # one bogus frame; each direction reassembles on its own.
    f = frame(0xC0, 0x01, bytes((1, 0x22, 0xAA)))
    cap = "\n".join([
        rec(20, "tx", f[:5], t=1.0),
        rec(20, "rx", f[5:], t=1.1),
    ])
    verdict = rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(cap))
    assert verdict["rcsp_fd"] is None
    assert verdict["confidence"] == "none"


def test_magic_without_valid_trailer_is_not_a_match():
    # bytes that contain FE DC BA but no valid framed EF must not count as RCSP
    junk = bytes((0xFE, 0xDC, 0xBA, 0x11, 0x22, 0x00, 0x02, 0xAA, 0xBB, 0x33))
    cap = rec(5, "rx", junk, t=1.0)
    verdict = rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(cap))
    assert verdict["rcsp_fd"] is None
    # but the fd is still surfaced as having shown the marker
    other = {c["fd"]: c for c in verdict["other_fds"]}
    assert other[5]["magic_seen"] is True and other[5]["frames"] == 0


def test_clear_leader_beats_incidental_second_fd():
    strong = "\n".join(rec(50, "rx", frame(0x80, 0x11, bytes((i,))), t=float(i))
                       for i in range(4))
    weak = rec(60, "rx", frame(0x80, 0x11, bytes((9,))), t=99.0)
    verdict = rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(strong + "\n" + weak))
    assert verdict["rcsp_fd"] == 50
    assert verdict["confidence"] == "high"        # 4 frames vs 1 -> clear leader
    assert [c["fd"] for c in verdict["candidates"]] == [50, 60]


def test_parse_skips_notes_and_non_data_records():
    cap = "\n".join([
        "# a human note about the run",
        json.dumps({"t": 0.0, "info": "probe attached"}),
        json.dumps({"t": 0.1, "java": "BluetoothSocket.connect", "fd": 47}),  # no hex
        rec(47, "tx", frame(0xC0, 0x01, bytes((1, 0x22))), t=1.0),
        "not json at all",
    ])
    records = rcsp_fd.parse_frida_capture(cap)
    assert len(records) == 1 and records[0].fd == 47
    verdict = rcsp_fd.identify_rcsp_fd(records)
    assert verdict["rcsp_fd"] == 47


def test_format_verdict_is_readable_and_mentions_fd():
    cap = rec(47, "tx", frame(0xC0, 0x01, bytes((1, 0x22, 0xAA))), t=1.0,
              target="socket:[999]")
    text = rcsp_fd.format_verdict(rcsp_fd.identify_rcsp_fd(rcsp_fd.parse_frida_capture(cap)))
    assert "47" in text and "RCSP" in text


def test_probe_script_is_passive_no_injection():
    """The Frida probe must observe only: no .replace, no write/send calls."""
    path = os.path.join(os.path.dirname(__file__), "..", "tools", "frida_rcsp_probe.js")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    assert "Interceptor.replace" not in src        # never rewrite behaviour
    # the probe must not itself invoke socket writes (only hook/observe them)
    for banned in ("new NativeFunction(sendmsgPtr", "new NativeFunction(writePtr",
                   ".sendmsg(", ".write("):
        assert banned not in src, f"probe appears to inject: {banned}"
    assert "Interceptor.attach" in src             # it does hook, just passively
