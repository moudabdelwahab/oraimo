"""Tests for the passive JieLi RCSP envelope decoder in agent/sniffer.py.

These exercise pure byte parsing only. The decoder opens no socket and emits no
byte; the raw-socket safety guard lives in test_agent.py.
"""

from agent import sniffer as s


def frame(flag: int, opcode: int, payload: bytes) -> bytes:
    """Build one FE DC BA .. EF frame with a big-endian length."""
    body = bytes((flag, opcode)) + len(payload).to_bytes(2, "big") + payload
    return s.RCSP_MAGIC + body + bytes((s.RCSP_END,))


def test_decode_command_with_datacmd_xmopcode():
    # bit7 set = command, bit6 set = needs reply; DataCmd(0x01) carries XM opcode
    d = s.decode_rcsp_frame(frame(0xC0, 0x01, bytes((0x05, 0x22, 0xAA, 0xBB))))
    assert d["is_command"] and d["needs_reply"]
    assert d["opcode"] == 0x01 and d["opcode_name"] == "DataCmd"
    assert d["sn"] == 0x05 and d["xm_opcode"] == 0x22
    assert d["data"] == bytes((0xAA, 0xBB))
    assert "status" not in d


def test_decode_reply_has_status_then_sn():
    # bit7 clear = reply: STATUS, SN, then (op 0x01) XM opcode, then data
    d = s.decode_rcsp_frame(frame(0x00, 0x01, bytes((0x00, 0x05, 0x22, 0xCC))))
    assert not d["is_command"] and not d["needs_reply"]
    assert d["status"] == 0x00 and d["sn"] == 0x05 and d["xm_opcode"] == 0x22
    assert d["data"] == bytes((0xCC,))


def test_non_datacmd_has_no_xmopcode():
    d = s.decode_rcsp_frame(frame(0x80, 0x11, bytes((0x07, 0xDE, 0xAD))))
    assert d["opcode_name"] == "PushStartTtsCmd"
    assert d["sn"] == 0x07 and "xm_opcode" not in d
    assert d["data"] == bytes((0xDE, 0xAD))


def test_extract_multiple_frames_in_one_buffer():
    f1 = frame(0xC0, 0x01, bytes((1, 2, 3)))
    f2 = frame(0x00, 0x01, bytes((0, 1, 2)))
    buf = bytearray(f1 + f2)
    frames = s.rcsp_extract(buf)
    assert len(frames) == 2 and len(buf) == 0


def test_reassembles_fragmented_frame():
    f1 = frame(0xC0, 0x01, bytes((5, 0x22, 0xAA, 0xBB)))
    buf = bytearray(f1[:4])
    assert s.rcsp_extract(buf) == []          # incomplete: nothing yet
    buf += f1[4:]
    got = s.rcsp_extract(buf)
    assert len(got) == 1 and s.decode_rcsp_frame(got[0])["sn"] == 5


def test_resyncs_past_leading_garbage_and_bad_trailer():
    f = frame(0x00, 0x01, bytes((0, 5, 0x22, 0xCC)))
    assert len(s.rcsp_extract(bytearray(b"\x99\x88\x00" + f))) == 1
    # a frame whose trailer is wrong is dropped, the following good frame survives
    bad = bytearray(s.RCSP_MAGIC + bytes((0xC0, 0x01, 0x00, 0x01, 0xAA, 0x00)))  # trailer 0x00, not EF
    assert s.rcsp_extract(bad + f) == [f]


def test_partial_magic_is_kept_for_next_chunk():
    buf = bytearray(s.RCSP_MAGIC[:2])         # split magic marker across chunks
    assert s.rcsp_extract(buf) == []
    assert len(buf) == 2                        # retained, not discarded


def test_summarize_collects_rcsp_section():
    cmd = s.rcsp_frame_json(s.decode_rcsp_frame(frame(0xC0, 0x01, bytes((1, 0x22, 0xAA)))))
    rep = s.rcsp_frame_json(s.decode_rcsp_frame(frame(0x00, 0x01, bytes((0, 1, 0x22)))))
    packets = [
        s.Packet(seq=1, ts=1.0, hci="ACL", direction="tx", protocol="JieLi RCSP (RFCOMM)",
                 summary="", classification="vendor", fields={"rcsp_frames": [cmd]}),
        s.Packet(seq=2, ts=2.0, hci="ACL", direction="rx", protocol="JieLi RCSP (RFCOMM)",
                 summary="", classification="vendor", fields={"rcsp_frames": [rep]}),
    ]
    rcsp = s.summarize_packets(packets)["rcsp"]
    assert rcsp["frames"] == 2 and rcsp["commands"] == 1 and rcsp["replies"] == 1
    assert rcsp["opcodes"]["DataCmd"] == 2
    assert len(rcsp["samples"]) == 2 and rcsp["samples"][0]["direction"] == "tx"
