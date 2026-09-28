"""Identify which file descriptor carries the JieLi RCSP transport.

This is the offline half of the Frida experiment (``tools/frida_rcsp_probe.js``).
The Frida probe watches the official oraimo app **passively** -- it hooks the
libc socket calls (and the Java ``BluetoothSocket`` layer) only to *observe* the
bytes going over each fd, and emits one NDJSON record per buffer that contains
the RCSP start marker. It never writes, injects, or replaces anything.

Given that capture, :func:`identify_rcsp_fd` reassembles each fd's byte stream
and runs the *proven* envelope decoder from :mod:`agent.sniffer`
(``FE DC BA .. EF``, see ``docs/jieli-rcsp-apk.md``). The fd that yields real
RCSP frames is the SPP/RFCOMM-10 socket the app talks to the headset on. We
decode only the transport envelope; command payloads stay raw, exactly as in
the btsnoop path. Nothing here opens a socket or sends a byte.

Capture record schema (one JSON object per line)::

    {"t": 12.34, "fd": 47, "dir": "tx"|"rx", "target": "socket:[123456]", "hex": "fedcba…"}

* ``t``      -- seconds since the probe attached (float, optional).
* ``fd``     -- the file descriptor the app read/wrote (int, required).
* ``dir``    -- ``tx`` = write/send (app -> headset), ``rx`` = read/recv.
* ``target`` -- ``readlink(/proc/<pid>/fd/<fd>)`` if the probe resolved it.
* ``hex``    -- the observed buffer bytes as hex (spaces optional).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import sniffer


@dataclass
class FdRecord:
    """One observed socket buffer from the Frida probe."""
    fd: int
    direction: str | None          # "tx" | "rx" | None
    data: bytes
    ts: float | None = None
    target: str | None = None      # /proc/<pid>/fd/<fd> link, e.g. "socket:[123456]"


def _coerce_hex(value: str) -> bytes:
    return bytes.fromhex(value.replace(" ", "").replace(":", ""))


def parse_frida_capture(text: str) -> list[FdRecord]:
    """Parse the NDJSON capture emitted by ``frida_rcsp_probe.js``.

    Blank lines and lines that are not objects with an ``fd`` and ``hex`` are
    skipped, so a capture interleaved with human notes still parses.
    """
    records: list[FdRecord] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict) or "fd" not in obj or "hex" not in obj:
            continue
        try:
            fd = int(obj["fd"])
            data = _coerce_hex(str(obj["hex"]))
        except (ValueError, TypeError):
            continue
        direction = obj.get("dir")
        if direction not in ("tx", "rx", None):
            direction = None
        ts = obj.get("t")
        records.append(FdRecord(
            fd=fd,
            direction=direction,
            data=data,
            ts=float(ts) if isinstance(ts, (int, float)) else None,
            target=obj.get("target") if isinstance(obj.get("target"), str) else None,
        ))
    return records


@dataclass
class _FdStat:
    fd: int
    frames: int = 0
    commands: int = 0
    replies: int = 0
    opcodes: dict[str, int] = field(default_factory=dict)
    directions: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    magic_seen: bool = False        # RCSP start marker appeared on this fd
    bytes_seen: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    samples: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "fd": self.fd,
            "frames": self.frames,
            "commands": self.commands,
            "replies": self.replies,
            "opcodes": dict(sorted(self.opcodes.items(), key=lambda kv: -kv[1])),
            "directions": sorted(self.directions),
            "targets": sorted(self.targets),
            "magic_seen": self.magic_seen,
            "bytes_seen": self.bytes_seen,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "samples": self.samples,
        }


def identify_rcsp_fd(records: list[FdRecord], max_samples: int = 20) -> dict:
    """Decide which fd carries RCSP from a passive Frida capture.

    Reassembles each ``(fd, direction)`` stream, extracts complete RCSP frames
    with :func:`agent.sniffer.rcsp_extract`, and ranks fds by how many valid
    frames they yield. The winner is the SPP socket the app uses for RCSP.

    Returns a verdict dict with ``rcsp_fd`` (the best fd, or ``None``),
    ``confidence`` (``"high"``/``"low"``/``"none"``), per-fd ``candidates``
    sorted by frame count, and ``other_fds`` that carried traffic but no RCSP
    frame. Read-only analysis; opens nothing.
    """
    stats: dict[int, _FdStat] = {}
    # reassembly buffers are per (fd, direction): a frame never spans directions.
    buffers: dict[tuple[int, str | None], bytearray] = {}

    for rec in sorted(records, key=lambda r: (r.ts is None, r.ts or 0.0)):
        st = stats.setdefault(rec.fd, _FdStat(fd=rec.fd))
        st.bytes_seen += len(rec.data)
        if rec.direction:
            st.directions.add(rec.direction)
        if rec.target:
            st.targets.add(rec.target)
        if rec.ts is not None:
            st.first_ts = rec.ts if st.first_ts is None else min(st.first_ts, rec.ts)
            st.last_ts = rec.ts if st.last_ts is None else max(st.last_ts, rec.ts)
        if sniffer.RCSP_MAGIC in rec.data:
            st.magic_seen = True

        buf = buffers.setdefault((rec.fd, rec.direction), bytearray())
        buf += rec.data
        for frame in sniffer.rcsp_extract(buf):
            decoded = sniffer.decode_rcsp_frame(frame)
            st.frames += 1
            if decoded["is_command"]:
                st.commands += 1
            else:
                st.replies += 1
            name = decoded["opcode_name"]
            st.opcodes[name] = st.opcodes.get(name, 0) + 1
            if len(st.samples) < max_samples:
                st.samples.append({"ts": rec.ts, "direction": rec.direction,
                                   **sniffer.rcsp_frame_json(decoded)})

    candidates = sorted((s for s in stats.values() if s.frames),
                        key=lambda s: (-s.frames, s.fd))
    others = sorted((s for s in stats.values() if not s.frames),
                    key=lambda s: (-s.bytes_seen, s.fd))

    best = candidates[0] if candidates else None
    if best is None:
        confidence = "none"
    elif len(candidates) == 1 or best.frames >= 2 * candidates[1].frames:
        # a single frame-bearing fd, or a clear leader, is a confident answer
        confidence = "high" if best.frames >= 2 else "low"
    else:
        confidence = "low"

    return {
        "rcsp_fd": best.fd if best else None,
        "confidence": confidence,
        "total_frames": sum(s.frames for s in stats.values()),
        "fds_observed": len(stats),
        "candidates": [s.as_dict() for s in candidates],
        "other_fds": [s.as_dict() for s in others],
    }


def format_verdict(verdict: dict) -> str:
    """Human-readable (Arabic) one-block summary of :func:`identify_rcsp_fd`."""
    lines: list[str] = []
    fd = verdict["rcsp_fd"]
    conf = {"high": "ثقة عالية", "low": "ثقة منخفضة", "none": "بلا نتيجة"}[verdict["confidence"]]
    if fd is None:
        lines.append(f"لم يُعثر على fd يحمل إطارات RCSP ({conf}). "
                     f"fd مرصودة: {verdict['fds_observed']}.")
    else:
        lines.append(f"fd الذي يحمل RCSP: {fd} — {conf}، "
                     f"{verdict['total_frames']} إطار على {verdict['fds_observed']} fd.")
    for c in verdict["candidates"]:
        tgt = f" [{', '.join(c['targets'])}]" if c["targets"] else ""
        dirs = "/".join(c["directions"]) or "—"
        ops = "، ".join(f"{k}×{v}" for k, v in c["opcodes"].items()) or "—"
        lines.append(f"  • fd {c['fd']}{tgt}: {c['frames']} إطار "
                     f"(أوامر {c['commands']}، ردود {c['replies']}؛ {dirs}؛ {ops})")
    return "\n".join(lines)
