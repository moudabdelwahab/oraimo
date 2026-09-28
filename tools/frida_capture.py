#!/usr/bin/env python3
"""Drive the passive RCSP Frida probe, or analyse a capture it already produced.

Two modes:

  Capture (needs a USB-connected rooted/frida-server Android running oraimo)::

      python tools/frida_capture.py --spawn com.transsion.oraimosound -o rcsp.ndjson
      python tools/frida_capture.py --attach oraimo -o rcsp.ndjson

    Attaches ``tools/frida_rcsp_probe.js`` (observation only -- it never writes
    to the socket), streams NDJSON records to the output file, and prints a live
    per-fd tally. Stop with Ctrl-C; the verdict is printed on exit.

  Analyse (no device needed -- run it here on a saved capture)::

      python tools/frida_capture.py --analyze rcsp.ndjson

    Re-runs the fd identification offline and prints which fd carried RCSP.

The heavy lifting (deciding which fd carries RCSP) lives in
``agent.rcsp_fd.identify_rcsp_fd`` and is shared with both modes, so the
capture path and the offline path always agree.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent import rcsp_fd  # noqa: E402

PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_rcsp_probe.js")


def analyze_file(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        records = rcsp_fd.parse_frida_capture(fh.read())
    verdict = rcsp_fd.identify_rcsp_fd(records)
    print(rcsp_fd.format_verdict(verdict))
    print("\n--- verdict (json) ---")
    print(json.dumps(verdict, ensure_ascii=False, indent=2))
    return 0 if verdict["rcsp_fd"] is not None else 1


def capture(args: argparse.Namespace) -> int:
    try:
        import frida  # imported lazily so --analyze works without frida installed
    except ImportError:
        print("frida is not installed. `pip install frida-tools`, or use --analyze "
              "on a capture made elsewhere.", file=sys.stderr)
        return 2

    with open(PROBE, encoding="utf-8") as fh:
        script_src = fh.read()

    device = frida.get_usb_device(timeout=10)
    if args.spawn:
        pid = device.spawn([args.spawn])
        session = device.attach(pid)
    else:
        session = device.attach(args.attach)
        pid = None

    out = open(args.output, "w", encoding="utf-8") if args.output else None
    tally: dict[int, int] = {}

    def on_message(message, data):
        if message.get("type") != "send":
            print("[frida]", message, file=sys.stderr)
            return
        payload = message["payload"]
        if out:
            out.write(json.dumps(payload, ensure_ascii=False) + "\n")
            out.flush()
        if "info" in payload or "note" in payload or "java" in payload:
            print("[probe]", json.dumps(payload, ensure_ascii=False), file=sys.stderr)
        elif "fd" in payload and "hex" in payload:
            fd = payload["fd"]
            tally[fd] = tally.get(fd, 0) + 1
            print(f"  fd {fd} carries RCSP marker ×{tally[fd]}  ({payload.get('dir')})",
                  file=sys.stderr)

    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)

    print("Probe attached (passive). Exercise the app, then press Ctrl-C to finish.",
          file=sys.stderr)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.unload()
            session.detach()
        except Exception:
            pass
        if out:
            out.close()

    if args.output and os.path.exists(args.output):
        print("\n=== verdict ===", file=sys.stderr)
        return analyze_file(args.output)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--analyze", metavar="FILE", help="analyse a saved NDJSON capture offline")
    g.add_argument("--spawn", metavar="PACKAGE", help="spawn and instrument this package")
    g.add_argument("--attach", metavar="NAME_OR_PID", help="attach to a running app")
    ap.add_argument("-o", "--output", metavar="FILE", help="write NDJSON capture here")
    args = ap.parse_args(argv)

    if args.analyze:
        return analyze_file(args.analyze)
    return capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
