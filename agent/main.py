"""Entry point: ``python -m agent`` (run from the necklace-controller folder)."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from aiohttp import web

from . import device as dev
from .api import create_app
from .controller import AGENT_VERSION, Controller

ROOT = Path(__file__).resolve().parent.parent


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="necklace-agent", description="Local Bluetooth agent for the Oraimo Necklace Lite")
    p.add_argument("--host", default=os.environ.get("NECKLACE_HOST", "127.0.0.1"),
                   help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=int(os.environ.get("NECKLACE_PORT", "8765")))
    p.add_argument("--device", default=os.environ.get("NECKLACE_DEVICE", dev.DEFAULT_ADDRESS),
                   help="headset Bluetooth address")
    p.add_argument("--adapter", default=os.environ.get("NECKLACE_ADAPTER"), help="adapter name, e.g. hci0")
    p.add_argument("--frontend", default=str(ROOT / "frontend"), help="frontend directory")
    p.add_argument("--allow-non-local", action="store_true",
                   help="allow binding to a non-loopback address (NOT recommended)")
    p.add_argument("--no-buttons", action="store_true", help="disable headset button observation (evdev)")
    p.add_argument("--capture-file", default=os.environ.get("NECKLACE_CAPTURE_FILE"),
                   help="btsnoop file written by 'sudo btmon -w FILE' to follow passively "
                        "(default ~/.cache/necklace-controller/live.btsnoop)")
    p.add_argument("--allow-rfcomm-probe", action="store_true",
                   default=os.environ.get("NECKLACE_ALLOW_RFCOMM_PROBE", "") in ("1", "true", "yes"),
                   help="enable read-only exploration of the JieLi RFCOMM channel 10 "
                        "(connect + read only; never writes, authenticates, or sends commands)")
    p.add_argument("--log-level", default=os.environ.get("NECKLACE_LOG_LEVEL", "INFO"))
    p.add_argument("--log-file", default=os.environ.get("NECKLACE_LOG_FILE"))
    p.add_argument("--version", action="version", version=AGENT_VERSION)
    return p.parse_args(argv)


def setup_logging(level: str, log_file: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.handlers.RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3))
    logging.basicConfig(level=level.upper(), handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_level, args.log_file)
    log = logging.getLogger("necklace")
    try:
        address = dev.normalize_address(args.device)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    extra_hosts: tuple[str, ...] = ()
    if not _is_loopback(args.host):
        if not args.allow_non_local:
            log.error("refusing to bind to non-loopback address %s (use --allow-non-local to override)", args.host)
            return 2
        log.warning("binding to %s: the Bluetooth control API is reachable from the network!", args.host)
        extra_hosts = (args.host,)
    frontend = Path(args.frontend).resolve()
    if not (frontend / "index.html").is_file():
        log.error("frontend not found at %s", frontend)
        return 2
    controller = Controller(address=address, adapter=args.adapter, bind=f"{args.host}:{args.port}",
                            enable_buttons=not args.no_buttons, capture_path=args.capture_file,
                            allow_rfcomm_probe=args.allow_rfcomm_probe)
    if args.allow_rfcomm_probe:
        log.warning("RFCOMM exploration ENABLED for %s channel 10 (read-only: connect + read, no writes)", address)
    app = create_app(controller, port=args.port, frontend_dir=frontend, extra_hosts=extra_hosts)
    log.info("necklace agent %s for %s on http://%s:%d/", AGENT_VERSION, address, args.host, args.port)
    web.run_app(app, host=args.host, port=args.port, print=None, access_log=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
