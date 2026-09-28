"""Local HTTP + WebSocket API.

Security model (local controller):
* binds to loopback by default (enforced in main.py)
* Host header must be a loopback name for the bound port (DNS-rebinding guard)
* Origin, when present, must be this same local origin (CSRF / cross-site WS guard)
* state-changing requests must be JSON (forces a CORS preflight that is never granted)
* only whitelisted actions exist; there is no raw Bluetooth route
* errors return a stable code + Arabic message; details go to the agent log only
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from aiohttp import WSMsgType, web

from .controller import AGENT_VERSION, Controller
from .errors import AgentError

log = logging.getLogger("necklace.api")

CONTROLLER_KEY = web.AppKey("controller", Controller)
CONFIG_KEY = web.AppKey("config", dict)
SOCKETS_KEY = web.AppKey("sockets", set)
MAX_WS_CLIENTS = 16
MAX_BODY = 4096
MAX_CAPTURE = 64 << 20  # uploaded btsnoop files (analysis only, never sent anywhere)
UPLOAD_PATHS = {"/api/capture/analyze"}

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")


def allowed_hosts(port: int, extra: tuple[str, ...] = ()) -> set[str]:
    hosts = {f"{h}:{port}" for h in LOOPBACK_HOSTS + tuple(extra)}
    if port == 80:
        hosts |= set(LOOPBACK_HOSTS + tuple(extra))
    return hosts


def error_response(err: AgentError) -> web.Response:
    return web.json_response(err.to_json(), status=err.status)


@web.middleware
async def security_middleware(request: web.Request, handler):
    cfg = request.app[CONFIG_KEY]
    host = (request.headers.get("Host") or "").lower()
    if host not in cfg["allowed_hosts"]:
        log.warning("rejected Host header %r from %s", host, request.remote)
        return error_response(AgentError("host_denied", host))
    origin = request.headers.get("Origin")
    state_changing = request.method not in ("GET", "HEAD", "OPTIONS")
    if origin is not None and origin.lower() not in cfg["allowed_origins"]:
        if state_changing or request.path == "/ws" or request.path.startswith("/api/"):
            log.warning("rejected Origin %r for %s %s", origin, request.method, request.path)
            return error_response(AgentError("origin_denied", origin))
    if request.method == "OPTIONS":
        # No CORS is ever granted: answer preflights without Access-Control-* headers.
        return web.Response(status=204)
    if state_changing and request.path.startswith("/api/"):
        upload = request.path in UPLOAD_PATHS
        expected = "application/octet-stream" if upload else "application/json"
        if request.content_type != expected:
            return error_response(AgentError("unsupported_media_type"))
        limit = MAX_CAPTURE if upload else MAX_BODY
        if request.content_length is not None and request.content_length > limit:
            return error_response(AgentError("bad_request", "body too large"))
    try:
        resp = await handler(request)
    except AgentError as err:
        if err.code not in ("device_disconnected", "no_media_player"):
            log.info("%s %s -> %s (%s)", request.method, request.path, err.code, err.detail)
        resp = error_response(err)
    except web.HTTPNotFound:
        resp = error_response(AgentError("not_found"))
    except web.HTTPMethodNotAllowed:
        resp = error_response(AgentError("action_not_allowed"))
    except web.HTTPException:
        raise
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("unhandled error for %s %s", request.method, request.path)
        resp = error_response(AgentError("internal"))
    _security_headers(resp, cfg)
    return resp


def _security_headers(resp: web.StreamResponse, cfg: dict) -> None:
    if resp.prepared:
        return
    # IPv6 literals are not valid CSP host-sources; 'self' already covers same-origin ws: in CSP3.
    ws = " ".join(f"ws://{h}" for h in sorted(cfg["allowed_hosts"]) if not h.startswith("["))
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
        f"img-src 'self' data:; connect-src 'self' {ws}; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'; object-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), serial=(), hid=()"
    if resp.content_type in ("application/json", "text/html"):
        resp.headers["Cache-Control"] = "no-store"


async def _json_body(request: web.Request) -> dict:
    if not request.can_read_body:
        return {}
    raw = await request.content.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise AgentError("bad_request", "body too large")
    if not raw.strip():
        return {}
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise AgentError("bad_request", "invalid JSON") from None
    if not isinstance(body, dict):
        raise AgentError("bad_request", "JSON object expected")
    return body


def _ctl(request: web.Request) -> Controller:
    return request.app[CONTROLLER_KEY]


# ---------------------------------------------------------------------------- GET
async def get_status(request):
    return web.json_response({"ok": True, "data": await _ctl(request).snapshot()})


async def get_device(request):
    from . import device as dev
    s = await _ctl(request).snapshot()
    p = dev.PROFILE
    reference = {
        "name": p.name, "address": p.address, "oui_vendor": p.oui_vendor, "chipset_vendor": p.chipset_vendor,
        "vendor_id": f"0x{p.vendor_id:04X}", "vendor_id_source": "Bluetooth SIG",
        "product_id": f"0x{p.product_id:04X}", "version": f"0x{p.version:04X}",
        "connection_type": p.connection_type, "avrcp_version": p.avrcp_version, "avctp_version": p.avctp_version,
        "avrcp_ct_features": p.avrcp_ct_features, "avrcp_tg_features": p.avrcp_tg_features,
        "headset_tg_events": list(p.headset_tg_events), "verified_passthrough": list(p.verified_passthrough),
        "profiles": list(p.profiles), "sdp_service_names": list(p.sdp_service_names),
        "source": "necklace_report.md (تحليل الالتقاط)",
    }
    return web.json_response({"ok": True, "data": {"reference": reference, "live": s["device"],
                                                   "connection": s["connection"]}})


async def get_battery(request):
    return web.json_response({"ok": True, "data": (await _ctl(request).snapshot())["battery"]})


async def get_volume(request):
    return web.json_response({"ok": True, "data": (await _ctl(request).snapshot())["volume"]})


async def get_media(request):
    return web.json_response({"ok": True, "data": (await _ctl(request).snapshot())["media"]})


async def get_diagnostics(request):
    fresh = request.query.get("refresh") in ("1", "true")
    s = await _ctl(request).snapshot(fresh=fresh)
    return web.json_response({"ok": True, "data": {
        "capabilities": s["capabilities"], "bluetooth": s["bluetooth"], "agent": s["agent"],
        "buttons": s["buttons"], "verified": s["verified"], "updated_at": s["updated_at"]}})


async def get_events(request):
    try:
        limit = max(1, min(500, int(request.query.get("limit", "200"))))
    except ValueError:
        raise AgentError("bad_request", "limit") from None
    return web.json_response({"ok": True, "data": _ctl(request).log.entries(limit)})


async def get_health(request):
    return web.json_response({"ok": True})


# ---------------------------------------------------------------------------- actions
async def _action(request, name, **params):
    result = await _ctl(request).perform(name, **params)
    return web.json_response({"ok": True, "data": result})


async def post_play(request):
    await _json_body(request)
    return await _action(request, "play")


async def post_pause(request):
    await _json_body(request)
    return await _action(request, "pause")


async def post_volume(request):
    body = await _json_body(request)
    return await _action(request, "set_volume", percent=body.get("percent"))


async def post_volume_up(request):
    await _json_body(request)
    return await _action(request, "volume_up")


async def post_volume_down(request):
    await _json_body(request)
    return await _action(request, "volume_down")


async def post_reconnect(request):
    await _json_body(request)
    return await _action(request, "reconnect")


async def post_player(request):
    body = await _json_body(request)
    return await _action(request, "select_player", bus_name=body.get("bus_name"))


async def post_next(request):
    await _json_body(request)
    return await _action(request, "next")


async def post_previous(request):
    await _json_body(request)
    return await _action(request, "previous")


# ---------------------------------------------------------------------------- discovery (read-only / passive)
async def get_discovery(request):
    ctl = _ctl(request)
    return web.json_response({"ok": True, "data": ctl.discovery.view(await ctl.snapshot())})


async def get_discovery_log(request):
    try:
        limit = max(1, min(2000, int(request.query.get("limit", "500"))))
    except ValueError:
        raise AgentError("bad_request", "limit") from None
    return web.json_response({"ok": True, "data": _ctl(request).discovery.log_entries(limit)})


async def post_safe_scan(request):
    await _json_body(request)
    return await _action(request, "safe_scan")


async def post_discovery_log_clear(request):
    await _json_body(request)
    return await _action(request, "clear_discovery_log")


async def post_research_start(request):
    await _json_body(request)
    return await _action(request, "research_start")


async def post_research_stop(request):
    await _json_body(request)
    return await _action(request, "research_stop")


async def post_research_headset(request):
    body = await _json_body(request)
    return await _action(request, "research_headset", trial_action=body.get("action"))


async def post_research_host(request):
    body = await _json_body(request)
    return await _action(request, "research_host", trial_action=body.get("action"))


async def post_rfcomm_probe(request):
    """Read-only RFCOMM exploration: connect, read for a window, close. Never writes."""
    body = await _json_body(request)
    return await _action(request, "rfcomm_probe", read_seconds=body.get("read_seconds", 5))


async def post_capture_analyze(request):
    data = await request.content.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE:
        raise AgentError("bad_request", "capture too large")
    return await _action(request, "analyze_capture", data=data)


async def post_clear_events(request):
    await _json_body(request)
    return await _action(request, "clear_log")


# ---------------------------------------------------------------------------- websocket
async def websocket(request: web.Request):
    sockets = request.app[SOCKETS_KEY]
    if len(sockets) >= MAX_WS_CLIENTS:
        raise AgentError("action_not_allowed", "too many websocket clients")
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=1024)
    await ws.prepare(request)
    ctl = _ctl(request)
    lock = asyncio.Lock()

    async def send(msg: dict):
        if ws.closed:
            raise ConnectionResetError
        async with lock:
            await ws.send_json(msg)

    sockets.add(ws)
    try:
        await send({"type": "hello", "version": AGENT_VERSION})
        await send({"type": "status", "data": await ctl.snapshot()})
        await send({"type": "log_history", "entries": ctl.log.entries(200)})
        ctl.subscribe(send)
        async for msg in ws:
            # The socket is receive-only for the browser; commands go through the
            # whitelisted HTTP routes. Only a ping is understood.
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except ValueError:
                    continue
                if isinstance(data, dict) and data.get("type") == "ping":
                    await send({"type": "pong"})
            elif msg.type == WSMsgType.ERROR:
                break
    finally:
        ctl.unsubscribe(send)
        sockets.discard(ws)
    return ws


# ---------------------------------------------------------------------------- static
def _static_handler(frontend: Path):
    files = {
        "/": ("index.html", "text/html"),
        "/index.html": ("index.html", "text/html"),
        "/styles.css": ("styles.css", "text/css"),
        "/app.js": ("app.js", "text/javascript"),
    }

    async def handler(request: web.Request):
        entry = files.get(request.path)
        if entry is None:
            raise web.HTTPNotFound()
        path = frontend / entry[0]
        if not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(path, headers={"Content-Type": f"{entry[1]}; charset=utf-8"})

    return handler


def _assets_handler(frontend: Path):
    root = (frontend / "assets").resolve()
    types = {".woff2": "font/woff2", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8",
             ".png": "image/png"}

    async def handler(request: web.Request):
        rel = request.match_info["path"]
        target = (root / rel).resolve()
        if root not in target.parents or not target.is_file() or target.suffix not in types:
            raise web.HTTPNotFound()
        return web.FileResponse(target, headers={"Content-Type": types[target.suffix]})

    return handler


async def _on_shutdown(app: web.Application):
    for ws in list(app[SOCKETS_KEY]):
        await ws.close(code=1001, message=b"shutdown")


def create_app(controller: Controller, *, port: int, frontend_dir: Path,
               extra_hosts: tuple[str, ...] = ()) -> web.Application:
    app = web.Application(middlewares=[security_middleware], client_max_size=MAX_CAPTURE)
    hosts = allowed_hosts(port, extra_hosts)
    app[CONFIG_KEY] = {"allowed_hosts": hosts, "allowed_origins": {f"http://{h}" for h in hosts}}
    app[CONTROLLER_KEY] = controller
    app[SOCKETS_KEY] = set()

    r = app.router
    r.add_get("/api/health", get_health)
    r.add_get("/api/status", get_status)
    r.add_get("/api/device", get_device)
    r.add_get("/api/battery", get_battery)
    r.add_get("/api/volume", get_volume)
    r.add_get("/api/media", get_media)
    r.add_get("/api/diagnostics", get_diagnostics)
    r.add_get("/api/events", get_events)
    r.add_post("/api/media/play", post_play)
    r.add_post("/api/media/pause", post_pause)
    r.add_post("/api/media/player", post_player)
    r.add_post("/api/volume", post_volume)
    r.add_post("/api/volume/up", post_volume_up)
    r.add_post("/api/volume/down", post_volume_down)
    r.add_post("/api/reconnect", post_reconnect)
    r.add_post("/api/events/clear", post_clear_events)
    r.add_post("/api/media/next", post_next)
    r.add_post("/api/media/previous", post_previous)
    r.add_get("/api/discovery", get_discovery)
    r.add_get("/api/discovery/log", get_discovery_log)
    r.add_post("/api/discovery/scan", post_safe_scan)
    r.add_post("/api/discovery/log/clear", post_discovery_log_clear)
    r.add_post("/api/research/start", post_research_start)
    r.add_post("/api/research/stop", post_research_stop)
    r.add_post("/api/research/headset", post_research_headset)
    r.add_post("/api/research/host", post_research_host)
    r.add_post("/api/capture/analyze", post_capture_analyze)
    r.add_post("/api/explore/rfcomm", post_rfcomm_probe)
    r.add_get("/ws", websocket)
    static = _static_handler(frontend_dir)
    for p in ("/", "/index.html", "/styles.css", "/app.js"):
        r.add_get(p, static)
    r.add_get("/assets/{path:.+}", _assets_handler(frontend_dir))

    async def on_startup(app):
        await controller.start()

    async def on_cleanup(app):
        await controller.stop()

    app.on_startup.append(on_startup)
    app.on_shutdown.append(_on_shutdown)
    app.on_cleanup.append(on_cleanup)
    return app
