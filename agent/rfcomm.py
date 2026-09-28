"""Read-only RFCOMM connection explorer (Phase 3, opt-in).

This is the ONLY module in the agent allowed to touch a Bluetooth socket, and
it is deliberately restricted to *connecting and reading*:

* It opens an RFCOMM connection to a channel on the paired headset.
* It reads whatever the peer sends for a short window, then closes.
* It NEVER sends a byte: there is no ``send``/``sendall``/``write`` call, no
  RCSP command, and no authentication handshake anywhere in this file. The
  JieLi RcspAuth flow is host-initiated (see ``docs/jieli-rcsp-apk.md``), so a
  pure read after connect typically observes nothing and the peer closes the
  channel after its auth timeout. That empty result is itself the finding: it
  confirms the transport and that the channel is auth-gated.

The whole feature is off unless the operator enables it explicitly
(``--allow-rfcomm-probe`` / ``NECKLACE_ALLOW_RFCOMM_PROBE=1``). When disabled,
``probe()`` returns a structured "disabled" result and opens no socket.

Opening RFCOMM is an ACTIVE connection (L2CAP + RFCOMM SABM), not passive
sniffing. It is safe against the operator's own device, but a new DLC while
A2DP/AVRCP is active can briefly disturb the current audio link; run it while
the headset is idle.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
import time
from typing import Callable

log = logging.getLogger("necklace.rfcomm")

# AF_BLUETOOTH / BTPROTO_RFCOMM are Linux-only and may be missing from the
# stdlib socket module on other platforms.
_AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", None)
_BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", None)

DEFAULT_CHANNEL = 10          # JieLi JL_SPP, from the SDP capture
MAX_READ_BYTES = 4096         # cap on how much we buffer from the peer
CONNECT_TIMEOUT = 10.0
READ_SECONDS_DEFAULT = 5.0
READ_SECONDS_MAX = 20.0


def platform_supported() -> bool:
    return _AF_BLUETOOTH is not None and _BTPROTO_RFCOMM is not None


class RfcommExplorer:
    """Connect to an RFCOMM channel, read passively for a window, then close."""

    def __init__(self, address: str, channel: int = DEFAULT_CHANNEL, *,
                 enabled: bool = False,
                 open_socket: Callable[[], socket.socket] | None = None):
        self.address = address
        self.channel = int(channel)
        self.enabled = bool(enabled)
        # Injectable for tests; production path builds a real RFCOMM socket.
        self._open_socket = open_socket or self._open_rfcomm_socket

    # -- socket factory (production) ---------------------------------------
    def _open_rfcomm_socket(self) -> socket.socket:
        if not platform_supported():
            raise OSError("AF_BLUETOOTH/BTPROTO_RFCOMM not available on this platform")
        return socket.socket(_AF_BLUETOOTH, socket.SOCK_STREAM, _BTPROTO_RFCOMM)

    # -- public API --------------------------------------------------------
    async def probe(self, read_seconds: float = READ_SECONDS_DEFAULT) -> dict:
        """Open the channel, read for a window, close. Returns a structured report."""
        base = {
            "address": self.address, "channel": self.channel,
            "transport": "RFCOMM (Bluetooth Classic BR/EDR)",
        }
        if not self.enabled:
            return {**base, "ok": False, "state": "disabled",
                    "note": "استكشاف RFCOMM مُطفأ. فعّله بـ --allow-rfcomm-probe "
                            "أو NECKLACE_ALLOW_RFCOMM_PROBE=1."}
        if not platform_supported():
            return {**base, "ok": False, "state": "unsupported",
                    "note": "نظام التشغيل لا يوفّر مقابس RFCOMM (AF_BLUETOOTH). "
                            "شغّل الوكيل على Linux مع BlueZ."}
        window = max(0.5, min(READ_SECONDS_MAX, float(read_seconds)))
        return await asyncio.to_thread(self._probe_blocking, window)

    # -- blocking worker (runs in a thread) --------------------------------
    def _probe_blocking(self, read_seconds: float) -> dict:
        report: dict = {
            "address": self.address, "channel": self.channel,
            "transport": "RFCOMM (Bluetooth Classic BR/EDR)",
            "ok": False, "state": "error", "connected": False,
            "bytes_read": 0, "data_hex": "", "peer_closed": False,
            "read_seconds": read_seconds, "note": "",
        }
        sock: socket.socket | None = None
        try:
            sock = self._open_socket()
            sock.settimeout(CONNECT_TIMEOUT)
            t0 = time.monotonic()
            sock.connect((self.address, self.channel))
            report["connected"] = True
            report["connect_ms"] = round((time.monotonic() - t0) * 1000)
            try:
                report["peer"] = _fmt_addr(sock.getpeername())
            except OSError:
                pass
            buf = bytearray()
            deadline = time.monotonic() + read_seconds
            while time.monotonic() < deadline and len(buf) < MAX_READ_BYTES:
                remaining = deadline - time.monotonic()
                sock.settimeout(max(0.1, min(1.0, remaining)))
                try:
                    chunk = sock.recv(min(1024, MAX_READ_BYTES - len(buf)))
                except socket.timeout:
                    continue
                except OSError as exc:
                    report["note"] = f"انقطاع أثناء القراءة: {exc}"
                    break
                if chunk == b"":
                    report["peer_closed"] = True
                    break
                buf.extend(chunk)
            report["bytes_read"] = len(buf)
            report["data_hex"] = buf.hex(" ")
            report["ok"] = True
            report["state"] = "connected"
            report["note"] = report["note"] or _interpret(report)
        except OSError as exc:
            report["errno"] = getattr(exc, "errno", None)
            if isinstance(exc, TimeoutError) or report["errno"] == errno.ETIMEDOUT:
                report["state"] = "timeout"
                report["note"] = "انتهت مهلة الاتصال — الجهاز لم يستجب لطلب فتح القناة."
            else:
                report["state"] = "error"
                report["note"] = _os_error_note(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return report


def _fmt_addr(peer) -> str:
    if isinstance(peer, (tuple, list)) and peer:
        return str(peer[0])
    return str(peer)


def _interpret(report: dict) -> str:
    if report["bytes_read"] == 0 and report["peer_closed"]:
        return ("اتصل بنجاح، لكن الجهاز أغلق القناة دون إرسال بيانات — يطابق سلوك "
                "المصادقة المبدوءة من المضيف في RcspAuth (المصافحة لا تبدأ من الجهاز).")
    if report["bytes_read"] == 0:
        return ("اتصل بنجاح، ولم يرسل الجهاز أي بايت خلال النافذة — متوقع، لأن "
                "المصافحة تبدأ من المضيف. القناة مفتوحة والنقل مؤكد.")
    return (f"اتصل بنجاح، واستقبل {report['bytes_read']} بايت غير مطلوبة من الجهاز "
            "قبل أي إرسال. سُجّلت كـ hex للتحليل فقط، دون أي رد.")


def _os_error_note(exc: OSError) -> str:
    code = getattr(exc, "errno", None)
    if code in (errno.ECONNREFUSED,):
        return "الجهاز رفض الاتصال على هذه القناة (قد تكون مشغولة أو تتطلب اقترانًا)."
    if code in (errno.EHOSTDOWN, errno.EHOSTUNREACH):
        return "تعذّر الوصول إلى الجهاز — تأكد أنه مقترن ومتصل وقريب."
    if code in (errno.EACCES, errno.EPERM):
        return "صلاحيات غير كافية لفتح مقبس RFCOMM."
    return f"فشل الاتصال: {exc}"
