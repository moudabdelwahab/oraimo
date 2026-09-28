"""Error catalog. User-facing messages are Arabic; details stay in agent logs."""

from __future__ import annotations

MESSAGES: dict[str, str] = {
    "dbus_unavailable": "تعذر الاتصال بناقل النظام D-Bus",
    "bluez_unavailable": "تعذر الوصول إلى خدمة Bluetooth على النظام",
    "permission_denied": "تم رفض الإذن بالوصول إلى Bluetooth. راجع صلاحيات المستخدم",
    "adapter_missing": "لم يتم العثور على محول Bluetooth",
    "adapter_off": "Bluetooth متوقف على هذا الجهاز",
    "device_not_found": "السماعة غير مقترنة بهذا الجهاز",
    "device_disconnected": "السماعة غير متصلة",
    "device_unavailable": "السماعة غير متاحة. تأكد من تشغيلها وقربها من الجهاز",
    "connect_in_progress": "جارٍ الاتصال بالسماعة بالفعل",
    "connect_failed": "فشل الاتصال بالسماعة",
    "battery_unavailable": "قراءة البطارية غير متاحة حاليًا",
    "volume_unavailable": "التحكم بمستوى الصوت غير متاح حاليًا",
    "unsupported": "هذه الوظيفة غير متاحة حاليًا",
    "no_media_player": "لا يوجد مشغل وسائط يدعم MPRIS على هذا الجهاز",
    "session_bus_unavailable": "تعذر الوصول إلى ناقل جلسة المستخدم (MPRIS)",
    "media_command_failed": "تعذر تنفيذ أمر التشغيل",
    "player_not_found": "مشغل الوسائط المحدد غير موجود",
    "action_not_allowed": "هذا الإجراء غير مسموح به",
    "bad_request": "طلب غير صالح",
    "origin_denied": "مصدر الطلب غير مسموح به",
    "host_denied": "اسم المضيف غير مسموح به",
    "unsupported_media_type": "يجب إرسال الطلب بصيغة JSON",
    "timeout": "انتهت مهلة الاستجابة",
    "dbus_error": "حدث خطأ أثناء التواصل مع خدمة Bluetooth",
    "not_found": "المسار غير موجود",
    "internal": "حدث خطأ داخلي في الوكيل المحلي",
}

HTTP_STATUS: dict[str, int] = {
    "dbus_unavailable": 503,
    "bluez_unavailable": 503,
    "permission_denied": 403,
    "adapter_missing": 503,
    "adapter_off": 409,
    "device_not_found": 404,
    "device_disconnected": 409,
    "device_unavailable": 504,
    "connect_in_progress": 409,
    "connect_failed": 502,
    "battery_unavailable": 409,
    "volume_unavailable": 409,
    "unsupported": 501,
    "no_media_player": 409,
    "session_bus_unavailable": 503,
    "media_command_failed": 502,
    "player_not_found": 404,
    "action_not_allowed": 403,
    "bad_request": 400,
    "origin_denied": 403,
    "host_denied": 403,
    "unsupported_media_type": 415,
    "timeout": 504,
    "dbus_error": 502,
    "not_found": 404,
    "internal": 500,
}


class AgentError(Exception):
    """An expected failure with a stable code and an Arabic message."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(detail or code)
        self.code = code if code in MESSAGES else "internal"
        self.detail = detail

    @property
    def message(self) -> str:
        return MESSAGES[self.code]

    @property
    def status(self) -> int:
        return HTTP_STATUS.get(self.code, 500)

    def to_json(self) -> dict:
        return {"ok": False, "error": {"code": self.code, "message": self.message}}


class DBusCallError(Exception):
    """A D-Bus method call returned an error reply."""

    def __init__(self, name: str, text: str = ""):
        super().__init__(f"{name}: {text}")
        self.name = name
        self.text = text


_ACCESS = {
    "org.freedesktop.DBus.Error.AccessDenied",
    "org.freedesktop.DBus.Error.AuthFailed",
    "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired",
    "org.bluez.Error.NotAuthorized",
    "org.bluez.Error.NotPermitted",
    "org.bluez.Error.AuthenticationRejected",
    "org.bluez.Error.AuthenticationFailed",
}
_NO_SERVICE = {
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
    "org.freedesktop.DBus.Error.NoReply",
    "org.freedesktop.DBus.Error.Disconnected",
}


def map_dbus_error(err: DBusCallError, *, action: str = "") -> AgentError:
    """Translate a D-Bus error reply into a user-facing AgentError."""
    name, text = err.name, (err.text or "").lower()
    if name in _ACCESS:
        return AgentError("permission_denied", str(err))
    if name in _NO_SERVICE:
        return AgentError("session_bus_unavailable" if action == "media" else "bluez_unavailable", str(err))
    if name == "org.freedesktop.DBus.Error.UnknownObject":
        return AgentError("device_not_found" if action == "connect" else "unsupported", str(err))
    if name in ("org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownProperty",
                "org.freedesktop.DBus.Error.PropertyReadOnly", "org.bluez.Error.NotSupported",
                "org.bluez.Error.NotAvailable"):
        return AgentError("unsupported", str(err))
    if name == "org.bluez.Error.NotReady":
        return AgentError("adapter_off", str(err))
    if name == "org.bluez.Error.InProgress":
        return AgentError("connect_in_progress", str(err))
    if name == "org.bluez.Error.InvalidArguments":
        return AgentError("bad_request", str(err))
    if name == "org.freedesktop.DBus.Error.Timeout" or "timeout" in text or "timed out" in text:
        return AgentError("timeout" if action != "connect" else "device_unavailable", str(err))
    if action == "connect":
        if any(s in text for s in ("page-timeout", "host is down", "no route", "not available", "br-connection")):
            return AgentError("device_unavailable", str(err))
        return AgentError("connect_failed", str(err))
    if action == "media":
        return AgentError("media_command_failed", str(err))
    return AgentError("dbus_error", str(err))
