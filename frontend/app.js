// متحكم Necklace — frontend.
// The UI never invents state: everything shown comes from the local agent's
// snapshots (/api/status and the /ws stream). Buttons only call whitelisted
// agent routes; results arrive back as snapshots.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  snap: null,
  log: [],
  agent: "connecting", // connecting | online | offline
  ws: null,
  wsRetry: 0,
  volumeTouchedAt: 0,
  volumeTimer: null,
  route: "dashboard",
};

// ------------------------------------------------------------------ helpers
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("data-") || k.startsWith("aria-") || k === "role" || k === "title" || k === "dir" || k === "datetime") el.setAttribute(k, v);
    else el[k] = v;
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function icon(name, cls = "") {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", `icon ${cls}`.trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

const timeFmt = new Intl.DateTimeFormat("ar-u-nu-latn", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dateTimeFmt = new Intl.DateTimeFormat("ar-u-nu-latn", { dateStyle: "medium", timeStyle: "medium", hour12: false });
const fmtTime = (iso) => { try { return timeFmt.format(new Date(iso)); } catch { return "—"; } };
const hex4 = (n) => (n == null ? "—" : "0x" + n.toString(16).toUpperCase().padStart(4, "0"));

function setText(sel, text) {
  const el = typeof sel === "string" ? $(sel) : sel;
  if (el && el.textContent !== text) el.textContent = text;
}

function storageGet(key, fallback) {
  try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
}
function storageSet(key, value) {
  try { localStorage.setItem(key, value); } catch { /* private mode etc. */ }
}

// ------------------------------------------------------------------ labels
const CONN_LABEL = { connected: "متصل", connecting: "جارٍ الاتصال", disconnected: "غير متصل", failed: "فشل الاتصال", unknown: "غير معروف" };
const PLAY_LABEL = { playing: "يعمل الآن", paused: "متوقف مؤقتًا", stopped: "متوقف", unknown: "غير معروف" };
const BAT_LABEL = { full: "ممتلئة", good: "جيدة", low: "منخفضة", critical: "حرجة", unknown: "غير معروفة" };
const STREAM_LABEL = { active: "البث إلى السماعة: نشط", idle: "البث إلى السماعة: خامل", pending: "البث إلى السماعة: جارٍ التحضير", none: "لا توجد قناة صوت A2DP" };
const STATUS_LABEL = { available: "متاح", unavailable: "غير متاح", unknown: "غير معروف" };
const STATUS_ICON = { available: "check", unavailable: "x", unknown: "help" };
const EVIDENCE_LABEL = { capture: "مؤكد في الالتقاط", sdp: "معلن في SDP", runtime: "من BlueZ مباشرة" };
const REASON_TEXT = {
  dbus_unavailable: "تعذر الاتصال بناقل النظام D-Bus",
  bluez_unavailable: "تعذر الوصول إلى خدمة Bluetooth على النظام",
  permission_denied: "تم رفض الإذن بالوصول إلى Bluetooth",
  session_bus_unavailable: "تعذر الوصول إلى ناقل جلسة المستخدم (MPRIS)",
  no_media_player: "لا يوجد مشغل وسائط يدعم MPRIS على هذا الجهاز. افتح مشغلًا مثل المتصفح أو Spotify أو VLC",
  device_disconnected: "السماعة غير متصلة",
  no_transport: "لا توجد قناة صوت A2DP مهيأة حاليًا",
  no_absolute_volume: "BlueZ لا يعرض مستوى الصوت المطلق لهذه القناة",
};
const LOG_TYPE_LABEL = {
  agent: "الوكيل", bluez_changed: "النظام", adapter_changed: "المحول", device_changed: "الجهاز",
  connection_changed: "الاتصال", battery_changed: "البطارية", volume_changed: "مستوى الصوت",
  playback_changed: "التشغيل", player_changed: "المشغل", stream_changed: "البث", headset_button: "زر السماعة",
  action: "إجراء", verified: "تحقق", log_cleared: "السجل", error: "خطأ",
};
const LOG_FILTERS = {
  connection: ["connection_changed", "device_changed", "adapter_changed"],
  battery: ["battery_changed"],
  volume: ["volume_changed"],
  playback: ["playback_changed", "player_changed", "stream_changed"],
  buttons: ["headset_button"],
  system: ["agent", "bluez_changed", "adapter_changed", "verified", "log_cleared", "action"],
};

// ------------------------------------------------------------------ API
class ApiError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

async function api(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: method === "GET" ? { Accept: "application/json" } : { "Content-Type": "application/json", Accept: "application/json" },
      body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch {
    setAgent("offline");
    throw new ApiError("agent_offline", "تعذر الوصول إلى الوكيل المحلي");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok || !data || data.ok === false) {
    const err = data?.error;
    throw new ApiError(err?.code || "internal", err?.message || "حدث خطأ غير متوقع");
  }
  return data.data;
}

async function runAction(button, fn, { success } = {}) {
  if (button) { button.setAttribute("aria-busy", "true"); button.disabled = true; }
  try {
    const result = await fn();
    if (success) toast(typeof success === "function" ? success(result) : success, "ok");
    return result;
  } catch (e) {
    toast(e.message || "حدث خطأ غير متوقع", "bad");
    return null;
  } finally {
    if (button) { button.removeAttribute("aria-busy"); }
    render();
  }
}

// ------------------------------------------------------------------ WebSocket
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  let ws;
  try { ws = new WebSocket(`${proto}://${location.host}/ws`); } catch { scheduleWs(); return; }
  state.ws = ws;
  ws.addEventListener("open", () => { state.wsRetry = 0; setAgent("online"); });
  ws.addEventListener("message", (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    handleMessage(msg);
  });
  ws.addEventListener("close", () => { if (state.ws === ws) { state.ws = null; setAgent("offline"); scheduleWs(); } });
  ws.addEventListener("error", () => ws.close());
}

function scheduleWs() {
  const delay = Math.min(10000, 800 * 2 ** state.wsRetry++);
  setTimeout(connectWs, delay);
}

function handleMessage(msg) {
  if (handleDiscoveryMessage(msg)) return;
  switch (msg.type) {
    case "status":
      state.snap = msg.data;
      render();
      break;
    case "log_history":
      state.log = msg.entries || [];
      renderLog();
      break;
    case "log": {
      // Coalesced entries (e.g. volume while dragging) keep their id: replace in place.
      const i = state.log.findIndex((e) => e.id === msg.entry.id);
      if (i >= 0) state.log[i] = msg.entry; else state.log.push(msg.entry);
      if (state.log.length > 500) state.log.shift();
      renderLog(msg.entry.id);
      break;
    }
    case "log_cleared":
      state.log = [msg.entry];
      renderLog();
      break;
    case "headset_button":
      if (msg.pressed) {
        const hero = $("#hero");
        hero.classList.remove("pulse-button");
        void hero.offsetWidth;
        hero.classList.add("pulse-button");
        toast(`ضغطة من السماعة: ${msg.label}`, "info", "necklace");
      }
      break;
    case "connection_changed":
      if (msg.state === "connected") toast("تم الاتصال بالسماعة", "ok", "check");
      else if (msg.state === "failed") toast("فشل الاتصال بالسماعة", "bad", "alert");
      else if (msg.state === "disconnected") toast("السماعة غير متصلة", "warn", "alert");
      break;
    default:
      break;
  }
}

function setAgent(s) {
  if (state.agent === s) return;
  state.agent = s;
  render();
}

// ------------------------------------------------------------------ toasts & banners
function toast(text, kind = "info", iconName) {
  const box = $("#toasts");
  const name = iconName || { ok: "check", bad: "alert", warn: "alert", info: "info" }[kind];
  const el = h("div", { class: `toast ${kind}`, role: kind === "bad" ? "alert" : "status" }, icon(name), h("span", { text }));
  box.append(el);
  while (box.children.length > 4) box.firstElementChild.remove();
  setTimeout(() => { el.classList.add("leaving"); setTimeout(() => el.remove(), 300); }, kind === "bad" ? 6000 : 3500);
}

function renderBanners() {
  const box = $("#banners");
  const items = [];
  const s = state.snap;
  if (state.agent === "offline") {
    items.push(["bad", "alert", "تعذر الوصول إلى الوكيل المحلي", "تأكد من تشغيل الوكيل (python -m agent) ثم أعد تحميل الصفحة. ستُعاد المحاولة تلقائيًا."]);
  } else if (s) {
    const bt = s.bluetooth;
    if (bt.service !== "available") {
      items.push(["bad", "alert", REASON_TEXT[bt.error] || "تعذر الوصول إلى خدمة Bluetooth على النظام",
        bt.error === "permission_denied" ? "راجع صلاحيات المستخدم لـ BlueZ على D-Bus (راجع README)." : "تأكد من تشغيل الخدمة: systemctl status bluetooth"]);
    } else if (!bt.adapter.present) {
      items.push(["bad", "alert", "لم يتم العثور على محول Bluetooth", "وصّل محولًا أو فعّله من إعدادات النظام."]);
    } else if (!bt.adapter.powered) {
      items.push(["warn", "bluetooth", "Bluetooth متوقف على هذا الجهاز",
        bt.adapter.power_state === "off-blocked" ? "المحول محظور بواسطة rfkill: rfkill unblock bluetooth" : "شغّله من إعدادات النظام أو: bluetoothctl power on"]);
    } else if (!s.device.known) {
      items.push(["warn", "necklace", "السماعة غير مقترنة بهذا الجهاز", "اقترن بها أولًا عبر إعدادات Bluetooth أو bluetoothctl (راجع README)."]);
    }
  }
  const key = JSON.stringify(items);
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  box.replaceChildren(...items.map(([kind, ic, title, sub]) =>
    h("div", { class: `banner ${kind}`, role: kind === "bad" ? "alert" : "status" }, icon(ic), h("div", {}, title, h("small", { text: sub })))));
}

// ------------------------------------------------------------------ render: agent & hero
function renderAgent() {
  const map = { online: "متصل", connecting: "جارٍ الاتصال…", offline: "غير متصل" };
  for (const el of [$("#agent-status"), $("#agent-chip")]) el.dataset.state = state.agent;
  setText("#agent-status-text", map[state.agent]);
  setText("#agent-chip-text", `الوكيل: ${map[state.agent]}`);
  $("#agent-chip").title = `الوكيل المحلي: ${map[state.agent]}`;
}

function canUseBluetooth(s) {
  return s && s.bluetooth.service === "available" && s.bluetooth.adapter.present && s.bluetooth.adapter.powered;
}

function renderHero() {
  const s = state.snap;
  const online = state.agent === "online" && s;
  const conn = online ? s.connection.state : "unknown";
  const connected = online && s.connection.connected;
  $("#hero").dataset.conn = conn;
  $("#conn-pill").dataset.state = conn;
  setText("#conn-label", CONN_LABEL[conn] || CONN_LABEL.unknown);

  if (s) {
    const d = s.device;
    setText("#dev-name", d.alias || d.name || "Oraimo Necklace Lite");
    setText("#dev-addr", d.address || d.target_address);
    setText("#conn-type", s.connection.type);
    const bt = s.bluetooth;
    setText("#bt-state", bt.service !== "available" ? "غير متاحة" : !bt.adapter.present ? "لا يوجد محول" : bt.adapter.powered ? "يعمل" : "متوقف");
    const t = $("#updated-at");
    t.setAttribute("datetime", s.updated_at);
    setText(t, fmtTime(s.updated_at));
  }

  // reconnect
  const rb = $("#btn-reconnect");
  const rhint = $("#reconnect-hint");
  let rReason = "";
  if (!online) rReason = "الوكيل المحلي غير متصل";
  else if (!canUseBluetooth(s)) rReason = "Bluetooth غير متاح على هذا الجهاز";
  else if (!s.device.known) rReason = "السماعة غير مقترنة بهذا الجهاز";
  else if (conn === "connecting") rReason = "جارٍ الاتصال…";
  if (rb.getAttribute("aria-busy") !== "true") rb.disabled = Boolean(rReason);
  setText("#btn-reconnect-label", connected ? "إعادة الاتصال" : "اتصال");
  setText(rhint, rReason && conn !== "connecting" ? rReason : (conn === "failed" && s?.connection.error ? "فشلت آخر محاولة. تأكد من تشغيل السماعة وقربها." : ""));

  renderMedia(online ? s : null);
  renderVolume(online ? s : null, connected);
  renderBattery(online ? s : null, connected);
}

function renderMedia(s) {
  const m = s?.media;
  const status = m?.status || "unknown";
  const ps = $("#play-state");
  ps.dataset.state = m?.available ? status : "unknown";
  setText(ps, m?.available ? PLAY_LABEL[status] : PLAY_LABEL.unknown);
  setText("#media-player", m?.player?.identity || "—");
  setText("#media-stream", STREAM_LABEL[m?.stream || "none"]);

  const play = $("#btn-play"), pause = $("#btn-pause");
  let reason = "";
  if (!s) reason = "الوكيل المحلي غير متصل";
  else if (!m.available) reason = REASON_TEXT[m.reason] || "مشغل الوسائط غير متاح";
  const busy = (b) => b.getAttribute("aria-busy") === "true";
  if (!busy(play)) play.disabled = Boolean(reason) || !m.player.can_play;
  if (!busy(pause)) pause.disabled = Boolean(reason) || !m.player.can_pause;
  play.classList.toggle("is-current", !reason && status === "playing");
  pause.classList.toggle("is-current", !reason && status === "paused");
  play.setAttribute("aria-pressed", String(!reason && status === "playing"));
  pause.setAttribute("aria-pressed", String(!reason && status === "paused"));
  const hint = $("#media-hint");
  hint.className = reason ? "hint warn" : "hint";
  setText(hint, reason || (s?.verified?.play_pause ? "" : "تتحكم الأزرار في مشغل الوسائط على هذا الجهاز، مثل زر السماعة تمامًا."));
}

function renderVolume(s, connected) {
  const v = s?.volume;
  const slider = $("#vol-slider");
  const tile = $(".tile-volume");
  const available = Boolean(v?.available);
  const dragging = Date.now() - state.volumeTouchedAt < 1500;
  if (!dragging) {
    tile.dataset.pending = "false";
    if (available) {
      slider.value = String(v.percent);
      setText("#vol-value", `${v.percent}%`);
    } else {
      setText("#vol-value", "—");
    }
    slider.style.setProperty("--pct", `${available ? v.percent : 0}%`);
    slider.setAttribute("aria-valuetext", available ? `${v.percent}%` : "غير متاح");
  }
  slider.disabled = !available;
  for (const id of ["#btn-vol-down", "#btn-vol-up"]) {
    const b = $(id);
    if (b.getAttribute("aria-busy") !== "true") b.disabled = !available;
  }
  $("#btn-vol-down").disabled ||= available && v.raw <= 0;
  $("#btn-vol-up").disabled ||= available && v.raw >= 127;
  const tag = $("#vol-verify");
  tag.hidden = !available;
  tag.className = v?.write_verified ? "verify-tag ok" : "verify-tag";
  tag.replaceChildren(icon(v?.write_verified ? "check" : "help"),
    v?.write_verified ? "التحكم متحقق منه" : "التحكم لم يُتحقق منه بعد");
  const hint = $("#vol-hint");
  hint.className = available ? "hint" : "hint warn";
  setText(hint, !s ? "الوكيل المحلي غير متصل" : available
    ? "مستوى الصوت المطلق (AVRCP) عبر BlueZ."
    : REASON_TEXT[v.reason] || (connected ? "مستوى الصوت غير متاح حاليًا" : "السماعة غير متصلة"));
}

function renderBattery(s, connected) {
  const b = s?.battery;
  const level = b?.available ? b.level : "unknown";
  const box = $("#battery");
  box.dataset.level = level;
  $("#bat-fill").setAttribute("width", String(b?.available ? Math.max(3, Math.round(52 * b.percentage / 100)) : 0));
  setText("#bat-value", b?.available ? `${b.percentage}%` : "—");
  setText("#bat-level", BAT_LABEL[level]);
  box.setAttribute("aria-label", b?.available ? `البطارية ${b.percentage}% — ${BAT_LABEL[level]}` : "البطارية غير معروفة");
  const hint = $("#bat-hint");
  setText(hint, !s ? "" : b?.available
    ? `القيمة كما يعرضها BlueZ${b.source ? ` (المصدر: ${b.source})` : ""}. السماعة تُبلغ عنها بدقة 10% عبر HFP.`
    : connected ? "BlueZ لا يعرض قراءة البطارية حاليًا (راجع README: PipeWire وBattery1)." : "السماعة غير متصلة");
}

// ------------------------------------------------------------------ render: side cards
const SUMMARY_IDS = ["connection", "avrcp", "volume_write", "battery", "play_pause", "headset_buttons", "hid"];

function badge(status, text) {
  return h("span", { class: `badge badge-${status}` }, icon(STATUS_ICON[status] || "help"), text || STATUS_LABEL[status]);
}

function renderSummary() {
  const s = state.snap;
  const ul = $("#cap-summary");
  if (!s || state.agent !== "online") {
    ul.replaceChildren(h("li", { class: "empty-inline", text: "بانتظار بيانات الوكيل…" }));
    return;
  }
  const rows = s.capabilities.filter((r) => SUMMARY_IDS.includes(r.id));
  ul.replaceChildren(...rows.map((r) => h("li", { title: r.detail }, h("span", { text: r.label }), badge(r.status))));
}

function renderRecent() {
  const ol = $("#recent-events");
  const items = state.log.slice(-6).reverse();
  if (!items.length) { ol.replaceChildren(h("li", { class: "empty-inline", text: "لا توجد أحداث بعد." })); return; }
  ol.replaceChildren(...items.map((e) => h("li", {}, h("time", { datetime: e.timestamp, text: fmtTime(e.timestamp) }), h("span", { text: e.message }))));
}

// ------------------------------------------------------------------ render: device
function dlRow(label, value, src) {
  const dd = h("dd", {});
  if (value instanceof Node) dd.append(value); else dd.append(h("span", { text: value ?? "—" }));
  if (src) dd.append(h("span", { class: `src ${src === "live" ? "live" : "capture"}`, text: src === "live" ? "من BlueZ مباشرة" : "من الالتقاط" }));
  return [h("dt", { text: label }), dd];
}

function renderDevice() {
  const s = state.snap;
  const dl = $("#info-confirmed");
  const d = s?.device || {};
  const mod = d.modalias_parsed;
  const matches = d.modalias_matches_capture;
  const rows = [
    dlRow("اسم الجهاز", "oraimo Necklace Lite", "capture"),
    ...(d.name ? [dlRow("الاسم الحالي", d.alias || d.name, "live")] : []),
    dlRow("العنوان", h("bdi", { dir: "ltr", text: "28:52:E0:0F:92:0A" }), "capture"),
    dlRow("الشركة المصنّعة (OUI)", "Layon International Electronic & Telecom", "capture"),
    dlRow("مورّد الشريحة", "Zhuhai Jieli Technology (JieLi)", "capture"),
    dlRow("Vendor ID", h("bdi", { dir: "ltr", text: "0x05D6 (Bluetooth SIG)" }), "capture"),
    dlRow("Product ID", h("bdi", { dir: "ltr", text: "0x000A" }), "capture"),
    dlRow("Version", h("bdi", { dir: "ltr", text: "0x0240" }), "capture"),
  ];
  if (mod) {
    rows.push(dlRow("Modalias", h("span", {}, h("bdi", { dir: "ltr", text: `${hex4(mod.vendor_id)} / ${hex4(mod.product_id)} / ${hex4(mod.version)}` }),
      " ", badge(matches ? "available" : "unknown", matches ? "مطابق للالتقاط" : "مختلف عن الالتقاط")), "live"));
  }
  rows.push(
    dlRow("نوع الاتصال", "Bluetooth الكلاسيكي (BR/EDR)", "capture"),
    dlRow("إصدار AVRCP", "AVRCP 1.5 عبر AVCTP 1.4", "capture"),
    dlRow("أدوار AVRCP", "وحدة تحكم: الفئة 1 (تشغيل/إيقاف) — هدف: الفئة 2 (مستوى الصوت)", "capture"),
    dlRow("أحداث هدف AVRCP", h("bdi", { dir: "ltr", text: "PLAYBACK_STATUS · BATT_STATUS · VOLUME_CHANGED" }), "capture"),
    dlRow("أزرار مؤكدة", "PLAY و PAUSE (ضغط وتحرير)", "capture"),
    dlRow("البروفايلات المكتشفة", "A2DP 1.3 · AVRCP 1.5 · HFP 1.8 · HID 1.0 (معلن) · SPP (معلن)", "capture"),
    dlRow("أسماء الخدمات (SDP)", h("bdi", { dir: "ltr", text: "JL_A2DP · JL_HFP · JL_HID · JL_SPP" }), "capture"),
  );
  if (d.known) {
    rows.push(dlRow("الاقتران", `${d.paired ? "مقترنة" : "غير مقترنة"} · ${d.trusted ? "موثوقة" : "غير موثوقة"}`, "live"));
  }
  dl.replaceChildren(...rows.flat());

  const unknown = [
    "الطراز الدقيق للشريحة وإصدار البرنامج الداخلي الكامل",
    "ترميز نقطة A2DP الثانية (SEID 2)",
    "دعم أزرار التالي/السابق/الإيقاف، وإيماءات الضغط المزدوج والمطوّل",
    "أي زر يستخدم واجهة HID، وما معنى الاستخدامين 0x307 و 0x308",
    "بروتوكول خدمة JieLi الخاصة (RFCOMM 10) وما تتحكم فيه",
    "هل تُعلن السماعة عن نفسها عبر Bluetooth منخفض الطاقة (BLE)",
    "سجلات SDP المفقودة (0x10007–0x10009، 0x1000B–0x10010)",
  ];
  $("#info-unknown").replaceChildren(...unknown.map((t) => h("li", {}, icon("help"), h("span", { text: t }))));

  const svc = $("#service-list");
  const uuids = d.uuids?.length ? d.uuids : null;
  setText("#uuids-source", uuids ? "من BlueZ مباشرة (Device1.UUIDs)" : "من الالتقاط (SDP)");
  const list = uuids || [
    { uuid: "0000110b-0000-1000-8000-00805f9b34fb", name: "A2DP Sink", description: "استقبال الصوت (A2DP 1.3)" },
    { uuid: "0000110e-0000-1000-8000-00805f9b34fb", name: "AVRCP", description: "التحكم عن بعد (AVRCP 1.5)" },
    { uuid: "0000110c-0000-1000-8000-00805f9b34fb", name: "AVRCP Target", description: "هدف AVRCP (الفئة 2)" },
    { uuid: "0000111e-0000-1000-8000-00805f9b34fb", name: "HFP", description: "المكالمات دون استخدام اليدين (HFP 1.8)" },
    { uuid: "00001124-0000-1000-8000-00805f9b34fb", name: "HID", description: "جهاز إدخال HID (معلن فقط)" },
    { uuid: "00001101-0000-1000-8000-00805f9b34fb", name: "SPP", description: "منفذ تسلسلي RFCOMM 1 (معلن فقط)" },
    { uuid: "fe010000-1234-5678-abcd-00805f9b34fb", name: "JieLi SPP", description: "خدمة JieLi الخاصة RFCOMM 10 — محظورة", blocked: true },
  ];
  svc.replaceChildren(...list.map((u) => h("li", { class: u.blocked ? "blocked" : "" },
    h("span", { class: "svc-name" }, h("strong", { text: u.name || "خدمة غير معروفة" }), h("small", { dir: "ltr", text: u.uuid })),
    u.blocked ? h("span", { class: "badge badge-unavailable" }, icon("lock"), "محظورة — لا يتم التواصل معها")
      : h("span", { class: "hint", text: u.description }))));
}

// ------------------------------------------------------------------ render: diagnostics
function renderDiagnostics() {
  const s = state.snap;
  const list = $("#diag-list");
  const summary = $("#diag-summary");
  if (!s || state.agent !== "online") {
    list.replaceChildren(h("li", { class: "empty-inline", text: "الوكيل المحلي غير متصل — لا يمكن الفحص." }));
    summary.replaceChildren();
    $("#diag-system").replaceChildren();
    $("#diag-verified").replaceChildren();
    return;
  }
  const counts = { available: 0, unavailable: 0, unknown: 0 };
  for (const r of s.capabilities) counts[r.status] = (counts[r.status] || 0) + 1;
  summary.replaceChildren(...["available", "unknown", "unavailable"].map((k) =>
    h("div", { class: `stat ${k}` }, h("span", { class: "stat-icon" }, icon(STATUS_ICON[k])), h("div", {}, h("strong", { text: String(counts[k]) }), h("span", { text: STATUS_LABEL[k] })))));
  list.replaceChildren(...s.capabilities.map((r) => h("li", { "data-status": r.status },
    h("span", { class: "diag-ico" }, icon(STATUS_ICON[r.status])),
    h("span", { class: "diag-label", text: r.label }),
    badge(r.status),
    h("span", { class: "diag-detail", text: r.detail }),
    h("span", { class: "diag-tags" },
      ...r.evidence.map((e) => h("span", { class: "src", text: EVIDENCE_LABEL[e] || e })),
      r.runtime_verified ? h("span", { class: "src live", text: "تحقق أثناء التشغيل" }) : null))));

  const bt = s.bluetooth;
  const a = bt.adapter;
  $("#diag-system").replaceChildren(...[
    dlRow("خدمة BlueZ", bt.service === "available" ? "تعمل" : (REASON_TEXT[bt.error] || "غير متاحة")),
    dlRow("ناقل النظام D-Bus", bt.system_bus ? "متصل" : "غير متصل"),
    dlRow("ناقل الجلسة (MPRIS)", bt.session_bus ? "متصل" : "غير متصل"),
    dlRow("محول Bluetooth", a.present ? h("span", {}, `${a.name || ""} `, h("bdi", { dir: "ltr", text: a.address || "" })) : "غير موجود"),
    dlRow("حالة المحول", !a.present ? "—" : a.powered ? "يعمل" : a.power_state === "off-blocked" ? "محظور (rfkill)" : "متوقف"),
    dlRow("السماعة لدى BlueZ", s.device.known ? (s.device.paired ? "معروفة ومقترنة" : "معروفة وغير مقترنة") : "غير معروفة"),
    dlRow("مراقبة أزرار السماعة", s.buttons.available ? h("bdi", { dir: "ltr", text: s.buttons.device_node || "" }) : "غير مفعّلة"),
    dlRow("آخر تحديث", fmtTime(s.updated_at)),
  ].flat());

  const labels = { volume_write: "التحكم بمستوى الصوت", play_pause: "التشغيل والإيقاف المؤقت", headset_buttons: "أزرار السماعة" };
  const v = Object.entries(s.verified || {});
  $("#diag-verified").replaceChildren(...(v.length ? v.map(([k, t]) => h("li", {}, icon("check"), h("span", { text: `${labels[k] || k} — ${fmtTime(t)}` })))
    : [h("li", { class: "empty-inline", text: "لم يتم التحقق من أي أمر بعد في هذه الجلسة." })]));
}

// ------------------------------------------------------------------ render: log
function logMatches(e, filter) {
  if (filter === "all") return true;
  if (filter === "errors") return e.severity === "warning" || e.severity === "error";
  return (LOG_FILTERS[filter] || []).includes(e.type);
}

function logItem(e, fresh) {
  return h("li", { "data-severity": e.severity, class: fresh ? "fresh" : "" },
    h("time", { datetime: e.timestamp, text: fmtTime(e.timestamp) }),
    h("span", { class: "log-type", text: LOG_TYPE_LABEL[e.type] || e.type }),
    h("span", { class: "log-msg", text: e.message }));
}

function renderLog(freshId = null) {
  const filter = $("#log-filter").value;
  const items = state.log.filter((e) => logMatches(e, filter)).reverse();
  $("#log-list").replaceChildren(...items.map((e) => logItem(e, e.id === freshId)));
  $("#log-empty").hidden = items.length > 0;
  renderRecent();
}

function exportLog(kind) {
  const entries = state.log;
  let blob, name;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  if (kind === "json") {
    blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), device: "oraimo Necklace Lite", entries }, null, 2)], { type: "application/json" });
    name = `necklace-log-${stamp}.json`;
  } else {
    const lines = entries.map((e) => `${e.timestamp}\t${LOG_TYPE_LABEL[e.type] || e.type}\t${e.message}`);
    blob = new Blob(["﻿" + lines.join("\n") + "\n"], { type: "text/plain;charset=utf-8" });
    name = `necklace-log-${stamp}.txt`;
  }
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  toast("تم تصدير السجل", "ok");
}

// ------------------------------------------------------------------ render: settings
function renderSettings() {
  const s = state.snap;
  const sel = $("#player-select");
  const players = s?.media?.players || [];
  const selected = s?.media?.selected || "auto";
  const opts = [h("option", { value: "auto", text: "تلقائي (المشغل النشط)" }),
    ...players.map((p) => h("option", { value: p.bus_name, text: `${p.identity} — ${PLAY_LABEL[p.status] || p.status}` }))];
  const key = JSON.stringify([players.map((p) => [p.bus_name, p.status]), selected]);
  if (sel.dataset.key !== key && document.activeElement !== sel) {
    sel.dataset.key = key;
    sel.replaceChildren(...opts);
    sel.value = selected;
  }
  sel.disabled = !s || state.agent !== "online" || !players.length;

  $("#agent-info").replaceChildren(...[
    dlRow("الحالة", state.agent === "online" ? "متصل" : "غير متصل"),
    dlRow("الإصدار", s?.agent?.version || "—"),
    dlRow("عنوان الاستماع", h("bdi", { dir: "ltr", text: s?.agent?.bind || location.host })),
    dlRow("السماعة المستهدفة", h("bdi", { dir: "ltr", text: s?.device?.target_address || "28:52:E0:0F:92:0A" })),
  ].flat());

  const theme = storageGet("necklace-theme", "dark");
  for (const b of $$("#theme-switch button")) b.setAttribute("aria-checked", String(b.dataset.themeValue === theme));
}

function applyTheme(value) {
  document.documentElement.dataset.theme = value;
  storageSet("necklace-theme", value);
  renderSettings();
}

// ================================================================== Phase 2: capability discovery
const ST_CLASS = { confirmed: "st-confirmed", advertised: "st-advertised", unknown: "st-unknown", unavailable: "st-unavailable", present: "st-present" };
const STEP_ICON = { ok: "check", failed: "x", skipped: "alert", unavailable: "alert" };
const FINDING_ICON = { confirmed: "check", warning: "alert", vendor: "lock", info: "info" };
const ACTION_ICON = { play: "play", pause: "pause", volume_up: "plus", volume_down: "minus", previous: "skip-prev", next: "skip-next", mute: "mute" };

const disc = { data: null, log: [], tab: "matrix", fetchTimer: null, logDirty: false, loadedLog: false };

function st(key, label) { return h("span", { class: `st ${ST_CLASS[key] || "st-unknown"}`, text: label }); }
function cls(c, label) { return h("span", { class: `cls cls-${c}`, text: label }); }
function td(label, ...children) { return h("td", { "data-label": label }, ...children); }
const fmtTs = (s) => (s ? fmtTime(new Date(s * 1000).toISOString()) : "—");

function scheduleDiscoveryFetch(delay = 250) {
  if (state.route !== "discovery") return;
  clearTimeout(disc.fetchTimer);
  disc.fetchTimer = setTimeout(fetchDiscovery, delay);
}

async function fetchDiscovery() {
  try {
    disc.data = await api("/api/discovery");
    if (!disc.loadedLog) {
      disc.log = await api("/api/discovery/log?limit=1000");
      disc.loadedLog = true;
    }
    renderDiscovery();
  } catch (e) {
    if (state.agent === "online") toast(e.message, "bad");
  }
}

function handleDiscoveryMessage(msg) {
  switch (msg.type) {
    case "discovery_log":
      disc.log.push(msg.entry);
      if (disc.log.length > 2000) disc.log.shift();
      if (state.route === "discovery" && disc.tab === "dlog" && !disc.logDirty) {
        disc.logDirty = true;
        requestAnimationFrame(() => { disc.logDirty = false; renderDlog(); });
      }
      return true;
    case "discovery_scan":
      if (msg.step) setText("#scan-status", `جارٍ الفحص: ${msg.step.label} — ${msg.step.detail}`);
      if (!msg.running) scheduleDiscoveryFetch(50);
      return true;
    case "research_trial":
      if (disc.data) {
        const trials = disc.data.research.trials;
        const i = trials.findIndex((t) => t.id === msg.trial.id);
        if (i >= 0) trials[i] = msg.trial; else trials.push(msg.trial);
        if (state.route === "discovery") renderTrials();
      }
      if (msg.trial.status === "done") scheduleDiscoveryFetch();
      return true;
    case "discovery_changed":
      scheduleDiscoveryFetch();
      return true;
    case "capture_status":
      if (disc.data) {
        disc.data.capture = msg.capture;
        if (state.route === "discovery" && disc.tab === "research") renderCapture(msg.capture);
      }
      return true;
    default:
      return false;
  }
}

function renderDiscovery() {
  if (state.route !== "discovery") return;
  const d = disc.data;
  const s = state.snap;
  // header: live connection from the status stream, identity from discovery
  const conn = state.agent === "online" && s ? s.connection.state : "unknown";
  $("#d-conn").dataset.state = conn;
  setText("#d-conn-label", CONN_LABEL[conn] || CONN_LABEL.unknown);
  if (d) {
    setText("#d-name", d.device.name);
    setText("#d-addr", d.device.address);
    setText("#d-maker", d.device.manufacturer);
    setText("#d-chip", d.device.chipset);
    setText("#d-profiles", `البروفايلات: ${d.device.profiles.join(" · ")}`);
  }
  const scanBtn = $("#btn-safe-scan");
  if (scanBtn.getAttribute("aria-busy") !== "true") scanBtn.disabled = state.agent !== "online" || Boolean(d?.scan_running);
  for (const b of $$("#disc-tabs [data-dtab]")) b.setAttribute("aria-selected", String(b.dataset.dtab === disc.tab));
  for (const p of $$(".dpanel")) p.hidden = p.dataset.dpanel !== disc.tab;
  if (!d) return;
  if (disc.tab === "matrix") renderMatrix(d);
  if (disc.tab === "services") renderServices(d);
  if (disc.tab === "profiles") renderProfiles(d);
  if (disc.tab === "research") renderResearch(d);
  if (disc.tab === "dlog") renderDlog();
}

function renderMatrix(d) {
  const counts = {};
  for (const r of d.matrix) counts[r.status_label] = (counts[r.status_label] || 0) + 1;
  setText("#matrix-meta", Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(" · "));
  $("#matrix-table tbody").replaceChildren(...d.matrix.map((r) => h("tr", {},
    h("td", { class: "fn" }, r.function, h("span", { class: "ev", text: r.evidence })),
    td("الحالة", st(r.status, r.status_label)),
    td("المصدر", h("span", { text: r.source })),
    td("طريقة الاختبار", h("span", { text: r.method })),
    td("آمنة؟", h("span", { class: r.safe_ok ? "safe-yes" : "safe-no", text: r.safe })))));
  const scan = d.scan;
  setText("#scan-meta", scan ? `آخر فحص: ${fmtTs(scan.finished_at || scan.started_at)}` : "لم يُجرَ فحص بعد");
  $("#scan-steps").replaceChildren(...(scan ? scan.steps.map((x) => h("li", { "data-status": x.status },
    icon(STEP_ICON[x.status] || "info"), h("span", {}, h("strong", { text: x.label }), h("small", { text: x.detail })),
    h("span", { class: "hint", text: { ok: "نجح", failed: "فشل", skipped: "تم التخطي", unavailable: "غير متاح" }[x.status] })))
    : [h("li", { class: "empty-inline", text: "اضغط «فحص آمن» لقراءة الخدمات من السماعة وBlueZ." })]));
  if (!d.scan_running) setText("#scan-status", scan ? `اكتمل الفحص ${fmtTs(scan.finished_at)} — قراءة فقط.` : "قراءة فقط: SDP وD-Bus وUUIDs. لا تُفتح أي قناة ولا تُرسل أوامر خاصة بالمصنّع.");
}

function renderServices(d) {
  const live = d.services.some((x) => x.live_sdp);
  setText("#svc-meta", live ? "من SDP مباشر (فحص آمن) مقارنة بالالتقاط" : "من الالتقاط وقائمة UUIDs في BlueZ — شغّل «فحص آمن» لقراءة SDP مباشرة");
  $("#svc-table tbody").replaceChildren(...d.services.map((x) => {
    const chan = x.rfcomm_channel ? `RFCOMM ${x.rfcomm_channel}` : x.l2cap_psm ? `L2CAP PSM 0x${x.l2cap_psm.toString(16).padStart(4, "0").toUpperCase()} (${x.psm_name || "?"})` : "—";
    return h("tr", { class: x.blocked ? "is-vendor" : "" },
      h("td", { class: "fn" }, x.display + (x.name ? ` (${x.name})` : ""), x.blocked ? h("span", { class: "ev", text: "خدمة مخصصة من الشركة — لا يتواصل معها الوكيل" }) : null,
        x.changed ? h("span", { class: "ev", text: "تختلف عن الالتقاط" }) : null),
      td("UUID", h("code", { text: x.uuid })),
      td("القناة", h("span", { text: chan })),
      td("البروفايل", h("span", { text: x.profile })),
      td("الحالة", st(x.state, x.state_label)));
  }));
  const scan = d.scan || {};
  const rf = scan.rfcomm || d.services.filter((x) => x.rfcomm_channel).map((x) => ({ channel: x.rfcomm_channel, service: x.display, blocked: x.blocked, source: "الالتقاط" }));
  $("#rfcomm-list").replaceChildren(...rf.map((r) => h("li", {},
    h("span", { class: "k" }, `القناة ${r.channel}`, h("small", { text: `المصدر: ${r.source}` })),
    h("span", { class: "v" }, r.service, r.blocked ? st("present", "موجودة — البروتوكول غير معروف") : st("advertised", "معلنة في SDP")))));
  const l2 = d.l2cap_capture.map((x) => h("li", {},
    h("span", { class: "k" }, `PSM 0x${x.psm.toString(16).padStart(4, "0").toUpperCase()} — ${x.protocol}`, h("small", { text: x.note })),
    h("span", { class: "v" }, h("bdi", { dir: "ltr", text: `${x.host_cid} ↔ ${x.headset_cid}` }))));
  $("#l2cap-list").replaceChildren(...l2);
  const uu = d.device.uuids || [];
  $("#uuid-list").replaceChildren(...(uu.length ? uu.map((u) => h("li", {},
    h("span", { class: "k" }, u.name || "غير معروف", h("small", { dir: "ltr", text: u.uuid })),
    h("span", { class: "v" }, u.blocked ? st("present", "محظورة") : st("present", "الخدمة موجودة"))))
    : [h("li", { class: "empty-inline", text: "لا توجد UUIDs — السماعة غير معروفة لدى BlueZ." })]));
  const obj = [];
  for (const o of scan.dbus?.objects || []) obj.push(h("li", {}, h("span", { class: "k" }, h("small", { dir: "ltr", text: o.path })), h("span", { class: "v", text: o.interfaces.map((i) => i.replace("org.bluez.", "")).join("، ") })));
  for (const i of scan.input || []) obj.push(h("li", {}, h("span", { class: "k" }, `جهاز إدخال: ${i.name}`, h("small", { text: i.handlers || "" })), h("span", { class: "v", text: i.kind })));
  if (scan.gatt) obj.push(h("li", {}, h("span", { class: "k", text: "GATT" }), h("span", { class: "v", text: Array.isArray(scan.gatt) && scan.gatt.length ? `${scan.gatt.length} خدمة` : "لا توجد خدمات معروضة" })));
  $("#objects-list").replaceChildren(...(obj.length ? obj : [h("li", { class: "empty-inline", text: "شغّل «فحص آمن» لعرض كائنات BlueZ وأجهزة الإدخال وGATT." })]));
}

function renderProfiles(d) {
  const a = d.avrcp;
  const live = a.live;
  const ph = a.observed.headset_passthrough || {};
  const rows = [
    ["تشغيل (PLAY 0x44)", st("confirmed", "مؤكدة"), `من السماعة في الالتقاط${ph.PLAY ? ` · رُصد الآن ×${ph.PLAY}` : ""}`],
    ["إيقاف مؤقت (PAUSE 0x46)", st("confirmed", "مؤكدة"), `من السماعة في الالتقاط${ph.PAUSE ? ` · رُصد الآن ×${ph.PAUSE}` : ""}`],
    ["مستوى الصوت", st("confirmed", "مؤكدة"), live.volume.available ? `الآن ${live.volume.percent}% (${live.volume.raw}/127)` : "غير متاح حاليًا"],
    ["حالة التشغيل", st("confirmed", "مؤكدة"), `المشغل: ${live.player || "—"} · ${PLAY_LABEL[live.playback] || "غير معروف"}`],
    ["معلومات المقطع", st("confirmed", "مؤكدة"), live.track?.title ? `${live.track.title}${live.track.artist ? ` — ${live.track.artist}` : ""}` : "السماعة تطلبها (GetElementAttributes)"],
    ["أحداث هدف السماعة", st("confirmed", "مؤكدة"), a.headset_tg_events.join("، ")],
    ["سجّلتها السماعة لدى الحاسوب", st("confirmed", "مؤكدة"), a.headset_registered.join("، ")],
    ["سجّلها الحاسوب لدى السماعة", st("confirmed", "مؤكدة"), a.host_registered.join("، ")],
    ["أحداث رُصدت الآن", a.observed.events.length ? st("confirmed", "مرصودة") : st("unknown", "لا شيء بعد"), a.observed.events.join("، ") || "يتطلب btmon"],
  ];
  $("#avrcp-list").replaceChildren(...rows.map(([k, b, v]) => h("li", {}, h("span", { class: "k" }, k, h("small", { text: v })), h("span", { class: "v" }, b))));

  const hd = d.hid;
  const hs = $("#hid-status");
  hs.className = `state-line ${hd.observed_reports ? "confirmed" : "advertised"}`;
  setText(hs, hd.status_label);
  $("#hid-reports").replaceChildren(...hd.reports.map((r) => h("div", { class: "hid-report" },
    h("p", {}, h("strong", { text: `Report ID ${r.report_id} — ${r.page}` }), h("span", { class: "hint", text: ` · ${r.description}` })),
    r.usages.length ? h("ul", { class: "kv-list" }, ...r.usages.map((u, i) => h("li", {},
      h("span", { class: "k" }, `بت ${i}: ${u.ar || u.name}`, h("small", { dir: "ltr", text: `0x${u.usage.toString(16).toUpperCase()} ${u.name}` })),
      h("span", { class: "v" }, st("advertised", "معلن"))))) : null)));
  $("#hid-notes").replaceChildren(...hd.capture_notes.map((n) => h("li", {}, h("span", { class: "k", text: n }))),
    ...(hd.live_sdp ? [h("li", {}, h("span", { class: "k", text: "الواصف من SDP المباشر" }), h("span", { class: "v" }, hd.live_sdp.matches_capture ? st("confirmed", "مطابق للالتقاط") : st("advertised", "مختلف")))] : []));

  const j = d.jieli;
  $("#jieli-list").replaceChildren(
    h("li", {}, h("span", { class: "k", text: "UUID" }), h("span", { class: "v" }, h("code", { dir: "ltr", text: j.uuid }))),
    h("li", {}, h("span", { class: "k", text: "قناة RFCOMM" }), h("span", { class: "v", text: String(j.rfcomm_channel) })),
    h("li", {}, h("span", { class: "k", text: "اسم الخدمة" }), h("span", { class: "v", text: j.name })),
    h("li", {}, h("span", { class: "k", text: "السياسة" }), h("span", { class: "v", text: j.policy })),
    h("li", {}, h("span", { class: "k", text: "حركة مرصودة (سلبيًا)" }), h("span", { class: "v", text: j.observed_frames ? `${j.observed_frames} رسالة` : "لا شيء" })));
}

function renderResearch(d) {
  renderCapture(d.capture);
  renderResearchControls(d);
  renderTrials();
  renderAnalysis(d.analysis);
}

function renderCapture(c) {
  const cb = $("#cap-badge");
  cb.className = `badge ${c.active && c.stats?.records ? "badge-available" : "badge-unknown"}`;
  setText(cb, c.active && c.stats?.records ? "نشط" : c.error ? "خطأ" : "لا يوجد التقاط");
  setText("#cap-cmd", c.command);
  $("#cap-info").replaceChildren(...[
    dlRow("الملف", h("bdi", { dir: "ltr", text: c.path })),
    dlRow("الحالة", c.exists ? (c.error === "permission_denied" ? "لا توجد صلاحية قراءة" : c.error ? "خطأ في القراءة" : "يُقرأ الآن") : "الملف غير موجود — شغّل الأمر أعلاه"),
    dlRow("السجلات", c.stats ? `${c.stats.records} (${c.stats.packets} حزمة تحكم، ${c.stats.media} وسائط)` : "—"),
    dlRow("اتصال السماعة", c.target_handles?.length ? `handle ${c.target_handles.join("، ")}` : "لم يُرصد اتصالها بعد (أعد الاتصال بعد تشغيل btmon)"),
    dlRow("آخر حزمة", fmtTs(c.last_packet_ts)),
  ].flat());
}

function renderResearchControls(d) {
  const r = d.research;
  setText("#hs-window", String(r.headset_window));
  const rb = $("#research-badge");
  rb.className = `badge ${r.active ? "badge-available" : "badge-muted"}`;
  setText(rb, r.active ? "يعمل" : "متوقف");
  setText("#btn-research-label", r.active ? "إيقاف وضع البحث" : "بدء وضع البحث");
  $("#btn-research").className = r.active ? "btn btn-soft" : "btn btn-primary";
  const grid = $("#action-grid");
  if (grid.dataset.key !== String(r.active)) {
    grid.dataset.key = String(r.active);
    grid.replaceChildren(...r.actions.map((a) => h("div", { class: "action-card" },
      h("h4", {}, icon(ACTION_ICON[a.id] || "info"), a.label),
      h("div", { class: "row" },
        h("button", { class: "btn btn-soft", type: "button", disabled: !r.active || !a.host, "data-research": "host", "data-action": a.id,
          title: a.host ? "ينفذ أمرًا مسموحًا من الحاسوب ثم يراقب الحزم" : "لا توجد واجهة آمنة لهذا الأمر من الحاسوب" }, "من الحاسوب"),
        h("button", { class: "btn btn-soft", type: "button", disabled: !r.active, "data-research": "headset", "data-action": a.id,
          title: "لا يُرسل شيئًا: يراقب ما ترسله السماعة عند ضغطك الزر" }, "سأضغط على السماعة")),
      !a.host ? h("span", { class: "hint", text: "من السماعة فقط: لا توجد واجهة كتم آمنة" }) : null)));
  }
}

function packetTable(packets) {
  return h("div", { class: "table-wrap" }, h("table", { class: "rtable" },
    h("thead", {}, h("tr", {}, ...["الوقت", "HCI", "القناة", "البروتوكول", "Opcode", "الاتجاه", "المعنى", "النوع"].map((x) => h("th", { text: x })))),
    h("tbody", {}, ...packets.map((p) => h("tr", { class: p.classification === "vendor" ? "is-vendor" : "" },
      td("الوقت", h("span", { class: "mono", text: fmtTs(p.ts) })),
      td("HCI", h("span", { text: p.hci })),
      td("القناة", h("span", { text: p.channel || "—" })),
      td("البروتوكول", h("span", { text: p.protocol })),
      td("Opcode", h("code", { text: p.opcode || "—" })),
      td("الاتجاه", h("span", { text: p.direction_label })),
      td("المعنى", h("span", {}, p.summary, h("span", { class: "raw", text: p.raw }))),
      td("النوع", cls(p.classification, p.classification_label)))))));
}

function renderTrials() {
  const d = disc.data;
  if (!d) return;
  const trials = [...d.research.trials].reverse();
  setText("#trials-meta", trials.length ? `${trials.length} تجربة` : "");
  const box = $("#trials");
  const key = JSON.stringify(trials.map((t) => [t.id, t.status, t.packets.length, t.findings.length]));
  if (box.dataset.key === key) return;
  box.dataset.key = key;
  if (!trials.length) { box.replaceChildren(h("p", { class: "empty-inline", text: "لا توجد تجارب بعد. ابدأ وضع البحث ثم اختر إجراءً." })); return; }
  box.replaceChildren(...trials.map((t) => {
    const pending = t.status === "pending";
    const remain = Math.max(0, Math.ceil(t.window[1] - Date.now() / 1000));
    return h("div", { class: "trial", "data-status": t.status },
      h("div", { class: "trial-head" },
        h("strong", { text: `#${t.id} ${t.label} — ${t.origin === "host" ? "من الحاسوب" : "من السماعة"}` }),
        h("span", { class: "meta" }, fmtTs(t.created), " · ",
          pending ? h("span", { class: "countdown", "data-until": String(t.window[1]), text: t.origin === "headset" ? `اضغط الزر الآن… ${remain} ث` : "جارٍ جمع الحزم…" })
            : t.status === "failed" ? `فشل: ${t.error}` : `${t.packets.length} حزمة، ${t.system_events.length} حدث نظام`)),
      t.findings.length ? h("ul", { class: "findings" }, ...t.findings.map((f) => h("li", { class: f.kind }, icon(FINDING_ICON[f.kind] || "info"), h("span", { text: f.text })))) : null,
      t.packets.length ? h("details", { class: "pk" }, h("summary", { text: `الحزم المرتبطة (${t.packets.length})` }), packetTable(t.packets)) : null);
  }));
}

function renderAnalysis(a) {
  const box = $("#analysis");
  if (!a) { box.replaceChildren(); return; }
  const s = a.summary;
  const kv = (k, v) => h("li", {}, h("span", { class: "k", text: k }), h("span", { class: "v", text: v }));
  box.replaceChildren(h("ul", { class: "kv-list" },
    kv("نوع الملف", a.datalink === 2001 ? "btmon (Linux monitor)" : a.datalink === 1002 ? "HCI H4 (Android)" : String(a.datalink)),
    kv("الأجهزة", a.devices.join("، ") || "—"),
    kv("حزم التحكم", `${a.stats.packets} (وسائط: ${a.stats.media})`),
    kv("حسب النوع", Object.entries(s.by_classification).map(([k, v]) => `${k}: ${v}`).join(" · ")),
    kv("أزرار PASS THROUGH", Object.entries(s.passthrough).map(([k, v]) => `${k}×${v}`).join("، ") || "لا شيء"),
    kv("أحداث AVRCP", s.avrcp_events.join("، ") || "لا شيء"),
    kv("خدمات SDP في الملف", a.services.map((x) => x.display + (x.rfcomm_channel ? ` (RFCOMM ${x.rfcomm_channel})` : "")).join("، ") || "لا شيء")),
    a.vendor_packets.length ? h("details", { class: "pk", open: true }, h("summary", { text: `حزم خاصة بالمصنّع (${a.vendor_packets.length}) — للدراسة فقط، لا تُعاد إرسالها` }), packetTable(a.vendor_packets))
      : h("p", { class: "hint", text: "لا توجد حزم خاصة بالمصنّع في هذا الملف." }));
}

function dlogMatches(e, f) {
  if (f === "all") return true;
  if (f === "vendor") return e.classification === "vendor" || e.classification === "controller_vendor";
  if (f === "avrcp") return e.type === "AVRCP" || e.type === "AV/C";
  if (f === "scan") return e.type === "فحص آمن";
  if (f === "research") return e.type === "وضع البحث" || e.type === "اكتشاف" || e.type === "تحليل التقاط";
  return true;
}

function renderDlog() {
  const f = $("#dlog-filter").value;
  const items = disc.log.filter((e) => dlogMatches(e, f)).slice(-600).reverse();
  $("#dlog-table tbody").replaceChildren(...items.map((e) => h("tr", { class: e.classification === "vendor" ? "is-vendor" : "" },
    td("الوقت", h("span", { text: fmtTs(e.ts) })),
    td("النوع", h("span", {}, e.type, " ", e.classification !== "standard" ? cls(e.classification, e.classification_label) : null)),
    td("القناة", h("span", { text: e.channel })),
    td("الاتجاه", h("span", { text: e.direction })),
    td("البيانات", h("span", {}, e.data, e.raw ? h("span", { class: "raw", text: e.raw }) : null)),
    td("النتيجة", h("span", { text: e.result })))));
  $("#dlog-empty").hidden = items.length > 0;
}

function bindDiscovery() {
  for (const b of $$("#disc-tabs [data-dtab]")) b.addEventListener("click", () => { disc.tab = b.dataset.dtab; renderDiscovery(); });
  $("#btn-safe-scan").addEventListener("click", (e) => {
    setText("#scan-status", "جارٍ الفحص الآمن…");
    runAction(e.currentTarget, () => api("/api/discovery/scan", { method: "POST" }), { success: "اكتمل الفحص الآمن" })
      .then(() => fetchDiscovery());
  });
  $("#btn-research").addEventListener("click", (e) => {
    const active = disc.data?.research?.active;
    runAction(e.currentTarget, () => api(active ? "/api/research/stop" : "/api/research/start", { method: "POST" }),
      { success: active ? "تم إيقاف وضع البحث" : "بدأ وضع البحث" }).then(() => fetchDiscovery());
  });
  $("#action-grid").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-research]");
    if (!b) return;
    const origin = b.dataset.research;
    runAction(b, () => api(`/api/research/${origin}`, { method: "POST", body: { action: b.dataset.action } }),
      { success: origin === "headset" ? "اضغط الزر على السماعة الآن" : "نُفذ الأمر — جارٍ جمع الحزم" })
      .then(() => { b.disabled = false; fetchDiscovery(); });
  });
  $("#btn-copy-cmd").addEventListener("click", async () => {
    const text = $("#cap-cmd").textContent;
    try { await navigator.clipboard.writeText(text); toast("تم نسخ الأمر", "ok"); } catch { toast("تعذر النسخ — انسخ الأمر يدويًا", "warn"); }
  });
  $("#capture-file").addEventListener("change", async (e) => {
    const file = e.currentTarget.files?.[0];
    if (!file) return;
    if (file.size > 64 * 1024 * 1024) { toast("الملف أكبر من 64 ميغابايت", "bad"); return; }
    const label = $(".file-drop span");
    label.setAttribute("aria-busy", "true");
    try {
      const res = await fetch("/api/capture/analyze", { method: "POST", headers: { "Content-Type": "application/octet-stream", Accept: "application/json" }, body: file, credentials: "same-origin" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.ok) throw new Error(data?.error?.message || "تعذر تحليل الملف");
      toast(`حُلّل الملف: ${data.data.stats.packets} حزمة`, "ok");
      await fetchDiscovery();
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      label.removeAttribute("aria-busy");
      e.currentTarget.value = "";
    }
  });
  $("#dlog-filter").addEventListener("change", renderDlog);
  $("#btn-dlog-export").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), entries: disc.log }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: `necklace-discovery-${new Date().toISOString().replace(/[:.]/g, "-")}.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast("تم تصدير السجل التفصيلي", "ok");
  });
  $("#btn-dlog-clear").addEventListener("click", (e) => {
    if (!confirm("هل تريد مسح السجل التفصيلي؟")) return;
    runAction(e.currentTarget, () => api("/api/discovery/log/clear", { method: "POST" }), { success: "تم مسح السجل التفصيلي" })
      .then(() => { disc.log = []; renderDlog(); });
  });
  // live countdown for pending headset trials
  setInterval(() => {
    for (const el of $$(".countdown[data-until]")) {
      const remain = Math.max(0, Math.ceil(Number(el.dataset.until) - Date.now() / 1000));
      el.textContent = remain > 0 ? `اضغط الزر الآن… ${remain} ث` : "جارٍ جمع الحزم…";
    }
  }, 500);
}

// ------------------------------------------------------------------ routing
const ROUTES = {
  dashboard: ["لوحة التحكم", "التحكم في سماعة Oraimo Necklace Lite عبر الوكيل المحلي"],
  discovery: ["اكتشاف إمكانيات السماعة", "فحص آمن للخدمات والبروتوكولات، ومراقبة سلبية للحركة"],
  device: ["معلومات الجهاز", "هوية السماعة كما أثبتها الالتقاط وكما يعرضها BlueZ"],
  diagnostics: ["التشخيص", "ما يعمل فعلًا الآن، وما هو معلن فقط"],
  log: ["سجل الأحداث", "كل ما رصده الوكيل المحلي بالترتيب الزمني"],
  advanced: ["التحكم المتقدم", "لم يتم اكتشاف بروتوكول آمن لهذه الوظائف بعد"],
  settings: ["الإعدادات", "المظهر ومشغل الوسائط والوكيل المحلي"],
};

function route() {
  const name = (location.hash.replace(/^#\/?/, "") || "dashboard").split("?")[0];
  state.route = ROUTES[name] ? name : "dashboard";
  for (const v of $$(".view")) v.hidden = v.dataset.view !== state.route;
  for (const a of $$("[data-route]")) {
    if (a.dataset.route === state.route) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  const [title, sub] = ROUTES[state.route];
  setText("#page-title", title);
  setText("#page-subtitle", sub);
  document.title = `${title} — متحكم Necklace`;
  render();
  if (state.route === "discovery") fetchDiscovery();
}

// ------------------------------------------------------------------ render root
function render() {
  renderAgent();
  renderBanners();
  renderHero();
  renderSummary();
  renderRecent();
  if (state.route === "device") renderDevice();
  if (state.route === "diagnostics") renderDiagnostics();
  if (state.route === "settings") renderSettings();
  if (state.route === "discovery") renderDiscovery();
}

// ------------------------------------------------------------------ events
function bind() {
  window.addEventListener("hashchange", route);
  bindDiscovery();

  $("#btn-play").addEventListener("click", (e) =>
    runAction(e.currentTarget, () => api("/api/media/play", { method: "POST" }),
      { success: (r) => (r.verified ? "تم التشغيل" : "أُرسل أمر التشغيل، ولم تتأكد حالة المشغل بعد") }));
  $("#btn-pause").addEventListener("click", (e) =>
    runAction(e.currentTarget, () => api("/api/media/pause", { method: "POST" }),
      { success: (r) => (r.verified ? "تم الإيقاف المؤقت" : "أُرسل أمر الإيقاف، ولم تتأكد حالة المشغل بعد") }));
  $("#btn-reconnect").addEventListener("click", (e) => {
    const connected = state.snap?.connection?.connected;
    if (connected && !confirm("سيتم قطع الاتصال بالسماعة ثم إعادة الاتصال. هل تريد المتابعة؟")) return;
    runAction(e.currentTarget, () => api("/api/reconnect", { method: "POST" }), { success: "تم الاتصال بالسماعة" });
  });
  $("#btn-vol-up").addEventListener("click", (e) =>
    runAction(e.currentTarget, () => api("/api/volume/up", { method: "POST" })));
  $("#btn-vol-down").addEventListener("click", (e) =>
    runAction(e.currentTarget, () => api("/api/volume/down", { method: "POST" })));

  const slider = $("#vol-slider");
  const sendVolume = () => {
    clearTimeout(state.volumeTimer);
    state.volumeTimer = null;
    const percent = Number(slider.value);
    api("/api/volume", { method: "POST", body: { percent } })
      .then((r) => { if (!r.verified) toast("أُرسل مستوى الصوت، ولم يؤكده BlueZ بعد", "warn"); })
      .catch((err) => toast(err.message, "bad"))
      .finally(() => { state.volumeTouchedAt = 0; render(); });
  };
  slider.addEventListener("input", () => {
    state.volumeTouchedAt = Date.now();
    $(".tile-volume").dataset.pending = "true";
    setText("#vol-value", `${slider.value}%`);
    slider.style.setProperty("--pct", `${slider.value}%`);
    clearTimeout(state.volumeTimer);
    state.volumeTimer = setTimeout(sendVolume, 350);
  });
  slider.addEventListener("change", () => { state.volumeTouchedAt = Date.now(); sendVolume(); });

  $("#btn-refresh").addEventListener("click", (e) =>
    runAction(e.currentTarget, async () => { const d = await api("/api/status"); state.snap = d; setAgent("online"); }, { success: "تم تحديث الحالة" }));
  $("#btn-diag-refresh").addEventListener("click", (e) =>
    runAction(e.currentTarget, async () => { await api("/api/diagnostics?refresh=1"); state.snap = await api("/api/status"); }, { success: "تمت إعادة الفحص" }));

  $("#log-filter").addEventListener("change", () => renderLog());
  $("#btn-export-json").addEventListener("click", () => exportLog("json"));
  $("#btn-export-txt").addEventListener("click", () => exportLog("txt"));
  $("#btn-clear-log").addEventListener("click", (e) => {
    if (!confirm("هل تريد مسح سجل الأحداث؟")) return;
    runAction(e.currentTarget, () => api("/api/events/clear", { method: "POST" }), { success: "تم مسح السجل" });
  });

  for (const b of $$("#theme-switch button")) b.addEventListener("click", () => applyTheme(b.dataset.themeValue));
  $("#player-select").addEventListener("change", (e) => {
    const value = e.currentTarget.value;
    runAction(null, () => api("/api/media/player", { method: "POST", body: { bus_name: value } }),
      { success: (r) => `المشغل المستهدف: ${r.player || "تلقائي"}` });
  });
}

// ------------------------------------------------------------------ boot
function boot() {
  document.documentElement.dataset.theme = storageGet("necklace-theme", "dark");
  bind();
  route();
  connectWs();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
else boot();
