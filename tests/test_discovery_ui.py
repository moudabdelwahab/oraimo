"""Discovery console UI tests (Chromium) against the TEST-ONLY mock + fake sdptool + synthetic btmon file."""

import time
from pathlib import Path

from playwright.sync_api import expect

from tests import btsnoop_writer as bw
from tests.test_ui import browser, no_overflow, open_page  # noqa: F401  (fixture re-export)


def test_discovery_scan_matrix_and_profiles(browser, env):  # noqa: F811
    page = open_page(browser, env, route="discovery")
    expect(page.locator("#page-title")).to_have_text("اكتشاف إمكانيات السماعة")
    expect(page.locator("#d-conn-label")).to_have_text("متصل")
    for label in ("متصل", "غير متصل", "الخدمة موجودة", "الخدمة غير متاحة", "الوظيفة مؤكدة", "الوظيفة معلنة فقط", "الوظيفة غير معروفة"):
        expect(page.locator(".legend")).to_contain_text(label)
    rows = page.locator("#matrix-table tbody tr")
    expect(rows.first).to_be_visible()
    expect(page.locator("#matrix-table tbody tr", has_text="خدمة JieLi المخصصة")).to_contain_text("لا ترسل أوامر مجهولة")
    expect(page.locator("#matrix-table tbody tr", has_text="HID (مفاتيح الوسائط)")).to_contain_text("معلنة فقط")
    expect(page.locator("#matrix-table tbody tr", has_text="البطارية").first).to_contain_text("مؤكدة")

    page.click("#btn-safe-scan")
    expect(page.locator("#scan-steps li")).to_have_count(10, timeout=15000)
    expect(page.locator("#scan-steps")).to_contain_text("8 سجل خدمة")

    page.click('[data-dtab="services"]')
    expect(page.locator("#svc-table tbody tr", has_text="fe010000-1234-5678-abcd-00805f9b34fb")).to_contain_text("RFCOMM 10")
    expect(page.locator("#rfcomm-list")).to_contain_text("القناة 10")
    expect(page.locator("#l2cap-list")).to_contain_text("PSM 0x0017")

    page.click('[data-dtab="profiles"]')
    expect(page.locator("#hid-status")).to_have_text("معلن لكنه غير متاح حاليًا / يحتاج اختبار اتصال آمن")
    expect(page.locator("#hid-reports")).to_contain_text("Report ID 3")
    expect(page.locator("#jieli-status")).to_have_text("خدمة مخصصة من الشركة - البروتوكول غير معروف")
    expect(page.locator("#jieli-list")).to_contain_text("fe010000-1234-5678-abcd-00805f9b34fb")
    expect(page.locator("#avrcp-list")).to_contain_text("PLAYBACK_STATUS_CHANGED")
    # no control exists anywhere for the JieLi service
    assert page.locator("#jieli-card button, #jieli-card input").count() == 0

    page.click('[data-dtab="dlog"]')
    expect(page.locator("#dlog-table thead")).to_contain_text("الاتجاه")
    expect(page.locator("#dlog-table tbody")).to_contain_text("لا تُرسل أي أوامر خاصة بالمصنّع")
    assert no_overflow(page)
    assert not page.problems, page.problems


def test_research_mode_live_capture(browser, env):  # noqa: F811
    cap = Path(env.capture_path)
    cap.write_bytes(bw.header() + bw.setup(time.time()))
    page = open_page(browser, env, route="discovery")
    page.click('[data-dtab="research"]')
    expect(page.locator("#cap-badge")).to_have_text("نشط", timeout=8000)
    expect(page.locator("#cap-cmd")).to_contain_text("sudo btmon -w")
    host_mute = page.locator('button[data-research="host"][data-action="mute"]')
    expect(host_mute).to_be_disabled()
    page.click("#btn-research")
    expect(page.locator("#research-badge")).to_have_text("يعمل")
    page.click('button[data-research="headset"][data-action="next"]')
    expect(page.locator(".trial[data-status='pending']")).to_have_count(1)
    time.sleep(0.6)
    with cap.open("ab") as f:
        f.write(bw.passthrough(0x4B, ts=time.time()))
    expect(page.locator(".trial[data-status='done']")).to_have_count(1, timeout=12000)
    expect(page.locator(".trial .findings")).to_contain_text("FORWARD (0x4B)")
    page.click(".trial details.pk summary")
    expect(page.locator(".trial table")).to_contain_text("PASS THROUGH 0x4B FORWARD")
    expect(page.locator(".trial table")).to_contain_text("قياسي")
    # a host-side action goes through MPRIS (whitelisted), never raw Bluetooth
    page.click('button[data-research="host"][data-action="next"]')
    expect(page.locator(".trial")).to_have_count(2)
    page.click('[data-dtab="matrix"]')
    expect(page.locator("#matrix-table tbody tr", has_text="التالي/السابق من السماعة")).to_contain_text("مؤكدة")
    assert not page.problems, page.problems


def test_discovery_mobile_layout(browser, env):  # noqa: F811
    page = open_page(browser, env, 390, 844, route="discovery")
    for tab in ("matrix", "services", "profiles", "research", "dlog"):
        page.click(f'[data-dtab="{tab}"]')
        expect(page.locator(f'[data-dpanel="{tab}"]')).to_be_visible()
        assert no_overflow(page), tab
    box = page.locator("#btn-safe-scan").bounding_box()
    assert box["height"] >= 48 and box["width"] > 300
    assert not page.problems, page.problems
