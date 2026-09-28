"""End-to-end UI tests in Chromium against the agent + TEST-ONLY mock BlueZ/MPRIS."""

import re
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME if Path(CHROME).exists() else None,
                              args=["--disable-background-networking", "--disable-component-update"])
        yield b
        b.close()


def open_page(browser, env, width=1440, height=960, route="dashboard"):
    page = browser.new_page(viewport={"width": width, "height": height})
    page.problems = []
    page.on("console", lambda m: page.problems.append(m.text) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: page.problems.append(str(e)))
    page.on("dialog", lambda d: d.accept())
    page.goto(f"{env.base}/#/{route}")
    expect(page.locator("#agent-status")).to_have_attribute("data-state", "online")
    return page


def no_overflow(page):
    return page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")


def test_dashboard_controls_desktop(browser, env):
    page = open_page(browser, env)
    assert page.evaluate("document.documentElement.dir") == "rtl"
    assert page.evaluate("getComputedStyle(document.querySelector('main')).direction") == "rtl"
    expect(page.locator("#conn-label")).to_have_text("متصل")
    expect(page.locator("#bat-value")).to_have_text("70%")
    expect(page.locator("#bat-level")).to_have_text("جيدة")
    expect(page.locator("#vol-value")).to_have_text("100%")
    expect(page.locator("#play-state")).to_have_text("متوقف مؤقتًا")
    expect(page.locator("#btn-mute")).to_be_disabled()

    page.click("#btn-play")
    expect(page.locator("#play-state")).to_have_text("يعمل الآن")
    assert env.status()["media"]["status"] == "playing"  # real backend state, not UI state
    page.click("#btn-pause")
    expect(page.locator("#play-state")).to_have_text("متوقف مؤقتًا")
    assert env.status()["media"]["status"] == "paused"

    page.eval_on_selector("#vol-slider", "el => { el.value = 40; el.dispatchEvent(new Event('input', {bubbles: true})); el.dispatchEvent(new Event('change', {bubbles: true})); }")
    page.wait_for_function("() => document.querySelector('#vol-verify').textContent.includes('متحقق')")
    assert env.status()["volume"]["raw"] == 51
    expect(page.locator("#vol-value")).to_have_text("40%")
    page.click("#btn-vol-up")
    expect(page.locator("#vol-value")).to_have_text("46%")

    # headset-originated / external changes arrive live over the WebSocket
    env.mock_call("SetBattery", "int32:12")
    expect(page.locator("#bat-value")).to_have_text("12%")
    expect(page.locator("#bat-level")).to_have_text("حرجة")
    env.mock_call("SetVolume", "uint16:120")
    expect(page.locator("#vol-value")).to_have_text("94%")
    expect(page.locator("#recent-events")).to_contain_text("تغير مستوى الصوت إلى 94%")
    assert no_overflow(page)
    assert not page.problems, page.problems


def test_disconnect_reconnect_and_bluetooth_off(browser, env):
    page = open_page(browser, env)
    env.mock_call("SetConnected", "boolean:false")
    expect(page.locator("#conn-label")).to_have_text("غير متصل")
    expect(page.locator("#vol-slider")).to_be_disabled()
    expect(page.locator("#btn-vol-up")).to_be_disabled()
    expect(page.locator("#bat-level")).to_have_text("غير معروفة")
    expect(page.locator("#btn-reconnect-label")).to_have_text("اتصال")
    page.click("#btn-reconnect")
    expect(page.locator("#conn-label")).to_have_text("متصل")
    expect(page.locator("#vol-slider")).to_be_enabled()

    env.mock_call("SetPowered", "boolean:false")
    expect(page.locator("#banners")).to_contain_text("Bluetooth متوقف على هذا الجهاز")
    expect(page.locator("#btn-reconnect")).to_be_disabled()
    expect(page.locator("#reconnect-hint")).to_have_text("Bluetooth غير متاح على هذا الجهاز")
    assert not page.problems, page.problems


def test_agent_offline(browser, env):
    page = open_page(browser, env)
    env.stop_agent()
    expect(page.locator("#banners")).to_contain_text("تعذر الوصول إلى الوكيل المحلي")
    expect(page.locator("#btn-play")).to_be_disabled()
    expect(page.locator("#vol-slider")).to_be_disabled()
    expect(page.locator("#conn-label")).to_have_text("غير معروف")


def test_log_diagnostics_advanced(browser, env):
    page = open_page(browser, env, route="log")
    expect(page.locator("#log-list li").first).to_be_visible()
    with page.expect_download() as dl:
        page.click("#btn-export-json")
    assert dl.value.suggested_filename.startswith("necklace-log-")
    page.click("#btn-clear-log")
    expect(page.locator("#log-list li")).to_have_count(1)
    expect(page.locator("#log-list")).to_contain_text("تم مسح السجل")

    page.goto(f"{env.base}/#/diagnostics")
    hid = page.locator("#diag-list li", has_text="HID")
    expect(hid).to_contain_text("معلن في SDP، لكن لم يتم تأكيد تبادل HID reports")
    expect(hid).to_contain_text("غير معروف")
    expect(page.locator("#diag-list li", has_text="JieLi")).to_contain_text("غير متاح")

    page.goto(f"{env.base}/#/advanced")
    expect(page.locator("#page-title")).to_have_text("التحكم المتقدم")
    features = page.locator(".feature")
    expect(features).to_have_count(7)
    for name in ("EQ", "Bass", "Treble", "Button Remapping", "Device Settings", "Firmware Information", "Firmware Update"):
        expect(page.locator(".feature", has_text=name)).to_have_count(1)
    for i in range(7):
        expect(features.nth(i)).to_have_attribute("aria-disabled", "true")
        expect(features.nth(i)).to_contain_text("لم يتم اكتشاف بروتوكول آمن لهذه الوظيفة بعد")
    assert page.locator("#view-advanced button, #view-advanced input, #view-advanced select").count() == 0
    assert not page.problems, page.problems


@pytest.mark.parametrize("width,height", [(390, 844), (360, 740), (820, 1180)])
def test_mobile_and_tablet_layout(browser, env, width, height):
    page = open_page(browser, env, width, height)
    assert no_overflow(page)
    expect(page.locator(".sidebar")).to_be_hidden()
    expect(page.locator("#tabbar")).to_be_visible()
    for sel in ("#btn-play", "#btn-pause"):
        box = page.locator(sel).bounding_box()
        assert box["height"] >= 64 and box["width"] >= 120, (sel, box)
    for sel in ("#btn-vol-up", "#btn-vol-down", "#btn-reconnect"):
        box = page.locator(sel).bounding_box()
        assert box["height"] >= 44 and box["width"] >= 44, (sel, box)
    if width < 640:
        # touch-first order: media controls come before volume, volume before battery, reconnect last
        y = {s: page.locator(s).bounding_box()["y"] for s in (".tile-media", ".tile-volume", ".tile-battery", "#btn-reconnect")}
        assert y[".tile-media"] < y[".tile-volume"] < y[".tile-battery"] < y["#btn-reconnect"], y
        expect(page.locator(".hero-visual")).to_be_hidden()
    for route in ("discovery", "device", "diagnostics", "log", "settings"):
        page.click(f'#tabbar a[data-route="{route}"]')
        expect(page.locator(f"#view-{route}")).to_be_visible()
        assert no_overflow(page), route
    assert not page.problems, page.problems


def test_settings_theme_and_player(browser, env):
    page = open_page(browser, env, route="settings")
    page.click('[data-theme-value="light"]')
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    page.reload()
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    page.select_option("#player-select", "org.mpris.MediaPlayer2.mockplayer")
    page.wait_for_function("() => document.querySelector('#toasts').textContent.includes('Mock Player')")
    assert env.status()["media"]["selected"] == "org.mpris.MediaPlayer2.mockplayer"
