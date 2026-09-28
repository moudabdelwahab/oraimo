"""TEST-ONLY: render the UI against the mock and save screenshots (python -m tests.screenshots OUTDIR)."""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

from tests.harness import Env

CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome"


def main(out: Path, pages=("dashboard",)):
    out.mkdir(parents=True, exist_ok=True)
    env = Env(); env.start_mock(); env.start_agent()
    errors = []
    try:
        env.post("/api/volume", {"percent": 72})
        with sync_playwright() as p:
            b = p.chromium.launch(executable_path=CHROME if Path(CHROME).exists() else None, args=["--disable-background-networking", "--disable-component-update"])
            for name, vp in [("desktop", (1440, 960)), ("tablet", (900, 1200)), ("mobile", (390, 844))]:
                pg = b.new_page(viewport={"width": vp[0], "height": vp[1]})
                pg.on("console", lambda m, n=name: errors.append(f"{n} console {m.type}: {m.text}") if m.type in ("error", "warning") else None)
                pg.on("pageerror", lambda e, n=name: errors.append(f"{n} pageerror: {e}"))
                for view in pages:
                    pg.goto(f"{env.base}/#/{view}")
                    pg.wait_for_selector('#conn-pill[data-state="connected"]', timeout=8000, state="attached")
                    pg.wait_for_timeout(700)
                    pg.screenshot(path=str(out / f"{name}-{view}.png"), full_page=True)
                    sw = pg.evaluate("document.documentElement.scrollWidth")
                    cw = pg.evaluate("document.documentElement.clientWidth")
                    print(name, view, "overflow" if sw > cw else "ok", sw, cw)
            b.close()
    finally:
        env.stop()
    print("\n".join(errors) or "no console errors")


if __name__ == "__main__":
    main(Path(sys.argv[1]), tuple(sys.argv[2:]) or ("dashboard",))
