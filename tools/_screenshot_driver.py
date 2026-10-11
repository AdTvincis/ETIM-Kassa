"""Поднять кассу, нажать несколько клавиш и держать окно открытым.

Используется для снятия скриншота (см. ``tools/_take_screenshot.ps1``):
скрипт сам закрывает окно по истечении ``--hold`` секунд, поэтому снимок
гарантированно попадает на заполненное состояние.
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import main as m  # noqa: E402
from ui.app import CashRegisterApp  # noqa: E402


def _root_of(app):
    import tkinter as tk

    root = getattr(app, "root", None) or getattr(app, "master", None)
    return root or tk._default_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="demo51")
    ap.add_argument("--hold", type=float, default=45.0)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--keys", default="5,0,0,СУММА,ОПЛ")
    args = ap.parse_args()

    ns = type("Ns", (), {"self_test": args.self_test, "dump": None})()
    backend = m.make_backend(args.backend, ns)

    holder: dict = {"root": None}

    def on_quit() -> None:
        if holder["root"] is not None:
            holder["root"].quit()

    app = CashRegisterApp(backend, title="ЭТИМ — Касса", on_quit=on_quit)
    root = _root_of(app)
    holder["root"] = root
    app.refresh()
    root.update_idletasks()
    root.update()

    for key in [k.strip() for k in args.keys.split(",") if k.strip()]:
        backend.keyboard.press(key)
        backend.run_budget(40_000)
        backend.keyboard.release(key)
        backend.run_budget(20_000)
        app.refresh()
        root.update_idletasks()
        root.update()

    app.refresh()
    root.update_idletasks()
    root.update()
    print("display:", repr(backend.display.text()), flush=True)
    print("receipt lines:", len(backend.printer.paper()), flush=True)

    root.after(int(args.hold * 1000), root.quit)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
