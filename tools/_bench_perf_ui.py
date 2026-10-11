# -*- coding: utf-8 -*-
"""SCRATCH (perf-ui): latency of UI reads + app.refresh() while emulation runs.

Run:  python tools/_bench_perf_ui.py [--no-gui]

Measures, with a background EmulationThread (the real GUI pacing loop):
  * backend.display.text()      p50/p95/max
  * backend.printer.paper()     p50/p95/max
  * backend.status()            p50/p95/max
  * app.refresh()               p50/p95/max   (only if Tk available)
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import main as m  # noqa: E402


def _args(backend: str):
    return argparse.Namespace(
        backend=backend, dump=None, firmware=None, self_test=False,
        headless=None, list=False, selftest=False,
    )


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def report(label, xs):
    print("  %-22s p50=%6.2fms  p95=%6.2fms  max=%6.2fms  n=%d" % (
        label, pct(xs, .5) * 1000, pct(xs, .95) * 1000,
        max(xs) * 1000, len(xs)))


def sample(fn, count, interval=0.02):
    out = []
    for _ in range(count):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
        time.sleep(interval)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="recovered")
    ap.add_argument("--samples", type=int, default=80)
    ap.add_argument("--no-gui", action="store_true")
    ns = ap.parse_args()

    # те же условия, что в main.run_gui: короткий GIL-switch для Tk
    m.tune_gil_for_gui()

    backend = m.make_backend(ns.backend, _args(ns.backend))
    thread = m.EmulationThread(backend)
    thread.start()
    time.sleep(0.3)  # let it warm up

    print("=== UI reads while EmulationThread runs (%s) ===" % ns.backend)
    report("display.text()", sample(lambda: backend.display.text(), ns.samples))
    report("printer.paper()", sample(lambda: backend.printer.paper(), ns.samples))
    report("status()", sample(lambda: backend.status(), ns.samples))

    app = None
    if not ns.no_gui:
        try:
            import tkinter  # noqa: F401
            from ui.app import CashRegisterApp
            app = CashRegisterApp(backend, title="bench")
            app.root.withdraw()
            app.stop_auto_refresh()  # как в run_gui: темп задаёт хост
        except Exception as exc:
            print("  (GUI unavailable: %r)" % (exc,))
            app = None

    if app is not None:
        print("=== app.refresh() while EmulationThread runs ===")
        xs = []
        for _ in range(ns.samples):
            t = time.perf_counter()
            app.refresh()
            xs.append(time.perf_counter() - t)
            time.sleep(0.02)
        report("app.refresh()", xs)
        # idle refresh (no load) for comparison
        thread.stop()
        thread.join(timeout=2.0)
        xs = []
        for _ in range(40):
            t = time.perf_counter()
            app.refresh()
            xs.append(time.perf_counter() - t)
        report("app.refresh() idle", xs)
        try:
            app.quit()
        except Exception:
            pass
    else:
        thread.stop()
        thread.join(timeout=2.0)

    frames = thread.frames
    print("  emulation frames: %d, errors: %r" % (frames, thread.errors[:3]))
    print("  mean refresh interval check: frames=%d" % frames)


if __name__ == "__main__":
    main()
