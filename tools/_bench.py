# -*- coding: utf-8 -*-
"""Бенчмарк/профиль производительности GUI-пути (не для тестов).

Запуск:  python tools/_bench.py

Что меряет:
1. скорость ``runner.advance`` (recovered) и ``cpu.run`` (demo51) — циклов/с;
2. латентность ``display.text()``/``status()`` ПОКА крутится фоновый
   поток эмуляции (это то, что видно пользователю как тормоза окна);
3. top-15 cProfile по циклам recovered-пути.
"""
from __future__ import annotations

import argparse
import cProfile
import io
import pstats
import sys
import threading
import time

ROOT = __file__.rsplit("\\", 2)[0].rsplit("/", 2)[0]
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import main as m  # noqa: E402


def _args(backend: str):
    return argparse.Namespace(
        backend=backend, dump=None, firmware=None, self_test=False,
        headless=None, list=False, selftest=False, demo=False, slow=False,
        cycles=None, duration=0.0,
    )


def bench_throughput(label: str, run_fn, budget: int, rounds: int) -> float:
    t0 = time.perf_counter()
    for _ in range(rounds):
        run_fn(budget)
    dt = time.perf_counter() - t0
    cps = rounds * budget / dt
    print(f"{label}: {cps:,.0f} циклов/с ({rounds}x{budget} за {dt:.2f}s)")
    return cps


def bench_contention(backend_name: str) -> None:
    """Латентность обращений UI, пока фон крутит эмуляцию."""
    # В GUI main.py вызывает tune_gil_for_gui() -> setswitchinterval(0.0005).
    # Без этого секция меряет дефолтные 5 мс ожидания GIL, а не поведение
    # настоящего окна (значения выше целевых были артефактом настройки).
    sys.setswitchinterval(0.0005)
    backend = m.make_backend(backend_name, _args(backend_name))
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            backend.run_budget(5_000)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    lat_text, lat_status = [], []
    for _ in range(60):
        t = time.perf_counter()
        backend.display.text()
        lat_text.append(time.perf_counter() - t)
        t = time.perf_counter()
        backend.status()
        lat_status.append(time.perf_counter() - t)
        time.sleep(0.02)
    stop.set()
    th.join(timeout=2)

    def pct(xs, p):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(len(xs) * p))]

    print(
        f"{backend_name}: латентность UI во время эмуляции — "
        f"display.text() p50={pct(lat_text, .5)*1000:.1f}ms "
        f"p95={pct(lat_text, .95)*1000:.1f}ms; "
        f"status() p50={pct(lat_status, .5)*1000:.1f}ms "
        f"p95={pct(lat_status, .95)*1000:.1f}ms"
    )


def bench_profile() -> None:
    backend = m.make_backend("recovered", _args("recovered"))
    prof = cProfile.Profile()
    prof.enable()
    for _ in range(40):
        backend.run_budget(10_000)
    prof.disable()
    s = io.StringIO()
    pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(15)
    print(s.getvalue())


if __name__ == "__main__":
    print("=== 1. пропускная способность ===")
    rec = m.make_backend("recovered", _args("recovered"))
    bench_throughput("recovered.advance", rec.run_budget, 50_000, 40)
    demo = m.make_backend("demo51", _args("demo51"))
    bench_throughput("demo51.run      ", demo.run_budget, 50_000, 40)
    print("=== 2. латентность UI под нагрузкой ===")
    bench_contention("recovered")
    bench_contention("demo51")
    if "--profile" in sys.argv:
        print("=== 3. cProfile recovered ===")
        bench_profile()
