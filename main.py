#!/usr/bin/env python3
"""ЭТИМ — касса. Точка входа.

Запускает эмуляцию кассы и интерфейс Tkinter:

    python main.py                       # GUI: рабочая касса (demo51, кнопки
                                         #   -> индикатор -> чек, по умолчанию)
    python main.py --backend recovered   # настоящая прошивка ETIM: бут + самотест
    python main.py --list                # что вообще доступно
    python main.py --selftest            # без окна: проверить, что всё грузится

Интерфейс: Tkinter, классические объёмные кнопки, тёмный фон
(см. docs/architecture.md, раздел «Требования к UI»).
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import traceback
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

#: Машинных циклов в секунду у эмулируемого кристалла (12 МГц / 12).
MACHINE_CYCLES_PER_SECOND = 1_000_000

BACKENDS = ("recovered", "etim", "demo51")


# --------------------------------------------------------------------- backends
class Backend:
    """Общий интерфейс для всех вариантов эмуляции.

    Интерфейс должен предоставлять ``display``/``keyboard``/``printer``
    (см. docs/board_contract.md), ``reset()``, ``status()`` и
    ``run_budget(cycles)``.
    """

    name = "base"
    description = ""

    display = None
    keyboard = None
    printer = None

    def reset(self) -> None:
        pass

    def run_budget(self, cycles: int) -> None:
        """Продвинуть эмуляцию не более чем на ``cycles`` машинных циклов."""

    def status(self) -> dict:
        return {}

    def shutdown(self) -> None:
        pass


class RecoveredBackend(Backend):
    """Восстановленный из декомпиляции код (recover/)."""

    name = "recovered"
    description = "Восстановленный код прошивки (Ghidra -> recover/)"

    def __init__(self, dump: Optional[str] = None) -> None:
        from recover.session import RecoveredFirmwareSession

        self.session = RecoveredFirmwareSession(**({"dump_path": dump} if dump else {}))
        # Фасады НЕ копируем: session.boot() внутри _refresh_facades()
        # подменяет их на новые объекты, и скопированные до boot() ссылки
        # останутся навсегда пустыми (экран и чек в GUI были бы пустыми,
        # а нажатия клавиш — no-op).  Свойства ниже всегда отдают живые
        # фасады текущей сессии.
        self.session.boot()

    @property
    def display(self):
        return self.session.display

    @property
    def keyboard(self):
        return self.session.keyboard

    @property
    def printer(self):
        return self.session.printer

    def run_budget(self, cycles: int) -> None:
        self.session.run(cycles)

    def status(self) -> dict:
        return dict(self.session.status())

    def reset(self) -> None:
        self.session.reset()
        self.session.boot()


class EmulatorBackend(Backend):
    """Настоящий эмулятор 8051 (m8051/) с платой кассы (board/)."""

    name = "etim"

    def __init__(self, profile: str = "etim", self_test: bool = False) -> None:
        from m8051 import CPU8051
        from m8051.firmware_profile import PROFILES, load_firmware
        from board.cashboard import CashRegisterBoard

        spec = PROFILES.get(profile) or PROFILES["etim"]
        self.profile = load_firmware(primary=str(spec["primary"]),
                                     secondary=spec.get("secondary"))
        try:
            self.board = CashRegisterBoard(self_test=self_test)
        except TypeError:
            self.board = CashRegisterBoard()
        self.cpu = CPU8051(self.profile.rom, self.board)
        self.cpu.pc = self.profile.reset_pc
        self.display = self.board.display
        self.keyboard = self.board.keyboard
        self.printer = self.board.printer
        self.description = self.profile.summary()

    def reset(self) -> None:
        self.cpu.reset()
        self.cpu.pc = self.profile.reset_pc

    def run_budget(self, cycles: int) -> None:
        # Прошивка после rebasing целиком лежит в нижних 32 КиБ; если бы
        # исполнение ушло в несданную верхнюю половину (0x8000..0xFFFF),
        # ``run`` остановил бы CPU сам с честным сообщением, поэтому цикл
        # ограничен и не может зависнуть.
        if self.cpu.halted:
            return
        self.cpu.run(cycles)

    def status(self) -> dict:
        state = self.cpu.state()
        return {
            "source": self.name,
            "cycles": state["cycles"],
            "pc": state["pc"],
            "ops": state["ops"],
            "halted": self.cpu.halted,
            "reason": self.cpu.error or "",
            "missing_pc": self.cpu.missing_pc,
            "reset_pc": self.profile.reset_pc,
            "missing_bytes": self.profile.missing_count(),
        }


class Demo51Backend(Backend):
    """Демонстрационная 8051-программа (firmware/demo/), работающая
    через ту же самую плату кассы. Является стенд-ином, а не оригинальной
    прошивкой — это всегда видно в строке состояния.
    """

    name = "demo51"
    description = "Демонстрационная 8051-программа (стенд-ин, не оригинал)"

    def __init__(self, self_test: bool = False) -> None:
        from m8051 import CPU8051, ROM
        from board.cashboard import CashRegisterBoard

        try:
            from firmware.demo import load_demo_image
            image = load_demo_image()
            base = 0x0000
        except Exception:
            image, base = self._fallback_image()
        self.rom = ROM("demo_cashier")
        self.rom.load_block(base, image)
        try:
            self.board = CashRegisterBoard(self_test=self_test)
        except TypeError:
            self.board = CashRegisterBoard()
        self.cpu = CPU8051(self.rom, self.board)
        self.cpu.pc = base
        self.display = self.board.display
        self.keyboard = self.board.keyboard
        self.printer = self.board.printer
        self.description = "демонстрационная 8051-программа (стенд-ин)"

    def _fallback_image(self):
        """Если assembler ещё не готов — минимальная программа на 8051.

        Пишет в P1 шаблон, чтобы на плате было видно движение, и не зависает.
        """
        from m8051.shim import build_shim

        base = 0x0000
        program = bytearray()
        program += bytes((0x75, 0x81, 0x30))       # MOV SP,#0x30
        loop_at = len(program)
        program += bytes((0x74, 0xAA))             # MOV A,#0xAA
        program += bytes((0xF5, 0x90))             # MOV P1,A
        program += bytes((0x74, 0x55))             # MOV A,#0x55
        program += bytes((0xF5, 0x90))             # MOV P1,A
        program += bytes((0x80, 0x00))             # SJMP $
        program[-1] = (loop_at - (len(program) + 1)) & 0xFF
        return bytes(program), base

    def reset(self) -> None:
        self.cpu.reset()

    def run_budget(self, cycles: int) -> None:
        if self.cpu.halted:
            return
        self.cpu.run(cycles)

    def status(self) -> dict:
        state = self.cpu.state()
        return {
            "source": "demo",
            "cycles": state["cycles"],
            "pc": state["pc"],
            "ops": state["ops"],
            "halted": self.cpu.halted,
            "reason": self.cpu.error or "",
        }


def make_backend(name: str, args) -> Backend:
    if name == "recovered":
        try:
            return RecoveredBackend(args.dump)
        except Exception as exc:
            print(f"[!] восстановленный бэкенд не поднялся: {exc}", file=sys.stderr)
            traceback.print_exc()
            raise
    if name == "demo51":
        return Demo51Backend(self_test=args.self_test)
    return EmulatorBackend(profile="etim", self_test=args.self_test)


# ------------------------------------------------------------------- runner
class EmulationThread(threading.Thread):
    """Крутит ``run_budget`` в фоне, удерживая реальное время.

    Эмулятор считает машинные циклы (1 МГц при кварце 12 МГц), а поток
    дозирует их по стенным часам, чтобы поведение кассы было похоже на
    настоящее, и чтобы интерфейс успевал перерисовываться.

    Темпинг (проверено замерами): ``cycles_per_budget`` = 20 000 циклов =
    20 мс эмулируемого времени за кадр.

    * ядро **быстрее** реального времени -> спим остаток кадра, ровно
      1M циклов/с настенных часах;
    * ядро **медленнее** -> ``delay <= 0`` и ``next_time`` сбрасывается на
      «сейчас»: накопленного долга и «погоняющих» серий ``run_budget``
      подряд не бывает - кадры идут просто один за другим;
    * между кадрами ``session.run()`` (recovered) отпускает замок на каждом
      срезе (:data:`recover.session.LOCK_SLICE_CYCLES`), поэтому даже
      непрерывная серия кадров не блокирует Tk-поток.
    """

    def __init__(self, backend: Backend, budget_ms: int = 20) -> None:
        super().__init__(daemon=True, name="emulation")
        self.backend = backend
        self.budget_ms = budget_ms
        self._stop = threading.Event()
        self.frames = 0
        self.errors: list = []

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        cycles_per_budget = max(1000, MACHINE_CYCLES_PER_SECOND * self.budget_ms // 1000)
        next_time = time.perf_counter()
        while not self._stop.is_set():
            try:
                self.backend.run_budget(cycles_per_budget)
            except Exception as exc:              # noqa: BLE001 - поток обязан жить
                self.errors.append(f"{type(exc).__name__}: {exc}")
                if len(self.errors) > 20:
                    self.errors.pop(0)
            self.frames += 1
            next_time += self.budget_ms / 1000.0
            delay = next_time - time.perf_counter()
            if delay > 0:
                self._stop.wait(min(delay, 0.05))
            else:
                next_time = time.perf_counter()


def run_headless(backend: Backend, seconds: float, verbose: bool = True) -> dict:
    """Прогон без окна — для проверки и отладки."""
    thread = EmulationThread(backend)
    thread.start()
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        time.sleep(0.1)
    thread.stop()
    thread.join(timeout=2.0)
    status = backend.status()
    if verbose:
        print("--- статус ---")
        for key in sorted(status):
            print(f"  {key}: {status[key]}")
        print(f"  кадров эмуляции: {thread.frames}, ошибок: {len(thread.errors)}")
        for err in thread.errors[:5]:
            print(f"    ! {err}")
        try:
            text = backend.display.text()
            print(f"  экран: {text!r}")
        except Exception as exc:                  # noqa: BLE001
            print(f"  экран недоступен: {exc}")
        try:
            paper = backend.printer.paper()
            print(f"  чек: {len(paper)} строк")
            for line in paper[-8:]:
                print(f"    | {line}")
        except Exception as exc:                  # noqa: BLE001
            print(f"  чек недоступен: {exc}")
    return {"status": status, "errors": list(thread.errors)}


#: Интервал переключения GIL для GUI-режима (сек).  См. tune_gil_for_gui().
GUI_GIL_SWITCH_INTERVAL = 0.0005


def tune_gil_for_gui() -> None:
    """Подготовить GIL к совместной работе Tk и потока эмуляции.

    Каждый вызов в Tcl (``StringVar.set``, канва, ``Text``) отпускает GIL, а
    после возвращения поток ждёт освобождения GIL от потока эмуляции до
    ``sys.getswitchinterval()`` - по умолчанию это до 5 мс **на каждый**
    Tcl-вызов.  Замер (tools/_bench_perf_ui.py): при 5 мс один refresh под
    нагрузкой стоил ~58 мс (3 вызова Tcl), полная перерисовка канвы
    индикатора - ~2.7 с (сотни ``create_rectangle``); при 0.5 мс - 0.25 мс и
    ~18 мс, а пропускная способность эмуляции не падает (~150К циклов/с).
    Короткий интервал делает GUI отзывчивым, не мешая фоновой эмуляции.
    """
    sys.setswitchinterval(GUI_GIL_SWITCH_INTERVAL)


def run_gui(backend: Backend) -> int:
    import tkinter as tk

    from ui.app import CashRegisterApp

    tune_gil_for_gui()

    root_holder: dict = {}

    def on_quit() -> None:
        thread.stop()

    app = CashRegisterApp(backend, title="ЭТИМ — Касса", on_quit=on_quit)
    # Один таймер обновления: темп задаёт хост (tick ниже), поэтому
    # внутренний таймер приложения выключаем - иначе refresh() выполнялся
    # бы дважды за интервал (двойной опрос платы и двойная работа Tk).
    app.stop_auto_refresh()
    thread = EmulationThread(backend)
    thread.start()

    root = getattr(app, "root", None) or getattr(app, "master", None) or tk._default_root
    if root is None:
        print("не удалось получить корневое окно Tk", file=sys.stderr)
        thread.stop()
        return 2
    root_holder["root"] = root

    # 50 мс: измеренный cost refresh() <= 1 мс (пока текст не менялся) и
    # <= ~3-5 мс при изменении - интервал менять незачем.
    def tick() -> None:
        try:
            app.refresh()
        except Exception as exc:                  # noqa: BLE001
            print(f"[!] refresh: {exc}", file=sys.stderr)
        root.after(50, tick)

    root.after(50, tick)
    try:
        app.run()
    finally:
        thread.stop()
        thread.join(timeout=2.0)
    return 0


# ---------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Эмулятор кассы «ЭТИМ» (AT89C55VD) с интерфейсом Tkinter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--backend", "-b", choices=BACKENDS, default="demo51",
        help="что запускать (по умолчанию: demo51 — рабочие кнопки/чек; "
             "recovered — настоящая прошивка ETIM, но её клавиатурный цикл "
             "ещё не восстановлен, см. docs/usage.md §4.3)",
    )
    parser.add_argument("--dump", default=None, help="путь к .c-дампу декомпиляции")
    parser.add_argument("--self-test", action="store_true",
                        help="плата сама показывает картинку и печатает чек")
    parser.add_argument("--headless", type=float, default=0.0, metavar="СЕК",
                        help="без окна: погонять эмуляцию N секунд и напечатать статус")
    parser.add_argument("--list", action="store_true", help="показать варианты и выйти")
    parser.add_argument("--selftest", action="store_true",
                        help="быстрая проверка, что все модули грузятся")
    return parser


def cmd_list() -> int:
    print("Варианты запуска (--backend):")
    for name in BACKENDS:
        print(f"  {name:<10} {_describe(name)}")
    print()
    try:
        from m8051.firmware_profile import available_images
        print("Образы прошивок в firmware/:")
        for image in available_images():
            print(f"  {image}")
    except Exception as exc:                      # noqa: BLE001
        print(f"  (не удалось перечислить: {exc})")
    return 0


def _describe(name: str) -> str:
    if name == "recovered":
        return "восстановленный декомпилированный код (recover/)"
    if name == "etim":
        return "эмулятор 8051 + дамп nm27c512n.hex"
    return "демонстрационная 8051-программа (стенд-ин)"


def cmd_selftest() -> int:
    ok = True
    checks = [
        ("m8051", lambda: __import__("m8051")),
        ("disasm", lambda: __import__("tools.disasm", fromlist=["x"])),
        ("recover.parse", lambda: __import__("recover.parse", fromlist=["x"])),
        ("recover.interp", lambda: __import__("recover.interp", fromlist=["x"])),
        ("board.cashboard", lambda: __import__("board.cashboard", fromlist=["x"])),
        ("ui.app", lambda: __import__("ui.app", fromlist=["x"])),
        ("recover.session", lambda: __import__("recover.session", fromlist=["x"])),
    ]
    for label, check in checks:
        try:
            check()
            print(f"  ok    {label}")
        except Exception as exc:                  # noqa: BLE001
            ok = False
            print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
    try:
        import tkinter
        _probe = tkinter.Tk()
        _probe.withdraw()               # никаких ВИДИМЫХ окон (заказ пользователя)
        _probe.destroy()
        print("  ok    tkinter (окно создаётся)")
    except Exception as exc:                      # noqa: BLE001
        print(f"  warn  tkinter: {exc} (графический режим недоступен)")
    return 0 if ok else 1


def _show_splash():
    """Мгновенное окно «загрузка…» для GUI-режима (до сборки бэкенда).

    ``make_backend("recovered")`` занимает ~2-3 с (разбор дампа прошивки:
    parse_body ~1.2 с, diagnose_consumers ~0.35 с, остальное - импорты и
    загрузка ROM), и раньше окно появлялось только ПОСЛЕ этой паузы -
    «запускаю - ничего не происходит».  Сплэш рисуется сразу и закрывается
    перед созданием основного окна (Tk не терпит два корневых окна).
    Никогда не бросает: без дисплея просто возвращается ``None``.
    """
    try:
        import tkinter as tk
    except Exception:                              # noqa: BLE001
        return None
    try:
        splash = tk.Tk()
        splash.title("ЭТИМ — Касса")
        bg = "#101010"
        splash.configure(bg=bg)
        width, height = 440, 130
        splash.geometry("%dx%d+%d+%d" % (
            width, height,
            max(0, (splash.winfo_screenwidth() - width) // 2),
            max(0, (splash.winfo_screenheight() - height) // 2),
        ))
        tk.Label(
            splash, text="КАССА «ЭТИМ»",
            bg=bg, fg="#d8d8a0", font=("TkDefaultFont", 16, "bold"),
        ).pack(pady=(24, 6))
        tk.Label(
            splash, text="загрузка прошивки…",
            bg=bg, fg="#7fc97f", font=("TkDefaultFont", 11),
        ).pack()
        splash.update_idletasks()
        splash.update()
        return splash
    except Exception:                              # noqa: BLE001
        return None


def _close_splash(splash) -> None:
    if splash is None:
        return
    try:
        splash.destroy()
    except Exception:                              # noqa: BLE001
        pass


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        return cmd_list()
    if args.selftest:
        return cmd_selftest()

    # GUI: окно «загрузка…» рисуем ДО дорогой сборки бэкенда
    splash = None if args.headless > 0 else _show_splash()
    try:
        backend = make_backend(args.backend, args)
    except Exception as exc:                      # noqa: BLE001
        _close_splash(splash)
        print(f"не удалось запустить '{args.backend}': {exc}", file=sys.stderr)
        print("попробуйте: python main.py --list", file=sys.stderr)
        print("или:       python main.py --backend demo51", file=sys.stderr)
        return 2

    # flush=True: при перенаправлении stdout (``python main.py > out.txt``)
    # буфер держит строку до выхода; печатаем сразу, чтобы лог запуска был
    # виден ещё до закрытия окна.
    print(f"бэкенд: {backend.name} — {getattr(backend, 'description', '')}",
          flush=True)
    _close_splash(splash)
    if args.headless > 0:
        result = run_headless(backend, args.headless)
        return 0 if not result["errors"] else 1
    return run_gui(backend)


if __name__ == "__main__":
    raise SystemExit(main())
