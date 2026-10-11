"""Структурная проверка окна кассы: стиль, цвета, живое содержимое.

Скриншот снимается отдельно, но «классичность» кнопок и тёмный фон удобнее
проверять свойствами виджетов — это воспроизводимо и запускается в тесте.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import main as m  # noqa: E402
from ui.app import CashRegisterApp  # noqa: E402


def _buttons(root):
    out = []

    def walk(w):
        for child in w.winfo_children():
            cls = child.winfo_class()
            if cls == "Button":
                out.append(child)
            walk(child)

    walk(root)
    return out


def _text_widgets(root):
    out = []

    def walk(w):
        for child in w.winfo_children():
            if child.winfo_class() == "Text":
                out.append(child)
            walk(child)

    walk(root)
    return out


def main() -> int:
    ns = type("Ns", (), {"self_test": False, "dump": None})()
    backend = m.make_backend("demo51", ns)

    holder = {}

    def on_quit():
        if holder:
            holder["root"].quit()

    app = CashRegisterApp(backend, title="ЭТИМ — Касса", on_quit=on_quit)
    root = getattr(app, "root", None)
    holder["root"] = root
    root.update_idletasks()
    root.update()

    print("== window ==")
    print("  title      :", root.title())
    print("  geometry   :", root.geometry())
    print("  bg         :", root.cget("bg"))

    buttons = _buttons(root)
    print("\n== buttons ==")
    print("  count      :", len(buttons))
    reliefs = {}
    bds = {}
    colors = {}
    faces = {}
    for b in buttons:
        reliefs[b.cget("relief")] = reliefs.get(b.cget("relief"), 0) + 1
        bds[str(b.cget("bd"))] = bds.get(str(b.cget("bd")), 0) + 1
        fg = str(b.cget("bg"))
        colors[fg] = colors.get(fg, 0) + 1
        faces[str(b.cget("fg"))] = faces.get(str(b.cget("fg")), 0) + 1
    print("  relief     :", reliefs)
    print("  borderwidth:", bds)
    print("  face colors:", dict(sorted(colors.items(), key=lambda kv: -kv[1])))
    print("  text colors:", dict(sorted(faces.items(), key=lambda kv: -kv[1])))
    sample = buttons[0] if buttons else None
    if sample is not None:
        print("  sample     : text=%r relief=%s bd=%s w=%d h=%d" % (
            str(sample.cget("text"))[:18], sample.cget("relief"),
            sample.cget("bd"), sample.winfo_width(), sample.winfo_height()))
    squeezed = [str(b.cget("text"))[:14] for b in buttons
                if b.winfo_width() < 30 or b.winfo_height() < 18]
    print("  degenerate :", squeezed[:8])

    print("\n== screen ==")
    screen = getattr(app, "screen", None)
    if screen is not None:
        print("  class      :", type(screen).__name__)
        for attr in ("text", "value", "chars", "state"):
            if hasattr(screen, attr):
                val = getattr(screen, attr)
                print("  %-10s: %r" % (attr, val() if callable(val) else val))
    print("  backend    :", repr(backend.display.text()))

    print("\n== receipt (before pressing keys) ==")
    texts = _text_widgets(root)
    print("  Text widgets:", len(texts))
    for t in texts:
        content = t.get("1.0", "end")
        print("   first line:", repr(content.split("\n")[0][:60]))

    # дать прошивке проснуться: самопроверка и первое обновление индикатора
    backend.run_budget(400_000)
    app.refresh()
    root.update_idletasks()
    root.update()
    print("\n== after boot ==")
    print("  display    :", repr(backend.display.text()))

    # прокрутить эмуляцию и нажать клавиши через тот же объект, что и UI
    for key in ("5", "0", "0"):
        backend.keyboard.press(key)
        backend.run_budget(40_000)
        backend.keyboard.release(key)
        backend.run_budget(20_000)
    app.refresh()
    root.update_idletasks()
    root.update()
    print("\n== after 5,0,0 ==")
    print("  display    :", repr(backend.display.text()))
    if screen is not None and hasattr(screen, "text"):
        val = screen.text() if callable(screen.text) else screen.text
        print("  widget text:", repr(val))

    # Нажать кнопку так, как нажал бы пользователь: Tk вызывает её command,
    # то есть проверяется вся цепочка кнопка -> клавиатура -> плата -> экран.
    clicked = None
    for b in buttons:
        if str(b.cget("text")).strip() == "СУММА":
            clicked = b
            break
    if clicked is None:
        print("\n!! кнопка СУММА не найдена среди", len(buttons))
    else:
        before = backend.printer.paper()
        clicked.invoke()
        root.update_idletasks()
        root.update()
        backend.run_budget(150_000)
        app.refresh()
        root.update_idletasks()
        root.update()
        after = backend.printer.paper()
        print("\n== after invoking the СУММА button ==")
        print("  display    :", repr(backend.display.text()))
        print("  receipt    :", len(before), "->", len(after), "lines")
        for line in after[:5]:
            print("    |", line)

    print("\n== text widgets after ==")
    for t in _text_widgets(root):
        content = t.get("1.0", "end")
        lines = [l for l in content.split("\n") if l.strip()]
        print("   filled lines:", len(lines), "| first:", repr(lines[0][:60]) if lines else "")

    root.destroy()
    print("\nOK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
