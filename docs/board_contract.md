# Протокол обмена: плата -> интерфейс (board.contract)

Этот документ фиксирует **единственный** интерфейс между эмуляцией железа
(`board/`, владелец: teammate `hal-ppi`) и интерфейсом Tkinter (`ui/`,
владелец: teammate `gui-tk`). Обе стороны обязаны следовать ему буквально.

## 1. Что плата отдаёт наружу

`board.cashboard.CashRegisterBoard` (наследник `m8051.bus.HardwareBus`)
предоставляет:

```python
board.display       # board.display.Display
board.keyboard      # board.keyboard.Keyboard
board.printer       # board.printer.ReceiptPrinter
```

## 2. Display

```python
class Display:
    columns: int              # число знакомест, напр. 20
    lines: int                # число строк (обычно 1 или 2)
    def text(self) -> str:
        """Текущее содержимое экрана, ровно columns*lines символов.
        Незажжённые знакоместа = пробел. Первая строка идёт первой."""

    def cell_segments(self, index: int) -> int:
        """Сырая маска сегментов знакоместа (для отладки), 0..255."""

    def render_rows(self, scale: int = 1) -> list[str]:
        """Список строк из символов '#', '.', ' ' для отрисовки без шрифта.
        Каждый символ знакоместа -> 5 колонок, 7 строк. Строк: lines*7."""
```

## 3. Keyboard

Клавиатура кассы — матрица. Tkinter-сторона **не знает** про строки/столбцы,
она нажимает клавиши по имени:

```python
class Keyboard:
    keys: list[str]           # все допустимые имена клавиш, в порядке раскладки
    def press(self, name: str) -> None:   # нажать (замкнуть контакт)
    def release(self, name: str) -> None: # отпустить
    def tap(self, name: str) -> None:     # press + release (для клика мышью)
    def is_pressed(self, name: str) -> bool
```

Обязательные имена клавиш (`keys` должен содержать их все):

```
"0".."9", ".", "00",
"СУММА"(SUMM), "ОПЛ"(PAY), "X"(MULT), "ITOG"(ИТОГ),
"ОТМЕНА"(CANCEL), "ВОЗВРАТ"(RETURN), "СКИДКА"(DISCOUNT),
"КАССИР"(CASHIER), "СЕРВИС"(SERVICE), "РЕЖИМ"(MODE),
"ВВОД"(ENTER), "СБРОС"(CLEAR), "ПОДЫТОГ"(SUBTOTAL),
"ЧЕК"(RECEIPT), "КС"(XREPORT), "Z"(ZREPORT), "ПИТ"(FEED),
"СТРЕЛКА_ВЛЕВО", "СТРЕЛКА_ВПРАВО", "ПРОБЕЛ", "ТАБ"
```

Допускается больше клавиш — `keys` остаётся источником правды, UI строит
раскладку по нему. Если какая-то клавиша не подключена физически, плата
всё равно принимает `press` без исключения (замыкание «в воздух»).

## 4. Printer

```python
class ReceiptPrinter:
    def feed(self, lines: int = 1) -> None
    def paper(self) -> list[str]      # все строки, что «напечатаны», сверху вниз
    def text(self) -> str             # paper(), склеенный через "\n"
    def clear(self) -> None
    def is_busy(self) -> bool         # True — принтер не готов принять байт
```

Плата обязана **всегда** держать принтер готовым (`is_busy() == False`) либо
снимать занятость по времени, чтобы прошивка не встала навсегда.

## 5. Что интерфейс вызывает

* `board.keyboard.tap(name)` — по клику мышью.
* `board.printer.paper()` / `board.printer.clear()` — для отрисовки и очистки чека.
* `board.display.text()` / `board.display.render_rows(scale)` — для отрисовки экрана.

Интерфейс **не** вызывает и не читает ничего из `board/` кроме перечисленного
(плюс `board.status_text()` — необязательная строка состояния, если реализована).

## 6. Изменения контракта

Только через владельца `hal-ppi`; при изменении обновить и этот файл.
