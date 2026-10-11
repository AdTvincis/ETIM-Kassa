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

## 6. Проводка (WIRING): INT0 — линия отключения питания, а не клавиатура

По умолчанию плата **не** поднимает `INT0` по нажатию клавиши
(`WIRING["INT0_ON_KEYPRESS"] = False` в `board/cashboard.py`).
Доказательство — настоящий обработчик вектора `INT0` в прошивке
(CPU `0x0003` → `LJMP 0x04D1`, после rebasing это запись `0x84D1`;
расшифровка байтов `firmware/nm27c512n.hex`):

* `CLR EA` — прерывания выключаются сразу;
* `MOV DPH,#A2h / MOV A,#08h / MOVX @DPTR,A` — сетка гасится (окно `0xA2xx`);
* `MOV DPTR,#BD1h / MOV R0,#7Fh / MOV A,@R0 / MOVX @DPTR,A / INC DPTR /
  DJNZ R0` — вся внутренняя RAM `0x00..0x7F` сохраняется во внешнюю память
  начиная с адреса `0x0BD1`;
* `MOV P2,#83h / MOV R0,#3Ch / MOV A,#55h / MOVX @R0,A / INC R0 / CPL A /
  MOVX @R0,A` — магические байты `55 AA` пишутся в батарейную область
  страницы `0x83xx`;
* `LJMP 04DFh`, где `04DF: SJMP 04DFh` — **вечный самоперехват**: касса
  «засыпает» навсегда.

То есть `INT0` — это линия POWER-FAIL/выключения: при прежнем значении
`True` обычное нажатие клавиши вешало настоящую прошивку. Механизм импульса
сохранён и включается только явно:
`CashRegisterBoard(wiring={"INT0_ON_KEYPRESS": True})` — так делают тесты
платы (один одноразовый импульс на событие клавиши, длина
`INT0_HOLD_CYCLES`; см. `irq_requested()` в `board/cashboard.py`).
Сторона UI на `INT0` **не** полагается: интерфейс работает только с
`display` / `keyboard` / `printer` (§§1–5).

## 7. Изменения контракта

Только через владельца `hal-ppi`; при изменении обновить и этот файл.
