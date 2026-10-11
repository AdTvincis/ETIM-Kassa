# Восстановление прошивки: конвейер, статистика, ограничения

> Источники — **только** два файла проекта:
> * `docs/nm27c512n_decompiled.c` — псевдо-C из Ghidra (16 721 строка, 516 961 байт, CRLF);
> * `firmware/nm27c512n.hex` — байты ПЗУ (32 768 байт; записи hex лежат по
>   смещениям программатора `0x8000..0xFFFF`, сама картинка — нижние 32 КиБ
>   CPU `0x0000..0x7FFF`, см. «Две сетки адресов» в `docs/architecture.md`).
>
> Никаких внешних источников. Все числа ниже получены запуском команд из корня
> репозитория с `PYTHONUTF8=1`; инструменты используют только стандартную
> библиотеку Python. Статистика приведена **после** фикса `_SIG_RE` (см. §6.1).

Связанные документы: `docs/architecture.md` — устройство проекта целиком,
`docs/hardware_evidence.md` — что именно код доказывает о железе кассы.

---

## 1. Что вообще восстанавливается

| Факт | Значение | Как проверить |
| --- | --- | --- |
| Сохранившаяся картинка ПЗУ | нижние 32 КиБ CPU `0x0000..0x7FFF` (32768 байт; записи hex — `0x8000..0xFFFF`, при загрузке сдвигаются на `−0x8000`) | `firmware/nm27c512n.hex` + `m8051/firmware_profile.py` (`_rebase_low32k`) |
| Вектор сброса | запись `0x8000` = CPU `0x0000`: `LJMP 0x0A06`; цель (запись `0x8A06`) внутри картинки — очистка внутренней RAM | дизассемблер `tools/disasm.py` |
| Чего нет | верхняя половина CPU `0x8000..0xFFFF` — она выходит за пределы файла | `python main.py --backend etim --headless 3` (`missing_bytes: 32768`) |
| «Родная» прошивка стартует? | **Да** на ядре `m8051`: `--backend etim` крутится от настоящего вектора (проверено: `--headless 3` → 400 004 цикла, `halted: False`); статус псевдокодного конвейера `recovered` зависит от `recover/session.py` | `status()["reason"]` |

> Артефакт `MISSING_RANGES = [[0, 32767]]` в
> `docs/recovered/firmware_recovered.py` генерируется `recover/emit.py`,
> который ещё работает в сетке записей: после его миграции артефакт
> перегенерируют, и отсутствующей станет верхняя половина `0x8000..0xFFFF`.

Отсюда следует главный принцип пакета `recover/`: исполняется только то, что
подтверждено байтами дампа (после rebasing — CPU `0x0000..0x7FFF`); всё
остальное не «дорисовывается», а явно отклоняется (`MissingFirmware`).

---

## 2. Конвейер: псевдо-C Ghidra → AST → интерпретатор / эмиттер

Четыре стадии, все в пакете `recover/`; CLI — `tools/recover_firmware.py`.

| Стадия | Модуль | Что делает |
| --- | --- | --- |
| 1. Разбор дампа | `recover/parse.py` | делит текст на **глобальные объявления** и **определения функций**; тело находит балансировкой скобок с учётом строковых/символьных литералов; адрес берётся из имени `FUN_CODE_810f` / `thunk_FUN_CODE_b904`; признак заглушки — наличие `halt_baddata()` в теле |
| 2. AST | `recover/cparse.py` | собственный токенизатор + рекурсивный спуск; выражения и все операторы C (`if/while/do/for/switch/case/goto/label/break/continue/return`), объявления локальных, приведения типов |
| 3. Исполнение | `recover/interp.py` | **интерпретатор** AST (не генерированный Python) поверх модели 8051 `recover/namespace.py`; память — прокси-объекты, поэтому код читает/пишет то же состояние, что и эмулятор `m8051/` |
| 3′. Помощники | `recover/runtime.py` | интринсики Ghidra (`CONCAT11`, `SUB41`, `ZEXT14`, `CARRY1`, `SEXT`, `nop`) как чистая битовая арифметика; разрешение `func_0xNNNN` и «чужих» `goto` во время выполнения |
| 4. Эмиттер | `recover/emit.py` | тот же дамп → два читаемых артефакта (§3.2) |

Почему интерпретатор, а не транспляция в Python (`recover/interp.py:3-11`):

* в восстановленном коде есть `goto` **в середину другой функции**;
* набор переменных декомпилятора динамичен (`uVar7` — байт в одной функции и
  указатель в другой);
* только на этапе исполнения можно честно сказать «этот адрес не покрыт ни одним
  дампом» и бросить `MissingFirmware` с точным адресом, вместо тихого вымысла.

Модель исполнения формализована в докстринге `recover/interp.py:17-42`:
кадр `_Frame` = список операторов + курсор, курсор двигается **до**
диспетчеризации; `while`/`for` проверяют условие до первого прохода
(`_enter_loop`) и после каждого тела (`_loop_tail`), `break` снимает внутренний
кадр цикла **или** `switch`, `continue` дорабатывает тело; каждая метка хранится
как `(список операторов, индекс)` + родитель, поэтому `goto` умеет разворачивать
стек кадров.

### 2.1 Слои вокруг интерпретатора

| Модуль | Роль |
| --- | --- |
| `recover/namespace.py` | модель 8051: SFR (`SFR_NAMES`), битовые ячейки (`BitAddress`), внутренняя RAM, внешняя память, `xdata_hooks`, `missing_calls`, `provenance()` |
| `recover/hal.py` | мост к эмуляции кассы: таблица `EVIDENCE` (адрес → свидетельство), устройствовые страницы, `CashRegisterHAL`, `sync_inputs()`, `PIN_ALIASES`, `bit_aliases_from_globals()` |
| `recover/session.py` | потокобезопасный драйвер для `main.py`: `boot()` / `run(cycles)` / `status()`; `source = "recovered"` только когда периферию реально двигает восстановленный ISR `FUN_CODE_8135` |
| `recover/errors.py` | `MissingFirmware`, `XdataUnmapped`, `BadDecompilation` |

### 2.2 Правила честности (заявлены в коде и соблюдаются)

1. Ничего не выдумывается, чтобы число «выглядело правильно».
2. Каждый адрес/бит, которого касается восстановленный код, либо подтверждён
   данными, либо отвечает `MissingFirmware`.
3. `provenance(addr)` позволяет спросить: реальное ПЗУ / другой дамп /
   сгенерированная заглушка / отсутствует.
4. Заглушки (`halt_baddata`) помечаются `stub` и **никогда** не называются
   «восстановленными».

---

## 3. Что восстановлено: статистика

### 3.1 Сводка по дампу

Получено `report` + `parse_dump()` + `scan_raw_functions()` + подсчётом по файлу
(состояние **после** фикса `_SIG_RE`, см. §6.1).

| Показатель | Значение |
| --- | --- |
| Строк в дампе / байт | 16 721 / 516 961 |
| Определений функций в первой колонке | **128** |
| Распознано `recover/parse.py` | **128 из 128** (до фикса было 123) |
| Исполняемых тел (`recovered` + `partial`) | **127 из 127** (`report`: `bodies parsed: 127/127 runnable functions (recovered + partial; stubs are refused at entry)`) |
| Разбивка статусов (`report`) | **57** `recovered` + **70** `partial` + **1** `stub` = 128 |
| Функций с `halt_baddata()` в теле | **71** = 70 `partial` + 1 `stub` (до фикса `_SIG_RE` их было 66) |
| Вызовов `halt_baddata()` всего | 216 |
| Комментариев `// WARNING:` | 593 |
| Глобальных объявлений | **361** (разбивка ниже) |
| Всего `;` в телах функций | 10 999 |
| Параметров суммарно | 671 |
| Вызовов `func_0xNNNN` | 756 (168 различных адресов) |
| — из них с целью в CPU `0x0000..0x7FFF` (байты в дампе: `запись = цель + 0x8000`) | **692** |
| — из них с целью в CPU `0x8000..0xFFFF` (верхняя половина, этих байтов в дампе нет) | 64 |
| Идентификаторов, которые вызываются, но нигде не определены | 175 (все — `func_0xNNNN` плюс интринсики `CARRY1`/`CONCAT11`/`SUB21`/`ZEXT12`/`nop`/`halt_baddata`/`decimal_adjust`) |
| Диапазон адресов `recovered`-функций (записи Ghidra) | `0x810F .. 0xFF59` |
| Диапазон адресов `partial`; чистый `stub` | `0x8D00 .. 0xFFE9`; `stub` один — `FUN_CODE_8139` |

> **Почему «восстановлено» осталось 57, а не стало 62.** Пять функций, которые
> `_SIG_RE` раньше терял (`FUN_CODE_ea4f`, `thunk_FUN_CODE_ea4f`,
> `FUN_CODE_f80d`, `FUN_CODE_f87d`, `FUN_CODE_feff`), сами оказались
> неразбираемыми до конца — в их телах есть `halt_baddata()`. Фикс поднял
> `functions` 123 → 128; число исполнимых тел не изменилось. (Тогда же
> показатели «содержит `halt_baddata()`» — 66 → 71 — позже `emit` разделил на
> `partial` 70 и `stub` 1; их сумма та же.) Побочный эффект: `report` и
> артефакты теперь дают одинаковые цифры.

Разбивка 361 глобального объявления:

| Категория | Штук | Примеры |
| --- | --- | --- |
| `DAT_INTMEM_xx` — внутренняя RAM | 115 | `DAT_INTMEM_3e`, `DAT_INTMEM_20` |
| `DAT_EXTMEM_xxxx` — внешняя память | 12 (10 уникальных) | `DAT_EXTMEM_000b`, `DAT_EXTMEM_0c7a` |
| `DAT_SFR_xx` — SFR без известного имени | 23 | `DAT_SFR_92`, `DAT_SFR_c2` |
| Битовые ячейки `XX.Y` | 62 | `22.1`, `P1.3`, `27.4`, `F8.0` |
| Имена SFR/выводов | 92 | `TCON`, `TL1`, `CMOD`, `P1`, `RXD` |
| Метки и регистры банков | 53 | `BANK3_R7`, `LAB_CODE_b46c`, `UNK_CODE_00fe` |
| `DAT_CODE_xxxx` — байт ПЗУ | 2 | `DAT_CODE_8299`, `DAT_CODE_829a` |
| `typedef` | 2 | `undefined`, `undefined1` |

### 3.2 Артефакты (`emit`)

| Артефакт | Размер | Содержимое |
| --- | --- | --- |
| `docs/recovered/firmware_clean.c` | 564 857 байт | весь дамп как C: настоящие ширины типов, адресные пространства в именах (`iram_3E`, `xdata_0C7A`, `sfr_92`, `sub_810F`, `loc_EE3F`), макрос на каждую интринсику, комментарий к каждому непокрытому адресу |
| `docs/recovered/firmware_recovered.py` | 541 157 байт | `RECOVERED` (128 записей) + `STATS` + `MISSING_RANGES` + `NAME_MAP` |

`STATS` артефакта (сверено чтением файла):

```
functions 128 | recovered 57 | partials 70 | stubs 1 | truncated 0
unparseable 0 | raw_scan_only 0 | globals 361 | uncovered_calls 155
body_parse_ratio (127, 127) | MISSING_RANGES [[0, 32767]]
```

> `MISSING_RANGES` и `DUMP_ROM` артефакта генерирует `recover/emit.py`, который
> пока работает в сетке записей (`DUMP_ROM = (0x8000, 0xffff)`); после миграции
> эмиттера на CPU-сетку артефакт перегенерируют — отсутствующей станет верхняя
> половина `0x8000..0xFFFF` (см. §1).

Проверка сбалансированности C: `C balance check: clean (braces/parens/brackets balanced)`,
`balance_problems: []`.

> После фикса `_SIG_RE` цифры `STATS` и `report` **сходятся**: 128 функций —
> это `57 recovered + 70 partial + 1 stub`, `raw_scan_only = 0`,
> `body_parse_ratio (127, 127)`. (До фикса расхождение было ровно на 5 — см.
> §6.1; категории `partial`/`stub` ввели позже, их сумма — те же «71 функция с
> `halt_baddata()`».)

### 3.3 Интринсики Ghidra, встречающиеся в дампе

`halt_baddata`, `nop`, `CONCAT11`, `ZEXT12`, `CARRY1`, `SUB21` — 6 различных;
`emit.INTRINSIC_ARITY` знает про них и про ещё несколько десятков редких
`SEXT*`/`SUB*`/`SBORROW*`/`ZEXT*`.

---

## 4. Что является заглушками

### 4.1 Обрубки Ghidra — `halt_baddata()`

* **71 функция** из 128 содержит `halt_baddata()` — Ghidra упёрся в байты, которые
  не являются началом инструкции (`// WARNING: Control flow encountered bad
  instruction data`). Всего в дампе **216 вызовов** `halt_baddata()` и
  **593 комментария `// WARNING:`**.
* `recover/parse.py` помечает такую функцию `is_stub`; `report` показывает её как
  `stub`, эмиттер — как `stub`, `RecoveredFunction.invoke()` бросает
  `MissingFirmware` **до** первого шага интерпретатора
  (`recover/interp.py:1012`).
* Важно: обрыв **не** означает, что всё тело выдумано. Например в
  `FUN_CODE_b274` обрыв стоит внутри `if` (строка 877), а соседние ветки того же
  тела — настоящий код (записи `DAT_EXTMEM_000b = 0x89` на строках 850/852 идут
  **до** обрыва). Поэтому доказательства из «заглушечных» функций используются,
  но помечаются как неполные — см. `docs/hardware_evidence.md`.

### 4.2 Заглушки исполняемого слоя

| Что | Где | Поведение |
| --- | --- | --- |
| Вызов `func_0xNNNN` (цель не связана с функцией дампа) | `recover/interp.py:870-873` (`call_by_name`), `recover/runtime.py:241-259` (`__getitem__`) | возвращает **`0`** и обязательно инкрементирует `machine.missing_calls[name]`; `report` и `snapshot_text` печатают блок «Uncovered call targets (no dump covers these)» — ничего не скрывается, но исключения нет |
| Вызов `FUN_CODE_xxxx`, на который в дампе нет определения | `recover/interp.py:860-868` | инкремент счётчика **и** `MissingFirmware` с адресом: это разрыв прошивки с известным адресом, а не неизвестный идентификатор |
| Косвенный вызов по вычисленному адресу | `recover/interp.py:844-850` | `MissingFirmware(addr, "indirect call through a computed address…")` |
| Вызов имени, которого нет нигде | `recover/interp.py:874-876` | `KeyError: recovered code calls '…', which is not defined in the dump` |
| Вызов функции-обрубка (`halt_baddata`) | `recover/interp.py:1009-1013` | `MissingFirmware` **до** первого шага интерпретатора |
| Запись в код ПЗУ | `recover/namespace.py:403`, `recover/hal.py:372` (`CodeCell.value`) | `MissingFirmware`, ROM read-only |
| Чтение кода при не подключённом ROM | `recover/namespace.py:257` | `MissingFirmware` |
| Чтение write-only окна железа | `recover/hal.py:1049-1066` (`CashRegisterHAL._read`) | `MissingFirmware` (strict, по умолчанию) |
| Неизвестное имя в выражении | `recover/interp.py:885-903` (`lookup`) | `KeyError` с пояснением «ни адрес, ни функция» |
| Когда `recover/hal.py` не установлен | `recover/namespace.py` | плоский образ внешней RAM `0x0000..0xFFFF` |
| Когда `board/` не импортируется | `recover/hal.py`, `_FallbackDisplay/_FallbackKeyboard/_FallbackPrinter` | минимальные заглушки периферии |

> Практическое следствие первой строки: **«провал» на несвязанную цель
> `func_0xNNNN` не роняет исполнение, но подсчитывается.** Проверять честность
> следует по `machine.missing_calls` / `status()["missing_calls"]`, а не по
> исключениям. Исключения (`MissingFirmware`) поднимает всё, что имеет
> **известный** адрес и всё же недоступно.

### 4.3 Стенд-ин в `main.py`

`--backend demo51` (`firmware/demo/cashier.asm` + `tools/asm51.py`) — **настоящий**
машинный код 8051, но **не** оригинальная прошивка. Это честная замена, а не
восстановление; режимы не смешиваются (`docs/architecture.md`).

---

## 5. Ограничения

1. **Верхней половины CPU нет.** 64 вызова из 756 `func_0xNNNN` целятся в
   CPU `0x8000..0xFFFF` — этих байтов в дампе нет (файл содержит ровно нижние
   32 КиБ). Остальные 692 цели (CPU `0x0000..0x7FFF`) после rebasing лежат в
   дампе, но связать их с функциями декомпиляции ещё предстоит (`recover/`:
   Ghidra грузил записи, операнды — в сетке CPU, разница `0x8000`).
   Инициализация и векторы прерываний при этом **в дампе есть** (CPU `0x0A06`,
   `0x0003`…, см. `docs/architecture.md`); сканирование клавиатуры и драйвер
   принтера остаются непокрытыми **функциями декомпиляции** (см.
   `docs/hardware_evidence.md` §3.3, §8).
2. **Исполняется отдельная функция, а не прошивка — в псевдокодном
   конвейере.** `run` вызывает одну функцию с произвольными аргументами;
   сквозной запуск псевдокода не собирается в цельную программу. Оригинальные
   байты на ядре `m8051` после rebasing крутятся от настоящего вектора
   сброса: `--backend etim` (проверено: `--headless 3` → 400 004 цикла,
   `halted: False`).
3. **Заглушечные тела неполны.** Исполнять их нельзя (`MissingFirmware`), но
   текст до/после обрыва в других ветках остаётся пригодным как источник
   доказательств.
4. **Указатели — не адресное пространство.** `Pointer` в `recover/interp.py:67`
   знает свой `space` и читает/пишет через колбэк; числа, которые декомпилятор
   превратил в указатели (`(byte *)0x1234`), не дают права считать адрес
   доказанным.
5. **Чтение write-only окна** в `hal` по умолчанию бросает исключение, а не
   возвращает выдуманное значение (`strict=True`).
6. **Формат псевдо-C нестабилен.** Сигнатуры переносятся, типы — битые
   (`undefined 22.1;`), интринсики Ghidra (`CONCAT11`, `ZEXT12`, `CARRY1`…) не
   существуют в C. Поэтому парсер — свой, а не «настоящий» компилятор.

---

## 6. Дефекты, найденные при аудите, и их статус

### 6.1 `_SIG_RE` пропускал 5 функций с указателем в типе возврата — **исправлено**

**Было** (`recover/parse.py:28`):

```python
_SIG_RE = re.compile(
    r"^(?P<ret>[A-Za-z_][\w]*)\s+(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^;{}]*)\)\s*$"
)
```

после типа допускался только `\s+`, но не `*`. В дампе **128** определений
функций начинается в первой колонке, а `parse_dump()` находил только **123** —
пропускались все пять сигнатур с типом-указателем:

| строка `docs/nm27c512n_decompiled.c` | сигнатура |
| --- | --- |
| 3526 | `char * thunk_FUN_CODE_ea4f(...)` |
| 3764 | `char * FUN_CODE_ea4f(...)` |
| 8523 | `byte * FUN_CODE_f80d(...)` |
| 9049 | `byte * FUN_CODE_f87d(...)` |
| 16098 | `byte * FUN_CODE_feff(...)` |

**Стало** (`recover/parse.py:28-33`):

```python
_SIG_RE = re.compile(
    # the return type may be a pointer: the dump has ``char * FUN_CODE_ea4f(...)``
    # and ``byte * FUN_CODE_f80d(...)``; without the ``\s*\*+`` those five
    # definitions were dropped and their call sites looked "undefined".
    r"^(?P<ret>[A-Za-z_][\w]*(?:\s*\*+)?)\s+(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^;{}]*)\)\s*$"
)
```

**Фактическое состояние после фикса** (сверено `report` и `selftest`;
категории того времени: сегодня `emit` дополнительно различает `partial` (70) и
`stub` (1), их сумма — те же «71», см. §3):

```
functions 128 | recovered 57 | stubs 71 | globals 361 (62 bit cells)
bodies parsed: 57/57 | raw_scan_only 0
called identifiers with no definition in the dump: 175
```

Блок `called identifiers…` больше не содержит `FUN_CODE_f80d` / `FUN_CODE_f87d` /
`FUN_CODE_feff` — остались только `func_0xNNNN` (цели, не связанные с функциями
дампа) и интринсики.

* **Почему `recovered` не выросло с 57 до 62:** все пять «найденных» функций
  сами оказались заглушками (`halt_baddata()` в теле), поэтому `stubs`
  выросли 66 → 71, а исполнимые тела остались в количестве 57.
* **Влияние до фикса** (для истории): занижение статистики `report`/`selftest`,
  отсутствие этих пяти функций в `FunctionLibrary`, расхождение `STATS` и
  `report` ровно на 5.

### 6.2 Устаревший комментарий в `recover/session.py` — **исправлено**

`RecoveredInterpreter` изначально объяснял своё существование тем, что
`Interpreter._run` «не двигает `frame.i`» и каждая функция кончается
`RuntimeError: exceeded 2000000 steps`. Дефект исправлен в самом
`recover/interp.py` (курсор двигается до диспетчеризации, есть
`_enter_loop`/`_loop_tail`/разворот кадров для `break`/`continue`/`goto`), а
докстринг `recover/session.py:59-76` переписан: субкласс оставлен как тонкая
обёртка «интерпретатор с правильным курсором», старая формулировка удалена.

### 6.3 Погрешность в `docs/hardware_from_pseudocode.md` — **исправлено**

Было сказано: «база таблицы: `0x824A - 0x1C = 0x822E`». Выражение в коде —
`*(byte *)((ushort)(param_3 + 0x1c) + 0x824a)` (`L460`, `L611`), то есть база
`0x824A + 0x1C` = **`0x8266`**. Байты `ROM 0x8266 = 41 49 48 4C 44 46 42 43`
подтверждают это (8 байт, ровно по числу знакомест); по адресу `0x822E` лежит
хвост соседней таблицы `0x8224`. Значение исправлено в
`docs/hardware_from_pseudocode.md` (пункт CONFIRMED о таблице знакогенератора и
итог раздела), разбор с цитатами — в `docs/hardware_evidence.md` §2.3.

### 6.4 Счётчик функций в `docs/architecture.md` — **исправлено**

`architecture.md:7` и `:115` теперь дают «128 определений функций (123
распознаёт `parse_dump`)»; ранее там было «121 функция». Тот же исправлен
пункт «Все 123 функции…» в `docs/hardware_from_pseudocode.md:156`.

### 6.5 Ссылка на несуществующий `__missing__` в `recover/runtime.py` — **исправлено**

Докстринг `recover/runtime.py:117` теперь явно говорит: «There is no
`__missing__` protocol here» — логика разрешения имён описана через
`RuntimeHelpers.__getitem__` (`recover/runtime.py:241-259`), включая
`func_0xNNNN` (счётчик + `0`) и срезание префикса `thunk_`.

---

## 7. Как воспроизводить

```powershell
$env:PYTHONUTF8 = 1

# 1. тесты восстановления (36 тестов)
python -m unittest tests.test_recover -q

# 2. справка и самопроверка конвейера (12 проверок)
python tools/recover_firmware.py --help
python tools/recover_firmware.py selftest

# 3. полный отчёт: таблица функций, непокрытые вызовы
python tools/recover_firmware.py report

# 4. пересобрать артефакты (пишет docs/recovered/*)
python tools/recover_firmware.py emit

# 5. исполнить одну восстановленную функцию
python tools/recover_firmware.py run FUN_CODE_810f --args 1,2 --steps 5000
python tools/recover_firmware.py run FUN_CODE_8135 --args 1,2,3,4,5,6 --steps 5000

# 6. весь набор
python -m unittest discover -s tests -q
```

Результаты, зафиксированные при написании документа (после фикса):

* `tests.test_recover` — `Ran 36 tests ... OK` (~24 с);
* `selftest` — 12 проверок `[ok]`, `selftest passed`; артефакты 563 483 и
  540 077 байт, `globals bound to the machine — 188`;
* `report` — см. §3.1: `functions 128`, `recovered 57`, `stubs 71`,
  `globals 361`, `bodies parsed: 57/57`, `call targets outside every dump: 168`,
  `called identifiers with no definition in the dump: 175`;
* `run FUN_CODE_810f --args 1,2` — `returned 0`, 5 шагов;
* `run FUN_CODE_8135 --args 1,2,3,4,5,6` — `returned 0`, 5 шагов (до фикса
  интерпретатора было 17);
* полный набор `python -m unittest discover -s tests` — **`Ran 409 tests …
  FAILED (failures=4, errors=1)`** (308 с). Все падения — в
  `tests/test_opcodes.py` (`TestOpcodeRoundTrip`, `TestFormerGaps`,
  `TestSelftestSourceRoundTrip`): это зона опкодов/дизассемблера, файл
  в работе, и его результат меняется от прогона к прогону (предыдущий прогон
  в тот же день давал `failures=3, skipped=2`). К пакету `recover/`
  отношения не имеет — `tests.test_recover` стабильно зелёный.

> `emit` перезаписывает `docs/recovered/firmware_clean.c` и
> `docs/recovered/firmware_recovered.py`; `test_emit_writes_readable_c` делает это
> и при обычном `unittest`. Вывод детерминирован.
