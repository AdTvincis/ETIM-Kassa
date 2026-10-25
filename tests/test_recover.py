"""Тесты восстановления дампа Ghidra (recover/ + tools/recover_firmware.py).

Здесь живут инварианты, без которых «восстановленный код» нельзя считать
восстановленным:

* каждая функция из дампа либо получает адрес, либо явно помечена обрубком;
* тело функции либо разбирается, либо причина отказа зафиксирована;
* сгенерированные C/Python-артефакты непусты и сбалансированы;
* интерпретатор исполняет вызовы без ошибок собственного кода;
* циклы/goto/указатели/обрезания ведут себя как в C, а всё, чего нет в
  прошивке, поднимает MissingFirmware (или считается в missing_calls) -
  никогда не выдаёт выдуманных значений.

Запуск::

    python -m unittest tests.test_recover -v
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from recover.parse import parse_dump  # noqa: E402
from recover.cparse import parse_body  # noqa: E402
from recover.errors import MissingFirmware, UnmappedRegister  # noqa: E402
from recover.interp import FunctionLibrary  # noqa: E402
from recover.namespace import Machine  # noqa: E402
from recover.runtime import RuntimeHelpers  # noqa: E402

DUMP = os.path.join(ROOT, "docs", "nm27c512n_decompiled.c")
TOOLS = os.path.join(ROOT, "tools", "recover_firmware.py")


def _load():
    with open(DUMP, "r", encoding="utf-8", errors="replace") as fh:
        return parse_dump(fh.read(), DUMP)


class TestDumpParse(unittest.TestCase):
    """Разбор исходного дампа: структура должна быть полной и правдивой."""

    @classmethod
    def setUpClass(cls):
        cls.program = _load()

    def test_all_functions_have_addresses(self):
        missing = [f.name for f in self.program.functions if f.address is None]
        self.assertEqual(missing, [], f"функции без адреса: {missing}")

    def test_function_addresses_are_unique(self):
        """Адреса уникальны, за исключением thunk/целевой пар.

        Ghidra эмитирует ``thunk_FUN_CODE_xxxx`` как тривиальный переход на
        ``FUN_CODE_xxxx`` — у них совпадает адрес по построению; это
        корректное состояние, а не потерянный адрес.
        """
        from collections import defaultdict

        by_addr = defaultdict(list)
        for fn in self.program.functions:
            by_addr[fn.address].append(fn.name)
        for addr, names in by_addr.items():
            if len(names) < 2:
                continue
            stripped = [
                n[len("thunk_"):] if n.startswith("thunk_") else n
                for n in names
            ]
            self.assertEqual(
                len(set(stripped)), 1,
                f"адрес 0x{addr:04X} у несвязанных функций: {names}",
            )

    def test_every_body_parses_or_is_a_known_stub(self):
        """Тела либо парсятся, либо это обрубки дизассемблера."""
        for fn in self.program.functions:
            if fn.is_stub:
                continue
            try:
                parse_body(fn.body)
            except Exception as exc:                       # noqa: BLE001
                self.fail(f"{fn.name} (0x{fn.address:04X}) не разобрался: {exc}")

    def test_statistics_match_the_dump(self):
        stats = self.program.stats()
        self.assertGreaterEqual(stats["functions"], 120, "дамп должен содержать код")
        self.assertGreaterEqual(stats["globals"], 300, "объявления должны разобраться")
        self.assertLessEqual(stats["stubs"], stats["functions"])


class TestRecoveryCli(unittest.TestCase):
    """CLI восстановления должен работать и проверять сам себя."""

    def test_selftest_passes(self):
        result = subprocess.run(
            [sys.executable, TOOLS, "selftest"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        self.assertEqual(
            result.returncode, 0,
            f"selftest провалился:\n{result.stdout}\n{result.stderr}",
        )

    def test_report_reports_every_addressed_function(self):
        result = subprocess.run(
            [sys.executable, TOOLS, "report"],
            capture_output=True, text=True, cwd=ROOT, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # 128 = 123 «обычных» + 5 сигнатур с указателем в типе возврата
        # (``char * FUN_CODE_ea4f`` и ``byte * FUN_CODE_f80d/f87d/feff``),
        # которые старый _SIG_RE отбрасывал целиком
        match = re.search(r"functions\s+:\s+(\d+)", result.stdout)
        self.assertIsNotNone(match, result.stdout[:400])
        self.assertGreaterEqual(int(match.group(1)), 128,
                                "отчёт обязан учитывать и указательные сигнатуры")
        for name in ("FUN_CODE_ea4f", "FUN_CODE_f80d", "FUN_CODE_f87d", "FUN_CODE_feff"):
            self.assertIn(name, result.stdout, f"{name} должна числиться в отчёте")
        # отчёт различает три статуса: recovered / partial / stub
        partial_line = re.search(r"partials\s+:\s+(\d+)", result.stdout)
        self.assertIsNotNone(partial_line, "в отчёте должна быть строка partials")
        self.assertGreaterEqual(int(partial_line.group(1)), 10,
                                "тела с bad-data внутри обязаны считаться отдельно")
        self.assertIsNotNone(
            re.search(r"0x[0-9A-F]{4}\s+\d+\s+\d+\s+partial\b", result.stdout),
            "в таблице статусов есть строки partial",
        )

    def test_emit_writes_readable_c(self):
        result = subprocess.run(
            [sys.executable, TOOLS, "emit"],
            capture_output=True, text=True, cwd=ROOT, timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        c_path = os.path.join(ROOT, "docs", "recovered", "firmware_clean.c")
        py_path = os.path.join(ROOT, "docs", "recovered", "firmware_recovered.py")
        self.assertTrue(os.path.isfile(c_path), "нет восстановленного C-файла")
        self.assertTrue(os.path.isfile(py_path), "нет восстановленного Python-файла")
        with open(c_path, "r", encoding="utf-8", errors="replace") as fh:
            c_text = fh.read()
        self.assertGreater(len(c_text), 100_000, "восстановленный C слишком короткий")
        # адреса сохранены и переименование произошло
        self.assertIn("sub_810F", c_text, "функция 0x810F должна быть переименована")
        self.assertIn("FUN_CODE_", c_text, "исходные имена обязаны остаться в комментариях")
        # тела обязаны использовать настоящие C-типы; сам Ghidra-тип допустим
        # только в комментарии-провенансе или в typedef-блоке
        bad_decls = re.findall(
            r"^[ \t]*(?:undefined\d?|byte|sbyte|ushort|uint3?|ulong|word|dword)\b"
            r"[ \t]+[* ]*\w+[ \t]*[;=,\[]",
            c_text,
            re.M,
        )
        self.assertEqual(bad_decls, [], f"тела используют Ghidra-типы: {bad_decls[:5]}")
        # halt_baddata обязан быть определён, а не бить по компиляции
        self.assertIn("#define halt_baddata", c_text,
                     "halt_baddata должен быть замакрован на заглушку")


# ---------------------------------------------------------------------------
# Семантика интерпретатора: синтетический дамп, исполнимый за миллисекунды.
# Каждая проверяемая особенность имеет отдельную функцию, чтобы падание
# указывало прямо на неё.
# ---------------------------------------------------------------------------

SYNTHETIC_DUMP = """
undefined1 DAT_INTMEM_30;
undefined1 DAT_INTMEM_31;
undefined1 DAT_EXTMEM_1000;
undefined1 DAT_SFR_92;
undefined 22.1;
undefined IP.7;
undefined P0.0;
undefined FIFLG.4;
undefined1 RXSTAT;
undefined1 FUN_CODE_9000()
{
  int i;
  int n;
  i = 0;
  n = 0;
  while (i < 3) {
    i = i + 1;
    n = n + 10;
  }
  for (i = 0; i < 4; i = i + 1) {
    n = n + 1;
  }
  while (i < 0) {
    n = n + 1000;
  }
  return n;
}
undefined1 FUN_CODE_9001()
{
  int i;
  int j;
  i = 0;
  j = 0;
  do {
    i = i + 1;
  } while (i < 5);
  do {
    j = j + 1;
  } while (0);
  return i + j;
}
undefined1 FUN_CODE_9002()
{
  int i;
  int n;
  i = 0;
  n = 0;
  for (i = 0; i < 5; i = i + 1) {
    if (i == 2) continue;
    if (i == 4) break;
    n = n + 1;
  }
  return n;
}
undefined1 FUN_CODE_9003()
{
  int i;
  int n;
  i = 0;
  n = 0;
  if (i == 0) {
    n = n + 100;
LAB_target:
    n = n + 1;
  }
  n = n + 7;
  if (n < 116) goto LAB_target;
  return n;
}
undefined1 FUN_CODE_9004()
{
  int z;
  z = 0;
  goto LAB_cross;
  z = 999;
  return z;
}
undefined1 FUN_CODE_9005()
{
  int y;
  y = 40;
LAB_cross:
  y = y + 2;
  return y;
}
undefined1 FUN_CODE_9006()
{
  goto LAB_nope;
  return 1;
}
undefined1 FUN_CODE_9007()
{
  int n;
  n = 0;
  while (true) {
    n = n + 1;
    if (n == 3) break;
  }
  if (false) {
    n = n + 100;
  }
  return n;
}
undefined1 FUN_CODE_9008()
{
  int s;
  char c;
  DAT_INTMEM_30 = 0x1234;
  DAT_EXTMEM_1000 = 0x1ff;
  DAT_SFR_92 = 0x1ff;
  s = 0xffff + 1;
  c = (char)0xff;
  DAT_INTMEM_31 = c;
  return s;
}
undefined1 FUN_CODE_9009()
{
  char c;
  c = (char)0xff;
  return c;
}
undefined1 FUN_CODE_900a()
{
  byte *p;
  byte *q;
  int x;
  p = (byte *)0x2000;
  *p = 0x11;
  *(p + 1) = 0x22;
  p[2] = 0x33;
  q = &DAT_INTMEM_30;
  *q = 0x44;
  q[1] = 0x55;
  x = 0x40;
  x[0] = 0x77;
  return p[1];
}
undefined1 FUN_CODE_900b()
{
  byte v;
  v = *(code *)0x8100;
  return v;
}
undefined1 FUN_CODE_900c()
{
  *(code *)0x8101 = 0x12;
  return 0;
}
undefined1 FUN_CODE_900d()
{
  (*(code *)(0x900e))();
  return 5;
}
undefined1 FUN_CODE_900e()
{
  DAT_INTMEM_30 = 0x2a;
  return 1;
}
undefined1 FUN_CODE_900f()
{
  (*(code *)(0x1234))();
  return 1;
}
undefined1 FUN_CODE_9010()
{
  func_0x4ce0();
  return 7;
}
undefined1 FUN_CODE_9011()
{
  byte b;
  b = RXSTAT;
  return b;
}
undefined1 FUN_CODE_9012()
{
  return FUN_CODE_ffff();
}
undefined1 FUN_CODE_9013()
{
  halt_baddata();
  return 0;
}
undefined1 FUN_CODE_9014()
{
  _2_1 = 1;
  IP_7 = 1;
  P0_0 = 1;
  return 0;
}
undefined1 FUN_CODE_9015()
{
  CY = 1;
  ACC = 0x9a;
  return 0;
}
undefined1 FUN_CODE_9016()
{
  int a;
  int b;
  a = decimal_adjust(0x9a);
  b = decimal_adjust(0x3a);
  return a + b;
}
undefined1 FUN_CODE_9017()
{
  byte b;
  b = FIFLG_4;
  return b;
}
undefined1 FUN_CODE_9018()
{
  DAT_INTMEM_30 = 0x11;
  halt_baddata();
  DAT_INTMEM_30 = 0x22;
  return 1;
}
"""


def _library(text=SYNTHETIC_DUMP, rom=None):
    """Свежая библиотека поверх свежей машины (никакого общего состояния)."""
    program = parse_dump(text, "<synthetic>")
    machine = Machine()
    if rom is not None:
        machine.rom_reader = lambda addr: rom.get(addr & 0xFFFF, 0xFF)
    helpers = RuntimeHelpers(machine)
    library = FunctionLibrary(machine, helpers)
    library.register_globals(program.globals)
    library.load(program)
    return machine, library


class TestLoopsAndControlFlow(unittest.TestCase):
    """Циклы и переходы: интерпретатор обязан исполнять их как C."""

    @classmethod
    def setUpClass(cls):
        cls.machine, cls.library = _library()

    def _call(self, name, *args):
        return self.library.functions[name].invoke(self.library.interpreter, list(args))

    def test_while_for_and_zero_iteration_while(self):
        # while отрабатывает 3 итерации, for - 4, while с ложным условием - 0
        self.assertEqual(self._call("FUN_CODE_9000"), 34)

    def test_do_while_runs_once_even_when_false(self):
        # do..while(i<5) -> 5; do..while(0) -> ровно один проход -> 6
        self.assertEqual(self._call("FUN_CODE_9001"), 6)

    def test_break_and_continue_inside_for(self):
        # i==2 пропускается, i==4 обрывает цикл: 0,1,3 -> 3
        self.assertEqual(self._call("FUN_CODE_9002"), 3)

    def test_goto_into_an_exited_block_rebuilds_the_chain(self):
        # goto в блок if, который уже закрыт: цепочка блоков собирается заново
        # 100 -> 101 -> (+7)=108 -> goto -> 109 -> (+7)=116
        self.assertEqual(self._call("FUN_CODE_9003"), 116)

    def test_goto_leaves_the_function_and_continues_in_another(self):
        # goto LAB_cross перепрыгивает в FUN_CODE_9005; выполняется с метки,
        # без пролога (y = 40) - регистры на границе функций не изобретаются
        self.assertEqual(self._call("FUN_CODE_9004"), 2)

    def test_goto_to_an_undefined_label_reports_a_gap(self):
        # неизвестная метка раньше молча оставляла курсор на месте (вечный цикл)
        with self.assertRaises(MissingFirmware) as ctx:
            self._call("FUN_CODE_9006")
        self.assertIn("LAB_nope", str(ctx.exception))

    def test_true_and_false_are_c_constants(self):
        # 277 вхождений while(true)/bVar = false в дампе
        self.assertEqual(self._call("FUN_CODE_9007"), 3)


class TestOverflowAndTruncation(unittest.TestCase):
    """Обрезание байт и переполнение 16 бит - как на настоящем 8051."""

    @classmethod
    def setUpClass(cls):
        cls.machine, cls.library = _library()

    def test_stores_truncate_to_the_width_of_their_space(self):
        machine = self.machine
        result = self.library.functions["FUN_CODE_9008"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, 0, "0xFFFF + 1 переполняется в 0")
        self.assertEqual(machine.ram(0x30), 0x34, "RAM принимает только байт")
        self.assertEqual(machine.xdata_read(0x1000), 0xFF, "xdata принимает байт")
        self.assertEqual(machine.sfr(0x92), 0xFF, "SFR принимает байт")
        self.assertEqual(machine.ram(0x31), 0xFF, "char -1 хранится как 0xFF")

    def test_signed_char_keeps_its_sign(self):
        result = self.library.functions["FUN_CODE_9009"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, -1, "(char)0xFF == -1")

    def test_machine_read_code_without_a_rom_reports_the_gap(self):
        machine = Machine()
        with self.assertRaises(MissingFirmware) as ctx:
            machine.read_code(0x8123)
        self.assertEqual(ctx.exception.addr, 0x8123)


class TestPointerAddressSpaces(unittest.TestCase):
    """Указатели обязаны попадать в своё пространство: xdata, RAM, code."""

    @classmethod
    def setUpClass(cls):
        cls.rom = {0x8100: 0x5C}
        cls.machine, cls.library = _library(rom=cls.rom)

    def test_pointer_spaces_survive_assignment_and_indexing(self):
        machine = self.machine
        result = self.library.functions["FUN_CODE_900a"].invoke(
            self.library.interpreter, [])
        # указатель из каста хранит своё пространство после присваивания
        self.assertEqual(result, 0x22, "p[1] читает второй байт указателя")
        self.assertEqual(machine.xdata_read(0x2000), 0x11)
        self.assertEqual(machine.xdata_read(0x2001), 0x22)
        self.assertEqual(machine.xdata_read(0x2002), 0x33, "p[2] - индексация")
        # &DAT_INTMEM_30 даёт указатель в RAM, а не голое число:
        # и *q, и q[1] обязаны попадать во внутреннюю память
        self.assertEqual(machine.ram(0x30), 0x44, "*(&DAT_INTMEM_30) - это RAM")
        self.assertEqual(machine.ram(0x31), 0x55, "индексация по RAM-указателю")
        # у целого без маркера пространства по умолчанию то же, что у *x (xdata)
        self.assertEqual(machine.xdata_read(0x40), 0x77,
                         "по умолчанию - как у *p: единое пространство")

    def test_code_pointer_read_is_movc(self):
        result = self.library.functions["FUN_CODE_900b"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, 0x5C, "чтение (code *) идёт в ПЗУ")

    def test_code_pointer_read_without_rom_reports_missing_firmware(self):
        machine, library = _library()          # без rom_reader
        with self.assertRaises(MissingFirmware) as ctx:
            library.functions["FUN_CODE_900b"].invoke(library.interpreter, [])
        self.assertEqual(ctx.exception.addr, 0x8100)

    def test_write_through_a_code_pointer_is_forbidden(self):
        with self.assertRaises(MissingFirmware) as ctx:
            self.library.functions["FUN_CODE_900c"].invoke(
                self.library.interpreter, [])
        self.assertIn("code memory", str(ctx.exception))


class TestCallsAndGaps(unittest.TestCase):
    """Вызовы: по адресу, по имени и честные пробелы."""

    @classmethod
    def setUpClass(cls):
        cls.machine, cls.library = _library()

    def test_indirect_call_dispatches_by_address(self):
        machine = self.machine
        result = self.library.functions["FUN_CODE_900d"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, 5)
        self.assertEqual(machine.ram(0x30), 0x2A,
                         "(*(code *)(0x900e))() должен позвать FUN_CODE_900e")

    def test_indirect_call_to_an_undumped_address_reports_missing_firmware(self):
        with self.assertRaises(MissingFirmware) as ctx:
            self.library.functions["FUN_CODE_900f"].invoke(
                self.library.interpreter, [])
        self.assertEqual(ctx.exception.addr, 0x1234)
        self.assertIn("indirect_0x1234", self.machine.missing_calls)

    def test_func_0x_returns_zero_and_counts_the_gap(self):
        # Поведенческий контракт: func_0xNNNN НЕ бросает MissingFirmware,
        # а возвращает 0 и инкрементирует machine.missing_calls.
        machine = self.machine
        before = machine.missing_calls.get("func_0x4ce0", 0)
        result = self.library.functions["FUN_CODE_9010"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, 7, "вызов вне дампа не роняет функцию")
        self.assertEqual(machine.missing_calls.get("func_0x4ce0", 0), before + 1)

    def test_call_to_a_named_but_undefined_function_reports_missing_firmware(self):
        with self.assertRaises(MissingFirmware) as ctx:
            self.library.functions["FUN_CODE_9012"].invoke(
                self.library.interpreter, [])
        self.assertEqual(ctx.exception.addr, 0xFFFF)
        self.assertEqual(self.machine.missing_calls.get("FUN_CODE_ffff"), 1)

    def test_stub_raises_on_entry(self):
        # обрубок: тело состоит только из halt_baddata() - исполнить нечего
        fn = self.library.functions["FUN_CODE_9013"]
        self.assertTrue(fn.is_stub, "тело без префикса - полный обрубок")
        self.assertFalse(fn.is_partial)
        with self.assertRaises(MissingFirmware) as ctx:
            fn.invoke(self.library.interpreter, [])
        self.assertEqual(ctx.exception.addr, 0x9013)

    def test_partial_body_executes_its_prefix_then_reports_the_gap(self):
        # partial: рабочий префикс выполняется, метка bad-data поднимает
        # MissingFirmware по адресу *самой функции*, всё после метки не бежит
        fn = self.library.functions["FUN_CODE_9018"]
        self.assertFalse(fn.is_stub, "префикс из рабочих statements = не стаб")
        self.assertTrue(fn.is_partial)
        self.assertEqual(fn.baddata_prefix, 1)
        with self.assertRaises(MissingFirmware) as ctx:
            fn.invoke(self.library.interpreter, [])
        self.assertEqual(ctx.exception.addr, 0x9018,
                         "пробел называется по адресу функции, дошедшей до метки")
        self.assertEqual(self.machine.ram(0x30), 0x11,
                         "statement до метки обязан выполниться")
        self.assertNotEqual(self.machine.ram(0x30), 0x22,
                            "statement после метки - никогда")

    def test_declared_register_without_an_address_is_named_in_the_error(self):
        with self.assertRaises(UnmappedRegister) as ctx:
            self.library.functions["FUN_CODE_9011"].invoke(
                self.library.interpreter, [])
        self.assertEqual(ctx.exception.name, "RXSTAT")
        self.assertIsInstance(ctx.exception, MissingFirmware,
                              "пробел регистра - частный случай пробела прошивки")

    def test_dotted_bit_declaration_is_reported_under_its_body_spelling(self):
        # дамп объявляет FIFLG.4, тело пишет FIFLG_4 - обе формы должны вести
        # на один и тот же честный пробел, а не на generic KeyError
        with self.assertRaises(UnmappedRegister) as ctx:
            self.library.functions["FUN_CODE_9017"].invoke(
                self.library.interpreter, [])
        self.assertEqual(ctx.exception.name, "FIFLG_4")


class TestBitsAndBcdThroughMachine(unittest.TestCase):
    """Битовые и BCD-операции идут через Machine и видны в байтах."""

    @classmethod
    def setUpClass(cls):
        cls.machine, cls.library = _library()

    def test_bit_declaration_maps_to_the_declared_byte(self):
        # регрессия: старая формула (0x22 >> 3) + 0x20 = 0x24 схлопывала
        # весь набор 20.0..2f.7 на два байта
        global_ = self.library.globals["22.1"]
        self.assertEqual((global_.addr, global_.bit), (0x22, 1))
        # ... и совпадает с формой из тел функций (_2_1)
        self.library.functions["FUN_CODE_9014"].invoke(self.library.interpreter, [])
        self.assertEqual(self.machine.ram(0x22) & 0x02, 0x02, "_2_1 = 1")
        cell = self.machine.proxy_cache["22.1"]
        self.assertEqual((cell.byte, cell.bit), (0x22, 1))
        self.assertEqual(int(cell.value), 1, "обе записи смотрят в одну ячейку")

    def test_named_sfr_bits_resolve_from_the_underscore_form(self):
        self.library.functions["FUN_CODE_9014"].invoke(self.library.interpreter, [])
        self.assertEqual(self.machine.sfr(0xB8) & 0x80, 0x80, "IP_7 -> IP.7 (0xB8)")
        self.assertEqual(self.machine.sfr(0x80) & 0x01, 0x01, "P0_0 -> P0.0 (0x80)")

    def test_psw_flags_written_by_code_are_visible_as_a_byte(self):
        self.library.functions["FUN_CODE_9015"].invoke(self.library.interpreter, [])
        self.assertEqual(self.machine.sfr(0xD0), 0x80, "CY - старший бит PSW")
        self.assertEqual(self.machine.sfr(0xE0), 0x9A, "ACC = 0x9A")
        # битовая и байтовая виды согласованы
        cell = self.machine.proxy_cache.get("CY")
        self.assertIsNotNone(cell)
        self.assertEqual(int(cell.value), 1)
        self.machine.set_sfr(0xD0, 0x00)
        self.assertEqual(int(cell.value), 0, "сброс байта гасит бит CY")

    def test_decimal_adjust_implements_da(self):
        decimal_adjust = self.library.helpers.get("decimal_adjust")
        self.assertIsNotNone(decimal_adjust, "Ghidra-внутренность должна быть определена")
        self.assertEqual(decimal_adjust(0x9A), 0x00, "99+1 в BCD")
        self.assertEqual(decimal_adjust(0x55), 0x55, "валидный BCD не меняется")
        self.assertEqual(decimal_adjust(0x3A), 0x40, "нижняя цифра > 9 -> +6")
        # та же функция доступна коду дампа
        result = self.library.functions["FUN_CODE_9016"].invoke(
            self.library.interpreter, [])
        self.assertEqual(result, 0x40)

    def test_carry_and_borrow_helpers(self):
        helpers = self.library.helpers
        self.assertEqual(helpers.get("CARRY1")(0xFF, 0x01), 1)
        self.assertEqual(helpers.get("CARRY1")(0x10, 0x01), 0)
        self.assertEqual(helpers.get("BORROW1")(0x05, 0x06), 1)
        self.assertEqual(helpers.get("BORROW1")(0x06, 0x05), 0)


class TestRealDumpScale(unittest.TestCase):
    """Реальный дамп: сколько загрузилось, что исполняется, где пробелы."""

    @classmethod
    def setUpClass(cls):
        cls.program = _load()
        cls.machine = Machine()
        cls.helpers = RuntimeHelpers(cls.machine)
        cls.library = FunctionLibrary(cls.machine, cls.helpers)
        cls.library.register_globals(cls.program.globals)
        cls.library.load(cls.program)
        cls.library.interpreter.max_steps = 20_000

    def test_pointer_returning_signatures_are_parsed(self):
        # _SIG_RE обязан пропускать '*' в типе возврата: иначе эти пять
        # определений теряется, и их вызовы выглядят как «не определено»
        expected = {
            "thunk_FUN_CODE_ea4f": 0xEA4F,
            "FUN_CODE_ea4f": 0xEA4F,
            "FUN_CODE_f80d": 0xF80D,
            "FUN_CODE_f87d": 0xF87D,
            "FUN_CODE_feff": 0xFEFF,
        }
        by_name = self.program.by_name()
        for name, address in expected.items():
            self.assertIn(name, by_name, f"{name} потеряна при разборе")
            self.assertEqual(by_name[name].address, address, name)

    def test_library_registers_every_function(self):
        stats = self.library.stats()
        pstats = self.program.stats()
        self.assertEqual(self.library.failed, {}, "ни одна функция не должна теряться")
        self.assertEqual(stats["loaded"], len(self.program.functions))
        self.assertGreaterEqual(stats["loaded"], 128)
        # трёхчастная классификация: каждая функция ровно в одном бакете,
        # и ни один бакет не пуст (есть и чистый обрубок, и тела с bad-data)
        self.assertEqual(
            pstats["recovered"] + pstats["partials"] + pstats["stubs"],
            pstats["functions"],
            "recovered + partial + stub должны давать functions",
        )
        self.assertGreaterEqual(pstats["recovered"], 57)
        self.assertGreaterEqual(pstats["partials"], 10)
        self.assertGreaterEqual(pstats["stubs"], 1)
        self.assertEqual(stats["stubs"], pstats["stubs"],
                         "library и program считают стабы одинаково")
        self.assertEqual(stats["partials"], pstats["partials"])
        # дамп объявляет символы без адреса - они обязаны быть посчитаны
        self.assertGreater(stats["unmapped"], 0)
        self.assertIn("RXSTAT", self.library.interpreter.unmapped)
        self.assertIn("FIFLG_4", self.library.interpreter.unmapped,
                      "форма из тела должна наследовать пробел объявления")

    def test_true_stub_and_partial_behave_differently(self):
        # FUN_CODE_8139 - единственное тело, состоящее только из halt_baddata
        interp = self.library.interpreter
        stub = self.library.functions["FUN_CODE_8139"]
        self.assertTrue(stub.is_stub, "тело без префикса - полный обрубок")
        self.assertFalse(stub.is_partial)
        interp.trace = []
        with self.assertRaises(MissingFirmware) as ctx:
            stub.invoke(interp, [1, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(ctx.exception.addr, 0x8139)
        self.assertEqual(interp.trace, [], "обрубок не исполняет ни одного statement")

        # FUN_CODE_f565: один рабочий statement, затем метка bad-data
        partial = self.library.functions["FUN_CODE_f565"]
        self.assertTrue(partial.is_partial, "префикс из рабочих statements")
        self.assertFalse(partial.is_stub)
        self.assertEqual(partial.baddata_prefix, 1)
        interp.trace = []
        with self.assertRaises(MissingFirmware) as ctx:
            partial.invoke(interp, [0x5A, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(
            ctx.exception.addr, 0xF565,
            "пробел называется по адресу функции, дошедшей до метки",
        )
        self.assertGreater(len(interp.trace), 0, "префикс обязан выполниться")
        self.assertEqual(self.machine.ram(0x0F), 0x5A,
                         "BANK1_R7 = param_1 выполнено до метки")
        interp.trace = None

    def test_every_function_executes_without_an_interpreter_bug(self):
        import collections

        categories: "collections.Counter[str]" = collections.Counter()
        unexpected = []
        for name, fn in self.library.functions.items():
            if fn.is_stub:
                categories["stub"] += 1
                continue
            if fn.is_partial:
                categories["partial"] += 1   # partial исполняется, не отказывает
            try:
                fn.invoke(self.library.interpreter, [1, 0, 0, 0, 0, 0, 0, 0])
                categories["ok"] += 1
            except MissingFirmware:
                categories["missing_firmware"] += 1   # честный пробел
            except RuntimeError:
                categories["step_limit"] += 1          # предохранитель цикла
            except Exception as exc:                   # noqa: BLE001
                categories["unexpected"] += 1
                unexpected.append(f"{name}: {type(exc).__name__}: {exc}")
        self.assertEqual(unexpected, [],
                         "интерпретатор не должен падать своими ошибками")
        self.assertGreaterEqual(categories["ok"], 30,
                                "значительная часть дампа должна исполняться")
        self.assertGreater(categories["missing_firmware"], 0,
                           "пробелы второй половины прошивки обязаны проговариваться")
        self.assertGreaterEqual(categories["partial"], 10,
                                "partial-тела обязаны попадать в исполнение")


class TestRealHexRunner(unittest.TestCase):
    """Оригинальный hex на ядре m8051 (recover/realrun.py) - без интерпретатора.

    Здесь проверяется не псевдокод, а настоящие байты ``firmware/nm27c512n.hex``
    в их реальном виде: файл хранит образ по record-адресам ``0x8000..0xFFFF``,
    а исполняется он по CPU-адресам ``0x0000..0x7FFF`` (record - 0x8000).
    Прогон идёт из настоящего вектора сброса (``cpu.pc = 0`` -> ``LJMP 0x0A06``),
    таймеры и прерывания ставит сама прошивка:

    * Timer-0 реально работает: вектор CPU ``0x000B`` -> тело мукса CPU
      ``0x02D9``, индикатор оживает сам (замерено: первый непустой экран на
      ~290 000 циклов - прошивка сама инициализируется);
    * Timer-1 прошивка в этом состоянии НЕ запускает (``TR1`` ставит только
      код по CPU ``0x5AEC``), поэтому refresh CPU ``0x0135`` и чтения
      страницы ``0x91`` честно равны нулю - мы не изобретаем вокруг них
      синтетику;
    * маршрутизация MOVX идёт через доказательные окна HAL, чтение страницы
      клавиатуры ``0x91`` матрицей работает, а верхняя половина CPU
      ``0x8000..0xFFFF`` в дампе отсутствует и даёт честную остановку.
    """

    @classmethod
    def setUpClass(cls):
        from recover.hal import CashRegisterHAL, load_rom
        cls.load_rom = load_rom
        cls.CashRegisterHAL = CashRegisterHAL
        cls.rom = load_rom()
        cls.program = _load()

    def _fresh(self, wiring=None):
        board = None
        if wiring:
            from board.cashboard import CashRegisterBoard
            board = CashRegisterBoard(wiring=wiring)
        hal = self.CashRegisterHAL(board=board, rom=self.rom, strict=True)
        from recover.realrun import RealRunner
        return RealRunner(hal=hal, rom=self.rom)

    def test_rebased_rom_boots_from_the_real_reset_vector(self):
        """Перебазирование: record 0x8000..0xFFFF становится CPU 0x0000..0x7FFF."""
        runner = self._fresh()
        # record-мир (псевдокод) не тронут - грузится как есть
        self.assertEqual(self.rom.coverage(), (0x8000, 0xFFFF))
        # исполняемая копия: вектор сброса лежит по CPU 0x0000 и указывает внутрь
        self.assertEqual(runner.rom.byte(0x0000), 0x02, "LJMP у вектора сброса")
        self.assertEqual(runner.rom.word(0x0001), 0x0A06)
        self.assertEqual(runner.rom.coverage(), (0x0000, 0x7FFF))
        self.assertFalse(runner.rom.is_mapped(0x8000),
                         "верхняя половина CPU в дамп не входит")
        self.assertEqual(runner.cpu.pc, 0x0000, "старт именно из вектора")
        # честная остановка: переход в несdumpанную верхнюю половину
        runner.cpu.pc = 0x8000
        runner.cpu.step()
        self.assertTrue(runner.cpu.halted, "верхняя половина должна останавливать")
        self.assertIn("missing", runner.cpu.error or "")
        runner.advance(1_000)
        self.assertTrue(runner.halted)
        self.assertIn("0x8000", runner.halt_reason)

    def test_real_hex_runs_half_a_million_cycles_without_errors(self):
        runner = self._fresh()
        runner.advance(500_000)
        self.assertFalse(runner.halted, runner.halt_reason)
        self.assertEqual(runner.bus.gaps, [], "шина не должна ловить пробелы")
        stats = runner.stats()
        # настоящий Timer-0: вектор 0x000B -> тело мукса CPU 0x02D9
        # (замерено на этой прошивке: ~115 исполнений за 500k циклов)
        self.assertGreaterEqual(stats["timer0_calls"], 100, stats)
        self.assertEqual(stats["mux_calls"], stats["timer0_calls"])
        # честный ноль: прошивка не запускает Timer-1, refresh не исполняется
        self.assertEqual(stats["timer1_calls"], 0, stats)
        self.assertEqual(stats["vector_dispatches"].get("0xb"),
                         stats["timer0_calls"], "каждому телу - свой вектор")
        self.assertNotIn("0x1b", stats["vector_dispatches"], stats)
        self.assertGreater(stats["instructions"], 10_000, stats)
        self.assertEqual(stats["overruns"], 0, "синтетических тел больше нет")
        # реальные страницы: сегменты дисплея, сетка, шагатели платы
        self.assertTrue({0x82, 0x92, 0xA2, 0xB1} <= set(stats["write_pages"]),
                        stats)

    def test_display_comes_alive_from_real_firmware_execution(self):
        """Индексор оживает без всякой синтетики: пишет сама прошивка."""
        runner = self._fresh()
        board = runner.board
        before = board.display.text()
        # Замерено: ~285k циклов собственных задержек инициализации, первый
        # непустой экран примерно на 290k; 120 x 5_000 = 600k с большим
        # запасом.
        changed_to = None
        for _ in range(120):
            runner.advance(5_000)
            text = board.display.text()
            if text != before:
                changed_to = text
                break
        stats = runner.stats()
        self.assertIsNotNone(
            changed_to,
            "реальная прошивка не изменила индикатор ни разу за 600k циклов "
            f"(writes={stats['write_pages']})",
        )
        self.assertTrue(changed_to.strip(), f"экран должен ожить: {changed_to!r}")
        self.assertGreater(stats["display_writes"], 0, "страницы дисплея не писались")
        self.assertTrue(
            {0x82, 0x92, 0xA2} <= set(stats["write_pages"]),
            f"мультиплексор CPU 0x02D9 не писал сегменты/сетку: {stats['write_pages']}",
        )
        self.assertGreater(stats["timer0_calls"], 0, "тело мукса не исполнялось")
        self.assertGreaterEqual(board.display.grid, 0, "сетка не выбиралась")

    def test_keyboard_page_is_served_and_key_events_reach_the_firmware(self):
        """Страница 0x91 обслуживается, а событие клавиши доходит до ядра.

        Честная граница наблюдений: в состоянии «самотест не пройден»
        (дефолтная проводка ППИ) прошивка стоит в своей ветке ошибки и
        матрицу не сканирует - поэтому ``keyboard_reads`` остаётся 0.
        Дефолтный wiring INT0 по нажатию НЕ поднимает (INT0 = линия
        отключения питания, см. board/cashboard.py WIRING); здесь импульс
        включается явно, чтобы проверить: событие клавиши доходит до
        настоящего вектора 0x0003 ровно один раз.

        Семантика страницы 0x91 — активная-ВЫСОКАЯ маска нажатий, а
        колонки стробируются линией выбора знакоместа (0xA2): без валидного
        знакоместа строка честно читается нулём.  Оба факта доказаны
        разбором настоящих байтов (см. docs/usage.md §4.3).
        """
        runner = self._fresh(wiring={"INT0_ON_KEYPRESS": True})
        bus = runner.bus
        board = runner.board
        # валидное знакоместо — иначе колонки не стробятся
        bus.ext_write(0xA200, 3)
        board.keyboard.press("5")
        try:
            # 1) страница отдаёт матрицу: нажатая клавиша видна (активная
            #    высокая маска: покой 0x00, нажатие = бит колонки)
            pressed_row = None
            for row in range(8):
                value = bus.ext_read(0x9130 + row)
                if value != 0x00:
                    pressed_row = (row, value)
                    break
            self.assertIsNotNone(
                pressed_row, "нажатая клавиша не читается страницей 0x91"
            )
            # собственные пробные чтения выше тоже попадают в счётчик шины
            probed_reads = bus.read_count(0x91)
            # 2) событие клавиши реально доходит до прошивки: вектор INT0
            runner.advance(100_000)
            stats = runner.stats()
            self.assertEqual(
                stats["vector_dispatches"].get("0x3", 0), 1,
                f"INT0-вектор должен сработать ровно один раз: {stats}",
            )
            # 3) честное наблюдение: idle-состояние прошивки матрицу не читает
            #    (она стоит в ветке ошибки самотеста) - мы это измеряем,
            #    а не замалчиваем: за 100k циклов шина не получила НИ ОДНОГО
            #    чтения 0x91 сверх наших собственных проб
            self.assertEqual(stats["keyboard_reads"], probed_reads, stats)
            self.assertEqual(stats["timer1_calls"], 0, stats)
        finally:
            board.keyboard.release("5")
        row, _value = pressed_row
        self.assertEqual(
            bus.ext_read(0x9130 + row), 0x00,
            "после отпускания строка должна вернуться в 0x00",
        )

    def test_diagnosis_reflects_the_rebased_truth(self):
        from recover.realrun import diagnose_consumers

        report = diagnose_consumers(self.program, self.rom)
        # вектор сброса указывает внутрь дампа: entry 0x0A06 = record 0x8A06
        reset = report["reset"]
        self.assertEqual(reset["entry"], 0x0A06)
        self.assertTrue(reset["covered"],
                        "после rebasing вектор сброса покрыт дампом")
        self.assertIn("0x8A06", reset["note"])
        self.assertEqual(report["isr"]["timer1_refresh"]["in_dump"], "FUN_CODE_8135")
        buffer = report["display_buffer"]
        self.assertIn("RAM 0x50", buffer["addresses"])
        self.assertTrue(buffer["writer_functions"],
                        "в дампе есть писатели буфера дисплея")
        # статически писатели недостижимы ИЗ refresh ISR (они не в цепочке
        # 0x001B) - это правда графа вызовов, но она больше не означает
        # "производителя нет": main loop от вектора сброса работает
        self.assertEqual(buffer["reachable_from_isr"], [])
        self.assertNotIn("PRODUCER MISSING", buffer["verdict"])
        self.assertIn("producers RUN", buffer["verdict"])
        self.assertIn("0x0A06", buffer["verdict"])
        self.assertEqual(report["scanner"]["callers_in_dump"], [])
        # динамическая проверка вердикта: запускаем реальный образ и смотрим,
        # что main loop реально заполняет буфер индикатора RAM 0x50..0x5F
        runner = self._fresh()
        runner.advance(400_000)
        self.assertFalse(runner.halted, runner.halt_reason)
        self.assertGreater(runner.stats()["timer0_calls"], 0, "мукс не запущен")
        self.assertTrue(
            any(byte != 0 for byte in runner.cpu.ram[0x50:0x60]),
            "main loop обязан заполнить буфер индикатора RAM 0x50..0x5F",
        )

    def test_session_defaults_to_real_hex_instead_of_demo(self):
        from recover.session import RecoveredFirmwareSession

        session = RecoveredFirmwareSession()
        try:
            session.boot()
            status = session.status()
            self.assertEqual(status["boot_error"], "")
            self.assertEqual(status["source"], "recovered",
                             "GUI-путь обязан исполнять реальный hex, а не demo")
            self.assertTrue(status["real_hex"])
            self.assertEqual(status["entry"], "0x0A06")
            self.assertTrue(status["entry_covered"],
                            "вектор сброса 0x0A06 покрыт дампом (record 0x8A06)")
            self.assertFalse(session.demo_enabled,
                             "demo доступен только по явному флагу")
            session.run(500_000)
            status = session.status()
            self.assertGreater(status["mux_calls"], 0,
                               "тело мукса (Timer-0) не вызывалось")
            self.assertEqual(status["isr_calls"], 0,
                             "Timer-1 прошивка не запускает - честный ноль")
            self.assertGreater(status["steps"], 0, "шаги должны идти")
            self.assertGreater(status["cpu_instructions"], 0)
            self.assertTrue(status["consumer"], "диагноз потребителя обязан быть")
            self.assertTrue(status["display"].strip(),
                            "экран обязан ожить от настоящего исполнения")
        finally:
            try:
                session.reset()
            except Exception:  # noqa: BLE001 - сброс не должен ломать тест
                pass


class TestRestoredBoot(unittest.TestCase):
    """Восстановленная загрузка настоящей прошивки (проводка RECOVERED_WIRING).

    Проверяет то, что найдено трассировкой (см. docs/usage.md §4.3 и
    ``tools/_diag_real_boot.py``): с ППИ вне диапазона самотеста и с
    «полевыми» устройствами-ответчиками настоящая прошивка проходит свой
    самотест ОЗУ, доходит до главного цикла и САМА сканирует матрицу
    клавиатуры, кладя коды в своё кольцо.
    """

    @classmethod
    def setUpClass(cls):
        from recover.hal import CashRegisterHAL, load_rom
        cls.load_rom = load_rom
        cls.CashRegisterHAL = CashRegisterHAL
        cls.rom = load_rom()

    def setUp(self):
        from board.cashboard import CashRegisterBoard, RECOVERED_WIRING
        from recover.realrun import RealRunner

        self.board = CashRegisterBoard(wiring=RECOVERED_WIRING)
        hal = self.CashRegisterHAL(board=self.board, rom=self.rom, strict=True)
        self.runner = RealRunner(hal=hal, rom=self.rom)
        self.cpu = getattr(self.runner, "cpu", None) or getattr(self.runner, "_cpu")

    def _boot_to_gate(self, limit_cycles: int = 12_000_000) -> bool:
        """Крутит эмуляцию до петли опроса кольца (CPU 0x0AD5..0x0AD8)."""
        for _ in range(limit_cycles // 20_000):
            self.runner.advance(20_000)
            if 0x0AD5 <= self.cpu.pc <= 0x0AD8:
                return True
            if self.runner.halted:
                return False
        return False

    def test_self_test_passes_and_boot_reaches_main_loop(self):
        """Самотест ОЗУ пройден, загрузка идёт до главного цикла."""
        reached = self._boot_to_gate()
        self.assertFalse(self.runner.halted, self.runner.halt_reason)
        self.assertTrue(reached, "загрузка не дошла до петли 0x0AD5 (pc=%#x)"
                        % self.cpu.pc)
        self.assertNotIn("h0000", self.board.display.text(),
                         "экрана ошибки самотеста быть не должно")
        stats = self.runner.stats()
        self.assertGreater(stats["mux_calls"], 100, "мукс обязан работать")

    def test_firmware_scans_the_matrix_itself(self):
        """Прошивка сама читает страницу клавиатуры 0x91 (наш ISR-скан)."""
        self._boot_to_gate()
        self.assertGreater(self.runner.stats()["keyboard_reads"], 0,
                           "прошивка должна сама сканировать матрицу 0x91")

    def test_service_key_passes_boot_gate_and_ring_receives_codes(self):
        """Клавиша «1» (код 0x10) проходит ворота, и коды ложатся в кольцо."""
        self.assertTrue(self._boot_to_gate())
        before = self.cpu.ram[0x4F]
        self.board.keyboard.press("1")
        self.runner.advance(200_000)
        self.board.keyboard.release("1")
        self.runner.advance(300_000)
        # кольцо XDATA 0x0C80: указатель записи сдвинулся
        self.assertNotEqual(self.cpu.ram[0x4F], before,
                            "код клавиши не попал в кольцо прошивки")
        # «1» проходит стартовые ворота 0x5C6D и прошивка рисует свой вывод
        self.assertNotEqual(self.board.display.text().strip(), "",
                            "экран обязан показать вывод прошивки")


if __name__ == "__main__":
    unittest.main(verbosity=2)
