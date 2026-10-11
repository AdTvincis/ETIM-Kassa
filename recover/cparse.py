"""A tiny recursive-descent parser for Ghidra's pseudo-C.

The input is *not* valid C (it contains things like ``undefined 22.1;`` and
``SUB41(x,0)``), but its statement and expression grammar is standard C, so a
hand-written parser is both short and more predictable than trying to force a
real C parser to accept it.

The output is a small AST that :mod:`recover.interp` executes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

__all__ = ["parse_body", "Token", "tokenize", "ParseError"]


class ParseError(SyntaxError):
    def __init__(self, message: str, token: "Token") -> None:
        super().__init__(f"{message} at {token!r}")
        self.token = token


# --------------------------------------------------------------------- tokens
TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>0[xX][0-9a-fA-F]+(?:[uUlL]{0,3})|\d+(?:[uUlL]{0,3}))
  | (?P<chr>'(?:\\.|[^'\\])*')
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<name>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<op><<=|>>=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|[{}()\[\];,:?~!%^&*\-+=<>/|.])
    """,
    re.VERBOSE,
)


@dataclass(slots=True)
class Token:
    kind: str
    text: str
    pos: int

    def __repr__(self) -> str:
        return f"{self.kind}:{self.text!r}"


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = TOKEN_RE.match(text, pos)
        if not m:
            raise ParseError(f"cannot tokenize {text[pos:pos+20]!r}", Token("bad", text[pos:pos+1], pos))
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        tokens.append(Token(kind, m.group(), m.start()))
    tokens.append(Token("eof", "", n))
    return tokens


# ------------------------------------------------------------------------ AST
@dataclass
class Expr:
    kind: str
    a: object = None
    b: object = None
    c: object = None
    pos: int = 0


@dataclass
class Stmt:
    kind: str
    expr: object = None
    body: Optional["Stmt"] = None
    els: Optional["Stmt"] = None
    items: List["Stmt"] = field(default_factory=list)
    name: str = ""
    init: object = None
    step: object = None
    vars: List[Tuple[str, str]] = field(default_factory=list)
    pos: int = 0


# -------------------------------------------------------------------- parser
class Parser:
    def __init__(self, tokens: Sequence[Token]) -> None:
        self.toks = list(tokens)
        self.i = 0

    # ---------------------------------------------------------------- helpers
    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def at(self, text: str) -> bool:
        return self.tok.text == text

    def at_name(self, name: str) -> bool:
        return self.tok.kind == "name" and self.tok.text == name

    def advance(self) -> Token:
        token = self.toks[self.i]
        if token.kind != "eof":
            self.i += 1
        return token

    def accept(self, text: str) -> bool:
        if self.at(text):
            self.advance()
            return True
        return False

    def expect(self, text: str) -> Token:
        if not self.at(text):
            raise ParseError(f"expected {text!r}", self.tok)
        return self.advance()

    def error(self, message: str):
        raise ParseError(message, self.tok)

    # -------------------------------------------------------------- statements
    def parse_statements(self, until: str = "}") -> Stmt:
        items: List[Stmt] = []
        start = self.tok.pos
        while not self.at(until) and self.tok.kind != "eof":
            stmt = self.parse_statement()
            if stmt is not None:
                items.append(stmt)
        return Stmt("block", items=items, pos=start)

    def parse_statement(self) -> Optional[Stmt]:
        token = self.tok
        if self.accept(";"):
            return Stmt("empty", pos=token.pos)
        if self.at("{"):
            self.advance()
            block = self.parse_statements("}")
            self.expect("}")
            return block
        text = token.text
        if text == "if":
            return self.parse_if()
        if text == "while":
            return self.parse_while()
        if text == "do":
            return self.parse_do()
        if text == "for":
            return self.parse_for()
        if text == "switch":
            return self.parse_switch()
        if text == "return":
            self.advance()
            value = None if self.at(";") else self.parse_expression()
            self.expect(";")
            return Stmt("return", expr=value, pos=token.pos)
        if text in ("break", "continue"):
            self.advance()
            self.expect(";")
            return Stmt(text, pos=token.pos)
        if text == "goto":
            self.advance()
            target = self.advance()
            if target.kind != "name":
                self.error("goto needs a label")
            self.expect(";")
            return Stmt("goto", name=target.text, pos=token.pos)
        if token.kind == "name" and self.i + 1 < len(self.toks) and self.toks[self.i + 1].text == ":":
            self.advance()
            self.advance()
            return Stmt("label", name=token.text, pos=token.pos)
        decl = self.try_parse_declaration()
        if decl is not None:
            return decl
        expr = self.parse_expression()
        self.expect(";")
        return Stmt("expr", expr=expr, pos=token.pos)

    def parse_if(self) -> Stmt:
        pos = self.advance().pos
        self.expect("(")
        cond = self.parse_expression()
        self.expect(")")
        body = self.parse_statement()
        els = None
        if self.at_name("else"):
            self.advance()
            els = self.parse_statement()
        return Stmt("if", expr=cond, body=body, els=els, pos=pos)

    def parse_while(self) -> Stmt:
        pos = self.advance().pos
        self.expect("(")
        cond = self.parse_expression()
        self.expect(")")
        return Stmt("while", expr=cond, body=self.parse_statement(), pos=pos)

    def parse_do(self) -> Stmt:
        pos = self.advance().pos
        body = self.parse_statement()
        if not self.at_name("while"):
            self.error("do without while")
        self.advance()
        self.expect("(")
        cond = self.parse_expression()
        self.expect(")")
        self.expect(";")
        return Stmt("do", expr=cond, body=body, pos=pos)

    def parse_for(self) -> Stmt:
        pos = self.advance().pos
        self.expect("(")
        init = None if self.at(";") else self.parse_expression()
        self.expect(";")
        cond = None if self.at(";") else self.parse_expression()
        self.expect(";")
        step = None if self.at(")") else self.parse_expression()
        self.expect(")")
        return Stmt("for", init=init, expr=cond, step=step, body=self.parse_statement(), pos=pos)

    def parse_switch(self) -> Stmt:
        pos = self.advance().pos
        self.expect("(")
        subject = self.parse_expression()
        self.expect(")")
        self.expect("{")
        cases: List[Tuple[Optional[object], Stmt]] = []
        prelude: List[Stmt] = []
        while not self.at("}") and self.tok.kind != "eof":
            if self.at_name("case"):
                self.advance()
                value = self.parse_expression()
                self.expect(":")
                body = self.parse_statements_until_case()
                cases.append((value, body))
            elif self.at_name("default"):
                self.advance()
                self.expect(":")
                cases.append((None, self.parse_statements_until_case()))
            else:
                prelude.append(self.parse_statement())
        self.expect("}")
        return Stmt("switch", expr=subject, items=[c[1] for c in cases], vars=[], pos=pos,
                    init=[c[0] for c in cases], body=Stmt("block", items=prelude))

    def parse_statements_until_case(self) -> Stmt:
        items: List[Stmt] = []
        start = self.tok.pos
        while not (self.at("}") or self.at_name("case") or self.at_name("default")) and self.tok.kind != "eof":
            stmt = self.parse_statement()
            if stmt is not None:
                items.append(stmt)
        return Stmt("block", items=items, pos=start)

    # ------------------------------------------------------------- declarations
    TYPE_WORDS = {
        "char", "byte", "undefined", "undefined1", "undefined2", "undefined4",
        "int", "uint", "long", "ulong", "short", "ushort", "bool", "float",
        "double", "void", "sbyte", "uint3", "code", "data", "xdata", "signed",
        "unsigned", "size_t", "word", "dword",
    }

    def try_parse_declaration(self) -> Optional[Stmt]:
        """Recognise a local declaration; ``None`` when this is not one."""
        save = self.i
        if self.tok.kind != "name" or self.tok.text not in self.TYPE_WORDS:
            # an unknown type word is still a declaration if followed by a name
            if not (self.tok.kind == "name" and self.i + 1 < len(self.toks)
                    and self.toks[self.i + 1].kind == "name"
                    and self._declaration_lookahead()):
                return None
        type_name = self.advance().text
        while self.at_name("signed") or self.at_name("unsigned") or self.at_name("int") and type_name in ("short", "long"):
            type_name += " " + self.advance().text
        stars = ""
        while self.accept("*"):
            stars += "*"
        if self.tok.kind != "name":
            self.i = save
            return None
        names: List[Tuple[str, str]] = []
        while True:
            name = self.advance().text
            suffix = stars
            while self.accept("*"):
                suffix += "*"
            array = ""
            if self.at("["):
                depth = 0
                parts = []
                while not (self.at("]") and depth == 0):
                    t = self.advance()
                    parts.append(t.text)
                    if t.text == "[":
                        depth += 1
                    elif t.text == "]":
                        depth -= 1
                    if t.kind == "eof":
                        self.error("unterminated array declarator")
                self.expect("]")
                array = "[" + "".join(parts) + "]"
            names.append((f"{name}{array}", type_name.strip() + " " + suffix))
            if self.accept(","):
                while self.accept("*"):
                    pass
                continue
            break
        if not self.accept(";"):
            self.i = save
            return None
        return Stmt("decl", vars=names, pos=save)

    def _declaration_lookahead(self) -> bool:
        j = self.i + 1
        while j < len(self.toks) and self.toks[j].text == "*":
            j += 1
        if j >= len(self.toks) or self.toks[j].kind != "name":
            return False
        j += 1
        return j < len(self.toks) and self.toks[j].text in (";", ",", "=", "[")

    # -------------------------------------------------------------- expressions
    def parse_expression(self) -> Expr:
        return self.parse_comma()

    def parse_comma(self) -> Expr:
        expr = self.parse_assignment()
        while self.at(","):
            pos = self.advance().pos
            right = self.parse_assignment()
            expr = Expr("comma", expr, right, pos=pos)
        return expr

    ASSIGN_OPS = ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=")

    def parse_assignment(self) -> Expr:
        left = self.parse_conditional()
        if self.tok.text in self.ASSIGN_OPS:
            op = self.advance().text
            right = self.parse_assignment()
            return Expr("assign", left, right, c=op, pos=left.pos)
        return left

    def parse_conditional(self) -> Expr:
        cond = self.parse_binary(0)
        if self.at("?"):
            pos = self.advance().pos
            then = self.parse_expression()
            self.expect(":")
            other = self.parse_conditional()
            return Expr("cond", cond, then, other, pos=pos)
        return cond

    # precedence table, loosest first
    LEVELS = [
        ("||",), ("&&",), ("|",), ("^",), ("&",),
        ("==", "!="), ("<", ">", "<=", ">="), ("<<", ">>"),
        ("+", "-"), ("*", "/", "%"),
    ]

    #: ``op -> its level`` для precedence climbing (строится один раз;
    #: операторы между уровнями не повторяются, проверяется по LEVELS).
    _OP_LEVEL = {
        op: i for i, ops in enumerate(LEVELS) for op in ops
    }

    def parse_binary(self, level: int) -> Expr:
        """Precedence climbing.

        Было: рекурсия по каждому уровню (``parse_binary(level+1)`` спускался
        до дна даже для атома) — ~11 вложенных вызовов и 11 проверок на каждый
        узел выражения (cProfile бута: 601K вызовов parse_binary).  Стало: один
        цикл, вниз рекурсия только по реально присутствующим операторам;
        таблица приоритетов и левая ассоциативность (правая часть зовётся с
        ``op_level + 1``) — ровно те же, что в ``LEVELS``.
        """
        if level >= len(self.LEVELS):
            return self.parse_unary()
        op_level = self._OP_LEVEL
        left = self.parse_unary()
        while True:
            lvl = op_level.get(self.tok.text)
            if lvl is None or lvl < level:
                return left
            op = self.advance().text
            right = self.parse_binary(lvl + 1)
            left = Expr("bin", left, right, c=op, pos=left.pos)

    def parse_unary(self) -> Expr:
        token = self.tok
        text = token.text
        if text in ("-", "+", "!", "~", "*", "&"):
            self.advance()
            operand = self.parse_unary()
            return Expr("un", operand, c=text, pos=token.pos)
        if text in ("++", "--"):
            self.advance()
            operand = self.parse_unary()
            return Expr("preinc", operand, c=text, pos=token.pos)
        if text == "(":
            # could be a cast
            save = self.i
            self.advance()
            cast = self.try_parse_cast_type()
            if cast is not None and self.at(")"):
                self.advance()
                if self.at("{") or self.at(";"):
                    return Expr("cast_raw", pos=token.pos)
                operand = self.parse_unary()
                return Expr("cast", operand, c=cast, pos=token.pos)
            self.i = save
        return self.parse_postfix()

    def try_parse_cast_type(self) -> Optional[str]:
        if self.tok.kind != "name":
            return None
        text = self.tok.text
        if text not in self.TYPE_WORDS and text not in ("__uint8", "uint8_t", "int8_t"):
            return None
        parts = []
        parts.append(self.advance().text)
        while self.at_name("signed") or self.at_name("unsigned") or self.at_name("int"):
            if self.at_name("int") and parts[-1] not in ("short", "long"):
                break
            parts.append(self.advance().text)
        while self.accept("*"):
            parts.append("*")
        return " ".join(parts)

    def parse_postfix(self) -> Expr:
        expr = self.parse_primary()
        while True:
            if self.at("["):
                pos = self.advance().pos
                index = self.parse_expression()
                self.expect("]")
                expr = Expr("index", expr, index, pos=pos)
            elif self.at("("):
                pos = self.advance().pos
                args: List[Expr] = []
                if not self.at(")"):
                    args.append(self.parse_assignment())
                    while self.accept(","):
                        args.append(self.parse_assignment())
                self.expect(")")
                expr = Expr("call", expr, args, pos=pos)
            elif self.at(".") or self.at("->"):
                op = self.advance().text
                field = self.advance().text
                expr = Expr("field", expr, field, c=op, pos=expr.pos)
            elif self.at("++") or self.at("--"):
                op = self.advance().text
                expr = Expr("postinc", expr, c=op, pos=expr.pos)
            else:
                return expr

    def parse_primary(self) -> Expr:
        token = self.tok
        if token.kind == "num":
            self.advance()
            text = re.sub(r"[uUlL]+$", "", token.text)
            value = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
            return Expr("const", value, pos=token.pos)
        if token.kind == "chr":
            self.advance()
            return Expr("const", _decode_char(token.text), pos=token.pos)
        if token.kind == "str":
            self.advance()
            return Expr("str", token.text, pos=token.pos)
        if token.kind == "name":
            self.advance()
            return Expr("var", token.text, pos=token.pos)
        if token.text == "(":
            self.advance()
            expr = self.parse_expression()
            self.expect(")")
            return expr
        self.error(f"unexpected token {token.text!r}")


def _decode_char(literal: str) -> int:
    """Decode a C character literal, including ``\\x`` and octal escapes."""
    body = literal[1:-1]
    if not body:
        return 0
    if body.startswith("\\"):
        simple = {
            "n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "'": 39, '"': 34,
            "b": 8, "f": 12, "v": 11, "a": 7, "?": 63,
        }
        escape = body[1]
        if escape in simple:
            return simple[escape]
        if escape == "x":
            return int(body[2:], 16) & 0xFF
        try:
            return int(body[1:], 8) & 0xFF
        except ValueError:
            return ord(escape) & 0xFF
    return ord(body[0]) & 0xFF


def parse_body(text: str) -> Stmt:
    """Parse a function body (the text between the outer braces)."""
    tokens = tokenize(text)
    parser = Parser(tokens)
    block = parser.parse_statements(until="\0")
    if parser.tok.kind != "eof":
        parser.error("trailing tokens")
    return block
