# -*- coding: utf-8 -*-
"""Разведка: парсер дампов + диспетчер ETIM по адресу 0x8000 (только чтение)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "процессоры")


def load_hex(path, tolerate=True):
    """Intel HEX -> {addr: byte}, список предупреждений."""
    mem, warns = {}, []
    with open(path, "r", encoding="ascii", errors="replace") as fh:
        for no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                warns.append((no, "no-colon", line[:20]))
                continue
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError:
                warns.append((no, "bad-hex", line[:20]))
                continue
            if len(raw) < 4:
                warns.append((no, "short", line[:20]))
                continue
            count, hi, lo, rtype = raw[0], raw[1], raw[2], raw[3]
            body = raw[4:]
            if len(body) < count + 1:
                warns.append((no, "truncated(need %d, got %d)" % (count + 1, len(body)),
                              line[:20]))
                if not tolerate:
                    continue
            else:
                if (sum(raw[:4 + count + 1]) & 0xFF) != 0:
                    warns.append((no, "checksum", line[:20]))
                    if not tolerate:
                        continue
            addr = (hi << 8) | lo
            if rtype == 0:
                for j, b in enumerate(body[:count]):
                    mem[addr + j] = b
            elif rtype == 1:
                break
    return mem, warns


def coverage(mem):
    if not mem:
        return None
    lo, hi = min(mem), max(mem)
    present = len(mem)
    span = hi - lo + 1
    return lo, hi, present, span


def show(name, mem, warns):
    c = coverage(mem)
    print("%-16s bytes=%-6d range=%s" % (name, len(mem),
          "0x%04X..0x%04X" % (c[0], c[1]) if c else "-"))
    for w in warns[:6]:
        print("      warn line %d: %s %s" % w)
    if len(warns) > 6:
        print("      ... ещё предупреждений: %d" % (len(warns) - 6))


if __name__ == "__main__":
    for fn in sorted(os.listdir(DIR)):
        if not fn.endswith(".hex"):
            continue
        mem, warns = load_hex(os.path.join(DIR, fn))
        show(fn, mem, warns)

    print("\n=== nm27c512n.hex ===")
    etim, warns = load_hex(os.path.join(HERE, "firmware", "nm27c512n.hex"))
    show("nm27c512n", etim, warns)

    print("\n=== сырьё ETIM по 0x8000..0x80FF ===")
    buf = [etim.get(a, None) for a in range(0x8000, 0x8100)]
    for off in range(0, 0x100, 16):
        row = buf[off:off + 16]
        print("%04X: %s" % (0x8000 + off,
                            " ".join("%02X" % b if b is not None else "??" for b in row)))
