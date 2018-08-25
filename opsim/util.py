from bisect import bisect_right
from collections import Mapping


def from_bytes(b):
    return int.from_bytes(b, byteorder="little")


def to_bytes(n):
    return int.to_bytes(n & 0xFFFFFFFF, 4, byteorder="little")


class MapLookupTable(Mapping):
    def __init__(self, table):
        self.table = [k for k, _ in sorted(table)]
        self.table2 = [v for _, v in sorted(table)]
        self.max = self.table[-1]

    def __getitem__(self, key):
        key = int(key)
        if not 0 <= key <= self.max:
            return None
        return self.table2[bisect_right(self.table, key) - 1]

    def __iter__(self):
        return iter(range(0, self.max + 1))

    def __len__(self):
        return self.max


def hex32(n):
    n &= 0xFFFFFFFF
    return "0x" + hex(n)[2:].zfill(8)


def get_CPSR(cpsr):
    FV = 1 << 28
    FC = 1 << 29
    FZ = 1 << 30
    FN = 1 << 31

    r = ""
    for f, s in zip((FN, FZ, FC, FV), "NZCV"):
        r += s if f & cpsr else " "

    return r