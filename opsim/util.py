from bisect import bisect_right
from collections import Mapping
from typing import Dict, Optional, Tuple

from opsim.types import Function


def from_bytes(b):
    return int.from_bytes(b, byteorder="little")


def to_bytes(n):
    return int.to_bytes(n & 0xFFFFFFFF, 4, byteorder="little")


class MapLookupTable(Mapping):
    def __init__(self, table: Dict[int, Function]):
        seq = sorted(table.items())
        _, first = seq[0]
        _, last = seq[-1]
        self.seq = seq
        self.vmap = [v for k, v in seq]
        self.kmap = [k for k, v in seq]
        self.vset = set(self.vmap)
        self.min = first.address
        self.max = last.address + last.size

    def _get(self, address: int) -> Function:
        index = bisect_right(self.kmap, address) - 1
        return self.vmap[index]

    def get_range(self, address: int) -> Tuple[int, int]:
        function = self._get(address)
        return function.address, function.address + function.size

    def __getitem__(self, address: int) -> Optional[Function]:
        if not self.min <= address < self.max:
            return None

        function = self._get(address)
        return function

    def __iter__(self):
        return iter(self.kmap)

    def __len__(self):
        return len(self.kmap)

    def __contains__(self, item):
        if isinstance(item, int):
            return self[item] is not None
        elif isinstance(item, Function):
            return item in self.vset

        raise TypeError()


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
