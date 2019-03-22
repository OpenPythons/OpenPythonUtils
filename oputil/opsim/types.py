from typing import Optional, Set

from dataclasses import dataclass, field


@dataclass(unsafe_hash=True)
class RawFunction:
    address: int
    size: Optional[int]
    name: str
    path: str

    def __contains__(self, item):
        return self.address <= item < self.address + self.size