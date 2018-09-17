from typing import Optional, Set

from dataclasses import dataclass, field


@dataclass(unsafe_hash=True)
class Function:
    address: int
    size: Optional[int]
    name: str
    path: str

    has_indirect: bool = False
    joint_set: Set[int] = field(default_factory=set, repr=False, hash=False)
    stop_set: Set[int] = field(default_factory=set, repr=False, hash=False)

    def __contains__(self, item):
        return self.address <= item < self.address + self.size