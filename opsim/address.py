from enum import IntEnum, Enum
from typing import NamedTuple

from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC


class MemoryRegion(NamedTuple):
    address: int
    size: int
    uc_mode: int

KB = 1024

class MemoryMap(Enum):
    FLASH = MemoryRegion(0x08000000, 256 * KB, UC_PROT_READ | UC_PROT_EXEC)
    SRAM = MemoryRegion(0x20000000, 64 * KB, UC_PROT_READ | UC_PROT_WRITE)
    PERIPHERAL = MemoryRegion(0x40000000, 4 * KB, UC_PROT_READ | UC_PROT_WRITE)
    RAM = MemoryRegion(0x60000000, 192 * KB, UC_PROT_READ | UC_PROT_WRITE)
    SYSCALL_BUFFER = MemoryRegion(0xE0000000, 16 * KB, UC_PROT_READ | UC_PROT_WRITE)


    @property
    def address(self) -> int:
        return self.value.address

    @property
    def size(self) -> int:
        return self.value.size

    @property
    def uc_mode(self) -> int:
        return self.value.uc_mode

    @property
    def address_until(self) -> int:
        return self.address + self.size


class PeripheralAddress(IntEnum):
    OP_IO_TXR = 0x40000000
    OP_IO_RXR = 0x40000004
    OP_IO_EXR = 0x40000008
    OP_IO_REDIRECT = 0x4000000c
    OP_IO_TXB = 0x40000010
    OP_IO_RXB = 0x40000014
    OP_CON_PENDING = 0x40000100
    OP_CON_EXCEPTION = 0x40000104
    OP_CON_INTR_CHAR = 0x40000108
    OP_CON_RAM_SIZE = 0x4000010c
    OP_CON_IDLE = 0x40000110
    OP_CON_INSNS = 0x40000114
    OP_RTC_TICKS_MS = 0x40000200
