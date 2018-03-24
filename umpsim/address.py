from enum import IntEnum, Enum
from typing import NamedTuple

from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC


class MemoryRegion(NamedTuple):
    address: int
    size: int
    uc_mode: int



class MemoryMap(Enum):
    FLASH = MemoryRegion(0x08000000, 0x100000, UC_PROT_READ | UC_PROT_EXEC)
    SRAM = MemoryRegion(0x20000000, 0x80000, UC_PROT_READ | UC_PROT_WRITE)
    STACK = MemoryRegion(0x3FFF0000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    PERIPHERAL = MemoryRegion(0x40000000, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
    SYSCALL_BUFFER = MemoryRegion(0xE0100000, 0x10000, UC_PROT_READ)

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
    UART0_TXR = 0x40000000
    UART0_RXR = 0x40000004
    UMPORT_CONTROLLER_PENDING = 0x40000100
    UMPORT_CONTROLLER_EXCEPTION = 0x40000104
    UMPORT_CONTROLLER_INTR_CHAR = 0x40000108
    UMPORT_CONTROLLER_RAM_SIZE = 0x4000010c
    UMPORT_CONTROLLER_STACK_SIZE = 0x40000110
    UMPORT_CONTROLLER_IDLE = 0x40000114
    UMPORT_CONTROLLER_INSNS = 0x40000118
    RTC_TICKS_MS = 0x40000300
    RTC_TICKS_US = 0x40000304
