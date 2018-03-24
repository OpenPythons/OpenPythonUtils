import sys
import time

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UcError, \
    UC_HOOK_MEM_READ_UNMAPPED
from unicorn.arm_const import *

from .address import MemoryMap, MemoryRegion, PeripheralAddress
from .context import CpuContext
from .firmware import Firmware
from .state import CpuState
from .util import to_bytes, from_bytes


class CPU:
    def __init__(self, firmware: Firmware, state: CpuState, context: CpuContext = None):
        self.firmware = firmware
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.context = CpuContext(self.uc) if context is None else context.with_uc(self.uc)
        self.state = state
        self.has_error = None
        self.init()

    def init(self):
        self.firmware.refresh()
        self.state.verify()
        self.init_memory()
        self.init_hook()
        self.init_misc()

    def init_misc(self):
        sp = MemoryMap.RAM.address + self.state.ram_size
        addr = from_bytes(self.firmware[4:8])
        self.uc.mem_write(MemoryMap.FLASH.address, self.firmware.buffer)
        self.uc.mem_write(MemoryMap.FLASH.address, to_bytes(sp))
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hook_unmapped)
        self.uc.reg_write(UC_ARM_REG_PC, addr)

    def run(self):
        INST_SIZE = 2
        try:
            while self.step():
                pass
        except UcError as e:
            print("ERROR:", e)
            addr = self.uc.reg_read(UC_ARM_REG_PC)
            self.debug_addr(addr - INST_SIZE * 4, count=3)
            print(">", end=" ")
            self.debug_addr(addr)
            self.debug_addr(addr + INST_SIZE, count=3)

    def step(self):
        addr = self.uc.reg_read(UC_ARM_REG_PC)
        self.uc.emu_start(addr | 1, MemoryMap.FLASH.address_until, 0, self.state.cycle)
        # debug_addr(addr)

        if self.has_error:
            raise UcError(0)

        return True

    def init_memory(self):
        for region in MemoryMap:  # type: MemoryRegion
            self.uc.mem_map(region.address, region.size, region.uc_mode)

    def init_hook(self):
        peripheral = MemoryMap.PERIPHERAL

        self.uc.hook_add(
            UC_HOOK_MEM_READ,
            self.hook_peripheral_read,
            None,
            peripheral.address,
            peripheral.address_until,
        )

        self.uc.hook_add(
            UC_HOOK_MEM_WRITE,
            self.hook_peripheral_write,
            None,
            peripheral.address,
            peripheral.address_until
        )

    def hook_peripheral_read(self, uc: Uc, access, address, size, value, data):
        if address == PeripheralAddress.UMPORT_CONTROLLER_RAM_SIZE:
            uc.mem_write(address, to_bytes(self.state.ram_size))
        elif address == PeripheralAddress.UMPORT_CONTROLLER_STACK_SIZE:
            uc.mem_write(address, to_bytes(self.state.stack_size))
        elif address == PeripheralAddress.UART0_RXR:
            if self.state.stack:
                uc.mem_write(address, to_bytes(self.state.stack.pop(0)))
            else:
                uc.mem_write(address, to_bytes(0))
        elif address == PeripheralAddress.RTC_TICKS_MS:
            uc.mem_write(address, to_bytes(int((time.time() - self.state.epoch) * 1000)))
        elif address == PeripheralAddress.RTC_TICKS_US:
            uc.mem_write(address, to_bytes(int((time.time() - self.state.epoch) * 1000 * 1000)))
        else:
            print("read", access, hex(address), size, value, data)

    def hook_peripheral_write(self, uc: Uc, access, address, size, value, data):
        global pending_addr, exception_addr, ichr_addr
        if address == PeripheralAddress.UMPORT_CONTROLLER_PENDING:
            print("UMPORT_CONTROLLER_PENDING", value)
            # pending_addr = address
        elif address == PeripheralAddress.UMPORT_CONTROLLER_EXCEPTION:
            print("UMPORT_CONTROLLER_EXCEPTION", value)
            # exception_addr = to_bytes(value)
        elif address == PeripheralAddress.UMPORT_CONTROLLER_INTR_CHAR:
            # ichr_addr = value
            print("UMPORT_CONTROLLER_INTR_CHAR", value)
        elif address == PeripheralAddress.UART0_TXR:
            print(chr(value), end="")
            sys.stdout.flush()
        else:
            print("write", access, hex(address), size, value, data)

    def hook_unmapped(self, uc: Uc, access, address, size, value, data):
        global has_error
        print("unmapped:", access, hex(address), size, value, data)
        uc.emu_stop()
        has_error = True

    def report_memory(self):
        total_size = 0
        for mem_start, mem_end, perm in self.uc.mem_regions():
            total_size += mem_end - mem_start
            print("memory:", hex(mem_start), hex(mem_end - mem_start), perm)
        print("memory total:", total_size / 1024, "kb")

    INST_SIZE = 2

    def debug_addr(self, addr, count=1):
        INST_SIZE = 2
        firmware = self.firmware.buffer
        flash_address = MemoryMap.FLASH.address
        for inst in self.cs.disasm(
                firmware[addr - flash_address:addr - flash_address + INST_SIZE * count], addr, count):
            print(hex(inst.address), inst.mnemonic, inst.op_str)
