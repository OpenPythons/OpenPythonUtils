import json
import sys
import time

from capstone import Cs, CsInsn, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UcError, \
    UC_HOOK_MEM_READ_UNMAPPED, UC_ERR_READ_UNMAPPED, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import *

from opsim.debugger import HELPER_FUNCTIONS
from .address import MemoryMap, MemoryRegion, PeripheralAddress
from .firmware import Firmware
from .state import CpuState
from .util import to_bytes, from_bytes


class CPU:
    def __init__(self, firmware: Firmware = None, state: CpuState = None, verbose=0):
        self.firmware = firmware
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.state = state
        self.has_error = None
        self.last_addr = None
        self.ready = False
        self.verbose = verbose

    def init(self):
        if self.firmware:
            self.firmware.refresh()
        self.state.verify()
        self.init_memory()
        self.init_hook()
        self.init_firmware()

    def init_firmware(self):
        if not self.firmware:
            raise Exception("firmware missing error")

        addr = MemoryMap.FLASH.address
        self.uc.mem_write(addr, self.firmware.buffer)
        self.uc.reg_write(UC_ARM_REG_PC, from_bytes(self.uc.mem_read(addr + 4, 4)))

        if False:
            self.init_dyn_stack()

    def run(self):
        if not self.ready:
            raise Exception("init() does not called")

        INST_SIZE = 2

        if self.firmware:
            self.last_func = self.firmware.mapping[self.uc.reg_read(UC_ARM_REG_PC)]
            if self.verbose >= 2:
                print(self.last_func)

        try:
            while self.step():
                pass
        except UcError as e:
            print("ERROR:", e)
            addr = self.uc.reg_read(UC_ARM_REG_PC)
            # TODO: Thumb-2 code?
            self.debug_addr(addr - INST_SIZE * 4, count=3)
            print(">", end=" ")
            self.debug_addr(addr)
            self.debug_addr(addr + INST_SIZE, count=3)

    def step(self):
        addr = self.uc.reg_read(UC_ARM_REG_PC)
        self.uc.emu_start(addr | 1, MemoryMap.FLASH.address_until, 0, self.state.cycle)

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

        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED,
            self.hook_unmapped
        )

        self.uc.hook_add(
            UC_HOOK_INTR,
            self.hook_intr,
        )

        if self.verbose >= 2:
            self.uc.hook_add(
                UC_HOOK_CODE,
                self.hook_inst
            )

    def hook_intr(self, uc: Uc, intno, user_data):
        # self.debug_addr(uc.reg_read(UC_ARM_REG_PC) - 40, 40)
        if intno == 2:
            swi = from_bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_PC) - 2, 1))
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            r3 = uc.reg_read(UC_ARM_REG_R3)

            if swi == 0:
                print("done?")
                print(intno, swi, ":", uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                      uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3))
                uc.reg_write(UC_ARM_REG_R0, 16)
                uc.reg_write(UC_ARM_REG_R1, 32)
                uc.reg_write(UC_ARM_REG_R2, 48)
                uc.reg_write(UC_ARM_REG_R3, 64)
            elif swi == 1:
                # TODO: address and size vaild required?
                buffer = uc.mem_read(r0, r1).decode('utf-8', 'replace')
                print(buffer)
                self.api_response("hello")
                self.uc.emu_stop()
            else:
                self.has_error = True

            self.uc.emu_stop()

    def api_response(self, *args):
        bufs = json.dumps(args)
        buf = bufs.encode("utf-8")
        print(buf)
        self.uc.mem_write(MemoryMap.SYSCALL_BUFFER.address, buf)
        self.uc.mem_write(MemoryMap.SYSCALL_BUFFER.address + len(buf), b'\0')
        self.uc.reg_write(UC_ARM_REG_R0, MemoryMap.SYSCALL_BUFFER.address)
        self.uc.reg_write(UC_ARM_REG_R1, len(buf))

    def hook_peripheral_read(self, uc: Uc, access, address, size, value, data):
        if address == PeripheralAddress.OPENPIE_CONTROLLER_RAM_SIZE:
            uc.mem_write(address, to_bytes(self.state.ram_size))
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
            if self.verbose >= 1:
                print("read", access, hex(address), size, value, data)

    def hook_peripheral_write(self, uc: Uc, access, address, size, value, data):
        if address == PeripheralAddress.OPENPIE_CONTROLLER_PENDING:
            if self.verbose >= 1:
                print("OPENPIE_CONTROLLER_PENDING", value)
        elif address == PeripheralAddress.OPENPIE_CONTROLLER_EXCEPTION:
            if self.verbose >= 1:
                print("OPENPIE_CONTROLLER_EXCEPTION", value)
        elif address == PeripheralAddress.OPENPIE_CONTROLLER_INTR_CHAR:
            if self.verbose >= 1:
                print("OPENPIE_CONTROLLER_INTR_CHAR", value)
        elif address == PeripheralAddress.UART0_TXR:
            print(chr(value), end="")
            sys.stdout.flush()
        else:
            if self.verbose >= 1:
                print("write", access, hex(address), size, value, data)

    def hook_unmapped(self, uc: Uc, access, address, size, value, data):
        print("unmapped:", access, hex(address), size, value, data)
        uc.emu_stop()
        self.has_error = True

    def hook_inst(self, uc: Uc, address, size, data):
        func = None
        if self.firmware:
            func = self.firmware.mapping[address]
            if func in HELPER_FUNCTIONS:
                return

        if self.last_func != func:
            self.last_func = func
            print("#inst", hex(address), func)

        self.last_addr = address

    def report_memory(self):
        total_size = 0
        for mem_start, mem_end, perm in self.uc.mem_regions():
            total_size += mem_end - mem_start
            print("memory:", hex(mem_start), hex(mem_end - mem_start), perm)
        print("memory total:", total_size / 1024, "kb")

    INST_SIZE = 2

    def debug_addr(self, addr, count=1):
        INST_SIZE = 4
        try:
            for inst in self.cs.disasm(self.uc.mem_read(addr, INST_SIZE * count), addr, count):  # type: CsInsn
                if self.firmware:
                    print(self.firmware.mapping[inst.address], end=" ")

                print(hex(inst.address), hex(from_bytes(inst.bytes)), inst.mnemonic, inst.op_str)
        except UcError as exc:
            if exc.errno == UC_ERR_READ_UNMAPPED:
                print("fail to read memory", hex(addr))
