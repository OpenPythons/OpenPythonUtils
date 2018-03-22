import msvcrt
import pickle
import sys
import time
from pathlib import Path

import cstruct
from capstone import *
from unicorn import *
from unicorn.arm_const import *


class UnicornControllerStruct(cstruct.CStruct):
    __byte_order__ = cstruct.LITTLE_ENDIAN
    __struct__ = """
    unsigned int PENDING;
    unsigned int EXCEPTION;
    unsigned int INTR_CHAR;
    unsigned int RAM_SIZE;
    unsigned int STACK_SIZE;
    unsigned int IDLE;
    """


# from www-emu/mp_unicorn.js
FLASH_ADDRESS = 0x08000000
FLASH_SIZE = 0x100000
RAM_ADDRESS = 0x20000000
MAX_RAM_SIZE = 0x40000
PERIPHERAL_ADDRESS = 0x40000000
PERIPHERAL_SIZE = 0x10000

UART0_TXR = 0x40000000
UART0_RXR = 0x40000004
RTC_TICKS_MS = 0x40000300
RTC_TICKS_US = 0x40000304

UMPORT_CONTROLLER_PENDING = 0x40000100
UMPORT_CONTROLLER_EXCEPTION = 0x40000104
UMPORT_CONTROLLER_INTR_CHAR = 0x40000108
UMPORT_CONTROLLER_RAM_SIZE = 0x4000010c
UMPORT_CONTROLLER_STACK_SIZE = 0x40000110
UMPORT_CONTROLLER_IDLE = 0x40000114
UMPORT_CONTROLLER_INSNS = 0x40000118

CYCLE_LIMIT = 50000
RAM_SIZE = 1024 * 128
STACK_SIZE = 1024 * 32


firmware_path = (Path(__file__).parent / "../umport/build/firmware.bin").absolute().relative_to(Path.cwd())
firmware = firmware_path.read_bytes()
print("firmware from:", firmware_path)
print("firmware", len(firmware), "bytes")

emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def from_bytes(b):
    return int.from_bytes(b, byteorder="little")

def to_bytes(n):
    return int.to_bytes(n & 0xFFFFFFFF, 4, byteorder="little")

INST_SIZE = 2
def debug_addr(addr, count=1):
    for inst in cs.disasm(firmware[addr - FLASH_ADDRESS:addr - FLASH_ADDRESS + INST_SIZE * count], addr, count):
        print(hex(inst.address), inst.mnemonic, inst.op_str)

source = """
def hello():
return 3



hello()
"""

epoch = time.time()
pending_addr = 0
exception_addr = 0
ichr_addr = 0
stack = list(("\r\n".join(source.strip().splitlines()) + '\r\n').encode())

def hook_read(uc: Uc, access, address, size, value, data):
    if address == UMPORT_CONTROLLER_RAM_SIZE:
        emu.mem_write(address, to_bytes(RAM_SIZE))
    elif address == UMPORT_CONTROLLER_STACK_SIZE:
        emu.mem_write(address, to_bytes(STACK_SIZE))
    elif address == UART0_RXR:
        if stack:
            emu.mem_write(address, to_bytes(stack.pop(0)))
        else:
            emu.mem_write(address, to_bytes(0))
    elif address == RTC_TICKS_MS:
        emu.mem_write(address, to_bytes(int((time.time() - epoch) * 1000)))
    elif address == RTC_TICKS_US:
        emu.mem_write(address, to_bytes(int((time.time() - epoch) * 1000 * 1000)))
    else:
        print("read", access, hex(address), size, value, data)


def hook_write(uc: Uc, access, address, size, value, data):
    global pending_addr, exception_addr, ichr_addr
    if address == UMPORT_CONTROLLER_PENDING:
        pending_addr = addr
        print("UMPORT_CONTROLLER_PENDING", value)
    elif address == UMPORT_CONTROLLER_EXCEPTION:
        print("UMPORT_CONTROLLER_EXCEPTION", value)
        exception_addr = to_bytes(value)
    elif address == UMPORT_CONTROLLER_INTR_CHAR:
        print("UMPORT_CONTROLLER_INTR_CHAR", value)
        ichr_addr = value
    elif address == UART0_TXR:
        print(chr(value), end="")
        sys.stdout.flush()
    else:
        print("write", access, hex(address), size, value, data)

#if 1:
#    addr = 0x08000000
#    for i in range(100):
#        debug_addr(addr, 1000)
#        addr += 1000
#
#    exit()

addr = 0

try:
    emu.mem_map(FLASH_ADDRESS, FLASH_SIZE, UC_PROT_ALL)
    emu.mem_map(RAM_ADDRESS, MAX_RAM_SIZE, UC_PROT_ALL)
    emu.mem_map(PERIPHERAL_ADDRESS, PERIPHERAL_SIZE, UC_PROT_ALL)

    sp = RAM_ADDRESS + RAM_SIZE
    addr = from_bytes(firmware[4:8])
    emu.mem_write(FLASH_ADDRESS, firmware)
    emu.mem_write(FLASH_ADDRESS, to_bytes(sp))

    total_size = 0
    for mem_start, mem_end, perm in emu.mem_regions():
        total_size += mem_end - mem_start
        print("memory:", hex(mem_start), hex(mem_end - mem_start), perm)
    print("memory total:", total_size / 1024, "kb")

    emu.hook_add(UC_HOOK_MEM_READ, hook_read, None, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE)
    emu.hook_add(UC_HOOK_MEM_WRITE, hook_write, None, PERIPHERAL_ADDRESS, PERIPHERAL_ADDRESS + PERIPHERAL_SIZE)

    emu.reg_write(UC_ARM_REG_PC, addr)

    CYCLE_LIMIT = 1000

    while True:
        addr = emu.reg_read(UC_ARM_REG_PC)
        emu.emu_start(addr | 1, FLASH_ADDRESS + FLASH_SIZE, 0, 10000)
        # debug_addr(addr)

        if msvcrt.kbhit():
            ch = msvcrt.getch()
            stack.append(ord(ch))

except UcError as e:
    print("ERROR:", e)
    debug_addr(addr - INST_SIZE * 4, count=3)
    print(">", end=" ")
    debug_addr(addr)
    debug_addr(addr + INST_SIZE, count=3)
    print(hex(emu.reg_read(UC_ARM_REG_R2)))
