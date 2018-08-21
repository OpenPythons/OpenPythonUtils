import faulthandler
import sys
from pathlib import Path
from subprocess import check_call, DEVNULL
from threading import Thread

from capstone import CsInsn
from capstone.arm import ArmOp
from unicorn.arm_const import *

from opsim.address import MemoryMap, PeripheralAddress
from opsim.cpu import CPU
from opsim.firmware import Firmware
from opsim.regs import REGS_NAME, REGS
from opsim.state import CpuState
from opsim.util import from_bytes, hex32

if True:
    # noinspection PyUnresolvedReferences
    import clr

    clr.AddReference("C:/Users/EcmaXp/Dropbox/Projects/ThumbCs/ThumbCs/bin/x64/Debug/ThumbCs.exe")

    # noinspection PyUnresolvedReferences
    import ThumbCs

oprom_path = (Path(__file__).parent / "../oprom")
build_path = oprom_path / "build"


def main():
    FLAG = None

    if False:
        check_call(
            ["wsl", "make"],
            cwd=oprom_path,
            shell=True,
            stdin=DEVNULL
        )

    firmware = Firmware(
        build_path / "firmware.bin",
        build_path / "firmware.elf.map"
    )

    sim = ThumbCs.ThumbCs()
    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)
    cpu.init()

    sim.Regs.PC = cpu.uc.reg_read(UC_ARM_REG_PC)
    for (begin, end, perms) in cpu.uc.mem_regions():
        if (end - begin) > 0x10000:
            sim.Memory.Map(begin, end - begin)

    sim.Memory.Write(MemoryMap.FLASH.address, firmware.buffer)

    prev_hook_addr = MemoryMap.PERIPHERAL.address
    next_hook_addr = MemoryMap.PERIPHERAL.address_until
    custom_stack = []

    count = 0

    def global_hook_memory(address, is_read, value):
        if is_read:
            original = cpu.uc.mem_read(address, 1)
            if original[0] != value:
                print("INVALID READ", hex(address), "uc:", original[0], "tc", value)
        else:
            original = cpu.uc.mem_read(address, 1)
            if original[0] != value:
                print("INVALID WRITE", hex(address), "uc:", original[0], "tc", value)

        return 0

    line_buffer = []

    def hook_memory(address, is_read, value):
        nonlocal line_buffer
        if prev_hook_addr <= address < next_hook_addr:
            if is_read:
                if address & ~3 == PeripheralAddress.OPENPIE_CONTROLLER_RAM_SIZE:
                    return cpu.uc.mem_read(address & ~3, 4)[address & 3]
                elif address & ~3 == PeripheralAddress.UART0_RXR:
                    if address & 3 == 0:
                        if custom_stack:
                            return custom_stack.pop(0)
                elif address & ~3 == PeripheralAddress.RTC_TICKS_MS:
                    return cpu.uc.mem_read(address & ~3, 4)[address & 3]
                elif address & ~3 == PeripheralAddress.RTC_TICKS_US:
                    return cpu.uc.mem_read(address & ~3, 4)[address & 3]
                else:
                    print("read", hex(address))
            else:
                if address & ~3 == PeripheralAddress.OPENPIE_CONTROLLER_PENDING:
                    pass
                elif address & ~3 == PeripheralAddress.OPENPIE_CONTROLLER_EXCEPTION:
                    pass
                elif address & ~3 == PeripheralAddress.OPENPIE_CONTROLLER_INTR_CHAR:
                    pass
                elif address & ~3 == PeripheralAddress.UART0_TXR:
                    if address & 3 == 0:
                        if FLAG:
                            print(chr(value), end="")
                        sys.stdout.flush()
                else:
                    print("write", hex(address), value)

        return 0

    sim.Memory.Hook = ThumbCs.HookMemory(hook_memory)

    def push(line):
        nonlocal custom_stack
        cpu.state.stack += (line + "\r\n").encode()
        custom_stack += (line + "\r\n").encode()

    def reader():
        while True:
            try:
                line = input()
            except EOFError:
                cpu.has_error = True
                break

            push(line)

    thread = Thread(target=reader, daemon=True)
    thread.start()

    push("1")

    FLAG = True
    if FLAG:
        while True:
            sim.Run(100000)

    cpu.state.cycle = cycle = 82500
    faulthandler.enable()
    while cpu.step():
        sim.Run(cycle)
        count += cycle
        if cycle > 1:
            sim.Memory.GlobalHook = ThumbCs.HookMemory(global_hook_memory)
            cpu.state.cycle = cycle = 1

        sim_regs = sim.Regs.Load()
        failture = False
        for reg, tc_value in zip(REGS, sim_regs):
            uc_value = cpu.uc.reg_read(reg)
            tc_value &= 0xFFFFFFFF

            if reg == UC_ARM_REG_CPSR:
                if (uc_value & 0xfff00000) != tc_value:
                    failture = True
            elif uc_value != tc_value:
                failture = True

        if failture:
            print(end="> ")
            addr = cpu.uc.reg_read(UC_ARM_REG_PC) - 2
            buf = cpu.uc.mem_read(addr, 4)

            target_regs = set()
            for inst in cpu.cs.disasm(buf, addr, 1):  # type: CsInsn
                if cpu.firmware:
                    print("@", cpu.firmware.mapping[inst.address])

                assert len(inst.bytes) == 2, inst
                bcode = bin(from_bytes(inst.bytes))[2:].zfill(16)
                print("hex", hex32(inst.address))
                print(":", bcode[0:4], bcode[4:8], bcode[8:12], bcode[12:16])
                print(inst.mnemonic, inst.op_str)

                for operand in inst.operands:  # type: ArmOp
                    target_regs.add(operand.reg)

            print(cpu.uc.mem_read(0x40000300, 4))

            for reg, tc_value in zip(REGS, sim_regs):
                uc_value = cpu.uc.reg_read(reg)
                tc_value &= 0xFFFFFFFF

                if reg == UC_ARM_REG_CPSR:
                    print(REGS_NAME[reg].ljust(5), hex32(uc_value & 0xfff00000), hex32(tc_value),
                          (uc_value & 0xfff00000 != tc_value and "[!]" or ""), sep='\t')
                else:
                    if reg in target_regs:
                        print(REGS_NAME[reg].ljust(5), hex32(uc_value), hex32(tc_value),
                              (uc_value != tc_value and "[!]" or ""), sep='\t')

            print("count:", count)
            break


if __name__ == '__main__':
    main()
