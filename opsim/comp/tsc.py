import faulthandler
import sys
import time
from threading import Thread

from unicorn.arm_const import *

from opsim.address import MemoryMap, PeripheralAddress
from opsim.cpu import CPU
from opsim.firmware import firmware
from opsim.ports.cs import ThumbSC, HookMemory
from opsim.state import CpuState
from opsim.valid import check_failures, print_failures


def main():
    faulthandler.enable()
    FLAG = None

    sim = ThumbSC()
    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)


    sim.Regs.PC = cpu.uc.reg_read(UC_ARM_REG_PC)
    for (begin, end, perms) in cpu.uc.mem_regions():
        if (end - begin) > 0x10000:
            sim.Memory.Map(begin, end - begin)

    sim.Memory.WriteBuffer(MemoryMap.FLASH.address, firmware.buffer)
    prev_hook_addr = MemoryMap.PERIPHERAL.address
    next_hook_addr = MemoryMap.PERIPHERAL.address_until
    custom_stack = []

    count = 0

    def int_from_bytes(buf):
        return int.from_bytes(buf, "little", signed=len(buf) == 4)

    def global_hook_memory(address, is_read, size, value):
        if is_read:
            original = cpu.uc.mem_read(address, size)
            if int_from_bytes(original) != value:
                print("INVALID READ", hex(address), "uc:", original[0], "tc", value)
        else:
            original = cpu.uc.mem_read(address, size)
            if int_from_bytes(original) != value:
                print("INVALID WRITE", hex(address), "uc:", original[0], "tc", value)

        return 0

    line_buffer = []
    FLAG = None
    epoch = time.time()

    def hook_memory(address, is_read, size, value):
        nonlocal line_buffer
        assert size == 4
        if prev_hook_addr <= address < next_hook_addr:
            if is_read:
                if address == PeripheralAddress.OP_CON_RAM_SIZE:
                    return int_from_bytes(cpu.uc.mem_read(address, size))
                elif address == PeripheralAddress.OP_IO_RXR:
                    if custom_stack:
                        return custom_stack.pop(0)
                elif address == PeripheralAddress.OP_RTC_TICKS_MS:
                    if not FLAG:
                        return int_from_bytes(cpu.uc.mem_read(address, size))
                    else:
                        return int((time.time() - epoch) * 1000)
                else:
                    print("read", hex(address))
            else:
                if address == PeripheralAddress.OP_CON_PENDING:
                    pass
                elif address == PeripheralAddress.OP_CON_EXCEPTION:
                    pass
                elif address == PeripheralAddress.OP_CON_INTR_CHAR:
                    pass
                elif address == PeripheralAddress.OP_IO_TXR:
                    if FLAG:
                        print(chr(value), end="")
                    sys.stdout.flush()
                else:
                    print("write", hex(address), value)

        return 0

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

    sim.Memory.Hook = HookMemory(hook_memory)

    FLAG = False
    if FLAG:
        while True:
            sim.Run(10000000)

    hook_installed = False
    cpu.state.cycle = cycle = 1

    while True:
        prev_pc = cpu.uc.reg_read(UC_ARM_REG_PC)
        cpu.step()
        sim.Run(cycle)
        count += cycle
        if not hook_installed:
            sim.Memory.GlobalHook = HookMemory(global_hook_memory)
            cpu.state.cycle = cycle = 1
            hook_installed = True

        failure, target_regs, sim_regs = check_failures(cpu, sim)
        if failure:
            print_failures(cpu, sim, prev_pc, target_regs, sim_regs, count)
            break


if __name__ == '__main__':
    main()
