import faulthandler
from array import array

from unicorn.arm_const import *

from opsim.cpu import CPU
from opsim.firmware import firmware
from opsim.ports.java import ThumbSJ, ready_sim_java, trace_code_java
from opsim.state import CpuState
from opsim.valid import check_failures, print_failures


def main():
    faulthandler.enable()

    sim = ThumbSJ()
    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)
    cpu.init()

    ready_sim_java(cpu, sim)

    count = 0
    def push(line):
        buf = (line + "\r\n").encode()
        cpu.state.input_buffer += buf

    push("import pystone")
    push("pystone.main(1)")

    FLAG = False
    if FLAG:
        while True:
            sim.Run(10000000)

    hook_installed = False
    cpu.state.cycle = cycle = 1  # 3437200
    while True:
        prev_pc = cpu.uc.reg_read(UC_ARM_REG_PC)
        cpu.step()

        if not sim.Run(cycle):
            # exception raised
            break

        if count % 10000 == 0:
            print(count)

        count += cycle
        if not hook_installed:
            # sim.Memory.GlobalHook = PyHookMemory(global_hook_memory)
            cpu.state.cycle = cycle = 1
            hook_installed = True

        failure, target_regs, sim_regs = check_failures(cpu, sim)
        if failure:
            bcode, inst = print_failures(cpu, sim, prev_pc, target_regs, sim_regs, count)
            trace_code_java(bcode, inst)
            break


if __name__ == '__main__':
    main()
