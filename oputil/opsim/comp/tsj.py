import faulthandler

from unicorn.arm_const import *

from oputil.opsim.cpu import CPU
from oputil.opsim import firmware
from oputil.opsim import ThumbSJ, ready_sim_java, trace_code_java
from oputil.opsim.state import CpuState
from oputil.opsim.valid import check_failures, print_failures


def main():
    faulthandler.enable()

    sim = ThumbSJ()
    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)


    ready_sim_java(cpu, sim)

    count = 0
    def push(line):
        buf = (line + "\r\n").encode()
        cpu.state.input_buffer += buf

    # push("import pystone")
    # push("pystone.main(1)")

    FLAG = False
    if FLAG:
        while True:
            sim.Run(10000000)

    hook_installed = False
    cpu.state.cycle = cycle = 1  # 3437200
    while True:
        prev_pc = cpu.uc.reg_read(UC_ARM_REG_PC)
        cpu.step()

        sim.Run(cycle)

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
