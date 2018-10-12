import faulthandler
from threading import Thread

from oputil.opsim.cpu import CPU
from oputil.opsim import firmware
from oputil.opsim.state import CpuState
from unicorn.arm_const import *


def main():
    faulthandler.enable()

    # firmware.build()

    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)

    def reader():
        while True:
            try:
                line = input()
            except EOFError:
                cpu.has_error = True
                break

            cpu.state.input_buffer += (line + "\r\n").encode()

    Thread(target=reader, daemon=True).start()

    pc = cpu.uc.reg_read(UC_ARM_REG_PC)
    ph = lambda x: print(hex(x))
    phr = lambda r: ph(cpu.uc.reg_read(r))

    cpu.step(7)
    phr(UC_ARM_REG_R0)
    phr(UC_ARM_REG_R1)
    phr(UC_ARM_REG_R3)
    phr(UC_ARM_REG_R4)

    # cpu.run()


if __name__ == '__main__':
    main()
