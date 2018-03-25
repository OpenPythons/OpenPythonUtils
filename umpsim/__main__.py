import faulthandler
import pickle
from pathlib import Path
from subprocess import check_call, DEVNULL
from threading import Thread

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import *

from umpsim.address import MemoryMap
from umpsim.context import CpuContext
from umpsim.cpu import CPU
from umpsim.firmware import Firmware
from umpsim.state import CpuState

umport_path = (Path(__file__).parent / "../umport")
build_path = umport_path / "build"


def main():
    check_call(
        ["wsl", "make"],
        cwd=umport_path,
        shell=True,
        stdin=DEVNULL
    )

    firmware = Firmware(
        build_path / "firmware.bin",
        build_path / "firmware.elf.map"
    )

    state = CpuState()
    context = CpuContext()
    cpu = CPU(firmware, state, verbose=1)
    cpu.init()

    def reader():
        while True:
            try:
                line = input()
            except EOFError:
                cpu.has_error = True
                break

            cpu.state.stack += (line + "\r\n").encode()

    Thread(target=reader).start()

    faulthandler.enable()
    while cpu.step():
        if False:
            # slow context save/load (memory, register, etc.)
            ctx = CpuContext.save(cpu)
            cpu = CpuContext.load(ctx)
            cpu.state = state  # for input

        if False:
            # fast context save/load (only register)
            ctx2 = cpu.uc.context_save()
            cpu.uc.context_restore(ctx2)

if __name__ == '__main__':
    main()
