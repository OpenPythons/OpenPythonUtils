from pathlib import Path
from subprocess import check_call, DEVNULL
from threading import Thread

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
    cpu = CPU(firmware, state, context, verbose=1)

    def reader():
        while True:
            try:
                line = input()
            except EOFError:
                cpu.has_error = True
                break

            state.stack += (line + "\r\n").encode()

    Thread(target=reader).start()
    cpu.run()


if __name__ == '__main__':
    main()
