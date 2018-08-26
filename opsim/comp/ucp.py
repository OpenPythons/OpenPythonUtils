import faulthandler
from threading import Thread

from opsim.cpu import CPU
from opsim.firmware import firmware
from opsim.state import CpuState


def main():
    faulthandler.enable()

    firmware.build()

    state = CpuState()
    cpu = CPU(firmware, state, verbose=1)
    cpu.init()

    def reader():
        while True:
            try:
                line = input()
            except EOFError:
                cpu.has_error = True
                break

            cpu.state.input_buffer += (line + "\r\n").encode()

    Thread(target=reader).start()

    cpu.run()

if __name__ == '__main__':
    main()
