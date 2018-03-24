from umpsim.firmware import default_firmware
from umpsim.cpu import CPU
from umpsim.state import CpuState
from umpsim.context import CpuContext
from threading import Thread


def main():
    firmware = default_firmware
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
