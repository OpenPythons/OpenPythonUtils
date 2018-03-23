from umpsim.firmware import default_firmware
from umpsim.cpu import CPU
from umpsim.state import CpuState
from umpsim.context import CpuContext


def main():
    firmware = default_firmware
    state = CpuState()
    context = CpuContext()
    cpu = CPU(firmware, state, context)

    cpu.run()


if __name__ == '__main__':
    main()
