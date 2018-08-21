import sys
from pathlib import Path
from pprint import pprint

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

from opsim.firmware import Firmware
from opsim.util import from_bytes

oprom_path = (Path(__file__).parent / "../oprom")
build_path = oprom_path / "build"
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def main2():
    firmware = Firmware(
        build_path / "firmware.bin",
        build_path / "firmware.elf.map"
    )

    buf = firmware.load_bytes()

    a = 0b11100111
    b = 0b11111110

    for inst in cs.disasm(bytes([b, a]), 0):
        print(hex(inst.address), hex(from_bytes(inst.bytes)), inst.mnemonic, inst.op_str)


def main():
    with open("opmap.txt", "w") as fp:
        for i in range(0x10000):
            buf = int.to_bytes(i, 2, "little", signed=False)
            hex_code = "0x" + hex(i)[2:].zfill(4)
            bin_code = bin(i)[2:].zfill(16)
            found = False
            for inst in cs.disasm(buf, 0x1000):
                found = True
                print(hex_code, ":", bin_code[0:4], bin_code[4:8], bin_code[8:12], bin_code[12:16], "=", inst.mnemonic, inst.op_str, file=fp)

            if not found:
                print(hex_code, ":", bin_code[0:4], bin_code[4:8], bin_code[8:12], bin_code[12:16], "=", "<INVALID>", file=fp)


if __name__ == '__main__':
    main()
