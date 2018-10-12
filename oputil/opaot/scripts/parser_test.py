from capstone import CS_ARCH_ARM, Cs, CS_MODE_THUMB

from oputil.opaot import UnsupportedInstructionException, UnknownInstructionException
from oputil.opaot.parser import parse


cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for i in range(0xffff + 1):
    pinst = None

    try:
        pinst = parse(0x1000, i)
    except (UnsupportedInstructionException, UnknownInstructionException):
        continue

    buf = int.to_bytes(i, 2, "little", signed=False)
    hex_code = "0x" + hex(i)[2:].zfill(4)
    bin_code = bin(i)[2:].zfill(16)
    found = False
    for inst in cs.disasm(buf, 0x1000):
        found = True
        sinst = str(pinst)
        cinst = " ".join([inst.mnemonic, inst.op_str])
        if cinst != sinst:
            print(hex_code, ":", bin_code[0:4], bin_code[4:8], bin_code[8:12], bin_code[12:16], "=", cinst, "\t|\t",
                  sinst)

    if not found and pinst is not None:
        print(hex_code, ":", bin_code[0:4], bin_code[4:8], bin_code[8:12], bin_code[12:16], "=", "<INVALID>",
              "\t|\t",
              pinst, )
