from capstone import Cs, CS_MODE_THUMB, CS_ARCH_ARM, CsInsn
from keystone import *
from unicorn import *
from unicorn.arm_const import *

from opsim.regs import REGS, REGS_NAME
from opsim.util import hex32

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def get_CPSR(cpsr):
    FV = 1 << 28
    FC = 1 << 29
    FZ = 1 << 30
    FN = 1 << 31

    r = ""
    for f, s in zip((FN, FZ, FC, FV), "NZCV"):
        r += s if f & cpsr else " "

    return r


addr = 0x10000
size = 0x1000
code = """

{1}

RORS r3, #1
MOV R1, R0
SUB R2, #2
{0} R1, R2

MOV R1, R0
SUB R2, #1
{0} R1, R2

RORS r3, #1
MOV R1, R0
MOV R2, #0
{0} R1, R2

RORS r3, #1
MOV R1, R0
MOV R2, #1
{0} R1, R2

RORS r3, #1
MOV R1, R0
MOV R2, #31
{0} R1, R2

RORS r3, #1
MOV R1, R0
MOV R2, #32
{0} R1, R2

""".format("LSLS", """
MOV R0, #3
""")

encoding, count = ks.asm(code.strip(), addr)
buf = bytes(encoding)
print(buf)

uc.mem_map(0x0, size)
uc.mem_map(addr, size)
uc.mem_write(addr, buf)

new_registers = {reg: uc.reg_read(reg) for reg in REGS}

pc = addr
uc.reg_write(UC_ARM_REG_PC, pc)
while pc <= addr + len(buf) - 4:
    old_registers = new_registers
    pc = uc.reg_read(UC_ARM_REG_PC)
    uc.emu_start(pc | 1, addr + len(buf), 0, 1)
    new_registers = {reg: uc.reg_read(reg) for reg in REGS}

    for insn in cs.disasm(uc.mem_read(pc, 4), pc, 1):  # type: CsInsn
        # print(insn.mnemonic, insn.op_str)
        if not insn.mnemonic.endswith("s") or insn.mnemonic == "rors.w":
            break
        else:
            pass
    else:
        for reg in REGS:
            uc_value = new_registers[reg]
            if (old_registers[reg] == uc_value and
                    reg != UC_ARM_REG_R1 and
                    reg != UC_ARM_REG_CPSR or
                    reg == UC_ARM_REG_PC or
                    reg == UC_ARM_REG_R3):
                continue

            if reg == UC_ARM_REG_CPSR:
                # print(">", REGS_NAME[reg].ljust(5), get_CPSR(uc_value), sep='\t')
                print(get_CPSR(uc_value))
            else:
                # print(">", REGS_NAME[reg].ljust(5), hex32(uc_value), sep='\t')
                print(hex32(uc_value))
