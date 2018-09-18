from enum import Enum
from typing import Union

from dataclasses import dataclass

from opaot.consts import PC


class Op(Enum):
    ADD = "add"
    SUB = "sub"
    MOV = "mov"

    ADR = "adr"
    CMP = "cmp"
    CMN = "cmn"
    REV = "rev"

    ADDS = "adds"
    SUBS = "subs"
    MOVS = "movs"

    ANDS = "ands"
    EORS = "eors"
    LSLS = "lsls"
    LSRS = "lsrs"
    ASRS = "asrs"
    ADCS = "adcs"
    SBCS = "sbcs"
    RORS = "rors"
    TSTS = "tst"
    RSBS = "rsbs"
    ORRS = "orrs"
    MULS = "muls"
    BICS = "bics"
    MVNS = "mvns"

    LDRB = "ldrb"
    LDR = "ldr"
    STRB = "strb"
    STR = "str"

    LDRSH = "ldrsh"
    LDRSB = "ldrsb"
    LDRH = "ldrh"
    STRH = "strh"

    SXTH = "sxth"
    SXTB = "sxtb"
    UXTH = "uxth"
    UXTB = "uxtb"

    PUSH = "push"
    POP = "pop"
    STAIM = "stm"  # with !
    LDMIA = "ldm"  # with !

    BEQ = "beq"
    BNE = "bne"
    BCS = "bhs"
    BCC = "blo"
    BMI = "bmi"
    BPL = "bpl"
    BVS = "bvs"
    BVC = "bvc"
    BHI = "bhi"
    BLS = "bls"
    BGE = "bge"
    BLT = "blt"
    BGT = "bgt"
    BLE = "ble"

    CBZ = "cbz"
    CBNZ = "cbnz"

    SVC = "svc"

    B = "b"
    BL = "bl"
    BLH = "bl!"
    BLX = "blx"
    BX = "bx"




    def is_cmp(self):
        return self in (
            Op.BEQ, Op.BNE, Op.BCS, Op.BCC, Op.BMI, Op.BPL, Op.BVS, Op.BVC, Op.BHI, Op.BLS, Op.BGE, Op.BLT, Op.BGT,
            Op.BLE)

    def __str__(self):
        return self.value


@dataclass
class Imm:
    value: int

    def __str__(self):
        return f"#{self.value if self.value < 0xa else hex(self.value)}"

    def __repr__(self):
        return repr(self.value)


class Reg(Enum):
    r0 = 0
    r1 = 1
    r2 = 2
    r3 = 3
    r4 = 4
    r5 = 5
    r6 = 6
    r7 = 7
    r8 = 8
    r9 = 9
    r10 = 10
    r11 = 11
    r12 = 12
    sp = 13
    lr = 14
    pc = 15

    def __index__(self):
        return self.value

    def __int__(self):
        return self.value

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


@dataclass
class Offset:
    value: int
    addr: int

    @property
    def target(self):
        return self.value + self.addr

    def __str__(self):
        return f"#{hex(self.addr + self.value)}"

    def __repr__(self):
        return hex(self.addr + self.value)


@dataclass
class Insn:
    op: Op


Value = Union[Imm, Reg, Offset]


@dataclass
class Insn2(Insn):
    op: Op
    dest: Reg
    src: Value

    def __str__(self):
        return f"{self.op} {self.dest}, {self.src}"


@dataclass
class Insn3(Insn):
    op: Op
    dest: Reg
    src: Reg
    offset: Value

    def __str__(self):
        return f"{self.op} {self.dest}, {self.src}, {self.offset}"


@dataclass
class InsnMem(Insn):
    op: Op
    dest: Reg
    base: Reg
    offset: Value

    def __str__(self):
        if isinstance(self.offset, Imm) and self.offset.value == 0 and self.base.value != PC:
            return f"{self.op} {self.dest}, [{self.base}]"
        else:
            return f"{self.op} {self.dest}, [{self.base}, {self.offset}]"


def stack_unroll(rlist, special_reg=None):
    regs = []

    for i in range(8):
        if (rlist & (1 << i)) != 0:
            regs.append(Reg(i))

    if special_reg:
        regs.append(special_reg)

    return regs


@dataclass
class InsnStack(Insn):
    op: Op
    Rlist: int
    R: bool

    @property
    def special_reg(self):
        reg = None
        if self.R:
            if self.op == Op.PUSH:
                reg = Reg.lr
            elif self.op == Op.POP:
                reg = Reg.pc

        return reg

    @property
    def regs(self):
        return stack_unroll(self.Rlist, self.special_reg)

    @property
    def pure_regs(self):
        return stack_unroll(self.Rlist)

    def __str__(self):
        regs_str = ', '.join(map(str, self.regs))
        return f"{self.op} {{{regs_str}}}"


@dataclass
class InsnMemStack(Insn):
    op: Op
    Rb: Reg
    Rlist: int

    @property
    def regs(self):
        return stack_unroll(self.Rlist)

    @property
    def is_incr(self):
        return self.Rb not in self.regs or self.op == Op.STAIM

    def __str__(self):
        regs_str = ', '.join(map(str, self.regs))
        mask = "!" if self.is_incr else ""

        return f"{self.op} {self.Rb}{mask}, {{{regs_str}}}"


@dataclass
class InsnSVC(Insn):
    op: Op
    soffset: Imm

    def __str__(self):
        return f"{self.op} {self.soffset}"


@dataclass
class InsnBranch(Insn):
    op: Op
    dest: Value

    def __str__(self):
        return f"{self.op} {self.dest}"


@dataclass
class InsnBranchIf(Insn):
    op: Op
    dest: Offset

    def __str__(self):
        return f"{self.op} {self.dest}"


@dataclass
class InsnBranchIf2(Insn):
    op: Op
    src: Reg
    dest: Offset

    def __str__(self):
        return f"{self.op} {self.src}, {self.dest}"


@dataclass
class InsnLongBranch(Insn):
    op: Op
    dest: Offset

    def __str__(self):
        return f"{self.op} {self.dest}"


@dataclass
class InsnBranch2(Insn):
    op: Op
    dest: Value
    H: bool

    def __str__(self):
        return f"{self.op} {self.dest}"


@dataclass
class InsnAddr(Insn):
    op: Op
    Rd: Reg
    Rs: Reg
    soffset: Imm

    def dest_pc(self, pc):
        if self.Rs == Reg.pc:
            return (self.soffset.value + pc + 4) & (0b11111111_11111111_11111111_11111101)
        else:
            raise Exception(self.Rs)

    def __str__(self):
        return f"{self.op} {self.Rd}, {self.Rs}, {self.soffset}"
