from enum import IntEnum, Enum
from functools import lru_cache
from typing import Union, Optional

from dataclasses import dataclass, field


class Op(Enum):
    MOVS = "MOVS"
    ADDS = "ADDS"
    SUBS = "SUBS"

    MOV = "MOV"
    ADD = "ADD"
    SUB = "SUB"

    ANDS = "ANDS"
    EORS = "EORS"
    LSLS = "LSLS"
    LSRS = "LSRS"
    ASRS = "ASRS"
    ADCS = "ADCS"
    SBCS = "SBCS"
    RORS = "RORS"
    TST = "TST"
    NEGS = "NEGS"
    CMP = "CMP"
    CMN = "CMN"
    ORRS = "ORRS"
    MULS = "MULS"
    BICS = "BICS"
    MVNS = "MVNS"

    LDR = "LDR"
    LDRB = "LDRB"
    LDRH = "LDRH"
    LDSB = "LDSB"
    LDSH = "LDSH"

    STR = "STR"
    STRB = "STRB"
    STRH = "STRH"

    PUSH = "PUSH"
    POP = "POP"

    STMIA = "STMIA"
    LDMIA = "LDMIA"

    B = "B"
    BL = "BL"
    BX = "BX"
    BLX = "BLX"
    BEQ = "BEQ"
    BNE = "BNE"
    BCS = "BCS"
    BCC = "BCC"
    BMI = "BMI"
    BPL = "BPL"
    BVS = "BVS"
    BVC = "BVC"
    BHI = "BHI"
    BLS = "BLS"
    BGE = "BGE"
    BLT = "BLT"
    BGT = "BGT"
    BLE = "BLE"
    SWI = "SWI"

    SXTH = "SXTH"
    SXTB = "SXTB"
    UXTH = "UXTH"
    UXTB = "UXTB"
    REV = "REV"

    def __str__(self):
        return self.name


@dataclass
class Buffer:
    address: int
    size: int
    content: bytearray = field(repr=False)


@dataclass
class Function:
    address: int
    size: int
    content: bytearray = field(repr=False)


class Firmware:
    def __init__(self, buffer=Buffer):
        self.firmware = buffer


class Reg(IntEnum):
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

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<{type(self).__name__}: {self.name}>"


class Imm(int):
    def __repr__(self):
        return f"<{type(self).__name__}: {int.__repr__(self)}>"


class Offset(int):
    def __repr__(self):
        return f"<{type(self).__name__}: {int.__repr__(self)}>"



@dataclass(frozen=True)
class Instruction:
    op: Op
    rd: Optional[Union[Reg, Imm, Offset]] = None
    rs: Optional[Union[Reg, Imm, Offset]] = None
    rn: Optional[Union[Reg, Imm, Offset]] = None
    flag: Optional[int] = None

    def __str__(self):
        args = []
        for name, value in ("rd", self.rd), ("rs", self.rs), ("rn", self.rn), ("flag", self.flag):
            if value is not None:
                args.append(f"{name}={value!r}")

        return f"{self.op}({', '.join(args)})"


P1_OP_TABLE = {
    0: Op.LSLS,
    1: Op.LSRS,
    2: Op.ASRS,
}

P3_OP_TABLE = {
    0: Op.MOVS,
    1: Op.CMP,
    2: Op.ADDS,
    3: Op.SUBS,
}

P4_OP_TABLE = {
    0: Op.ANDS,
    1: Op.EORS,
    2: Op.LSLS,
    3: Op.LSRS,
    4: Op.ASRS,
    5: Op.ADCS,
    6: Op.SBCS,
    7: Op.RORS,
    8: Op.TST,
    9: Op.NEGS,
    10: Op.CMP,
    11: Op.CMN,
    12: Op.ORRS,
    13: Op.MULS,
    14: Op.BICS,
    15: Op.MVNS,
}

P5_OP_TABLE = {
    # bits(8, 2), h1
    (0, True): Op.ADD,
    (0, False): Op.ADD,
    (1, True): Op.CMP,
    (1, False): Op.CMP,
    (2, True): Op.MOV,
    (2, False): Op.MOV,
    (3, True): Op.BLX,
    (3, False): Op.BX,
}

P7_OP_TABLE = {
    # L, B
    (True, False): Op.LDR,
    (True, True): Op.LDRB,
    (False, False): Op.STR,
    (False, True): Op.STRB,
}

P8_OP_TABLE = {
    # S, H
    (False, False): Op.STRH,
    (False, True): Op.LDRH,
    (True, False): Op.LDSB,
    (True, True): Op.LDSH,
}

P9_OP_TABLE = {
    # L, B
    (True, False): Op.LDR,
    (True, True): Op.LDRB,
    (False, False): Op.STR,
    (False, True): Op.STRB,
}

P16_OP_TABLE = {
    0: Op.BEQ,
    1: Op.BNE,
    2: Op.BCS,
    3: Op.BCC,
    4: Op.BMI,
    5: Op.BPL,
    6: Op.BVS,
    7: Op.BVC,
    8: Op.BHI,
    9: Op.BLS,
    10: Op.BGE,
    11: Op.BLT,
    12: Op.BGT,
    13: Op.BLE,
}

U1_OP_TABLE = {
    0: Op.SXTH,
    1: Op.SXTB,
    2: Op.UXTH,
    3: Op.UXTB,
}
U2_OP_TABLE = {
    0: Op.REV,
}


@lru_cache(4096)
def decode(code: int) -> Instruction:
    def bits(offset: int, size: int) -> int:
        return code >> offset & ((1 << size) - 1)

    def reg(offset: int) -> Reg:
        return Reg(bits(offset, 3))

    def regx(offset: int, extra: bool) -> Reg:
        return Reg(bits(offset, 3) + (8 if extra else 0))

    def bit(offset: int) -> bool:
        return code & (1 << offset) != 0

    prefix = bits(8, 8)

    # 1: 0b000-----
    # Move shifted register
    if 0b000_00_000 <= prefix <= 0b000_11_000:
        offset5 = bits(6, 5)
        if not (bits(11, 2) == 0 or offset5 != 0):
            offset5 = 32

        return Instruction(
            op=P1_OP_TABLE[bits(11, 2)],
            rd=reg(0),
            rs=reg(3),
            rn=Imm(offset5)
        )

    # 2: 0b00011---
    # Add/subtract
    elif 0b000_11_000 <= prefix <= 0b001_00_000:
        return Instruction(
            op=Op.SUBS if bit(9) else Op.ADDS,
            rd=reg(0),
            rs=reg(3),
            rn=Imm(bits(6, 3)) if bit(10) else reg(6)
        )

    # 3: 0b001-----
    # Move/compare/add/subtract immediate
    elif 0b001_00000 <= prefix <= 0b010_00000:
        return Instruction(
            op=P3_OP_TABLE[bits(11, 2)],
            rd=reg(8),
            rs=Imm(bits(0, 8)),
        )

    # 4: 0b010000--
    # ALU operations
    elif 0b010000_00 <= prefix <= 0b010001_00:
        return Instruction(
            op=P4_OP_TABLE[bits(6, 5)],
            rd=reg(0),
            rs=reg(3),
        )

    # 5: 0b010001--
    # Hi register operations/branch exchange
    elif 0b010001_00 <= prefix <= 0b010010_00:
        h2 = bit(6)
        h1 = bit(7)

        op = P5_OP_TABLE[bits(8, 2), h1]
        if op == Op.ADD or op == Op.CMP or op == Op.MOV:
            return Instruction(
                op=op,
                rd=regx(0, h1),
                rs=regx(3, h2),
            )
        elif op == Op.BX or op == Op.BLX:
            return Instruction(
                op,
                rd=regx(0, h1),
            )
        else:
            raise AssertionError

    # 6: 0b01001---
    # PC-relative load
    elif 0b01001_000 <= prefix <= 0b01010_000:
        return Instruction(
            op=Op.LDR,
            rd=reg(8),
            rs=Reg.pc,
            rn=Imm(bits(0, 8)),
        )

    # 7: 0b0101--0-
    # Load/store with register
    elif prefix in {0b0101_00_0_0, 0b0101_00_0_1,
                    0b0101_01_0_0, 0b0101_01_0_1,
                    0b0101_10_0_0, 0b0101_10_0_1,
                    0b0101_11_0_0, 0b0101_11_0_1}:
        return Instruction(
            op=P7_OP_TABLE[bit(11), bit(10)],  # L, B
            rd=reg(0),
            rs=reg(3),
            rn=reg(6),
        )

    # 8: 0b0101--1-
    # Load/store sign-extended byte/halfword
    elif prefix in {
        0b0101_00_1_0, 0b0101_00_1_1,
        0b0101_01_1_0, 0b0101_01_1_1,
        0b0101_10_1_0, 0b0101_10_1_1,
        0b0101_11_1_0, 0b0101_11_1_1}:
        return Instruction(
            op=P8_OP_TABLE[bit(11), bit(10)],  # S, H
            rd=reg(0),
            rs=reg(3),
            rn=reg(6),
        )

    # 9: 0b011-----
    # Load/store with immediate offset
    elif 0b011_00_000 <= prefix <= 0b100_00_000:
        return Instruction(
            op=P9_OP_TABLE[bit(11), bit(12)],  # L, B
            rd=reg(0),
            rs=reg(3),
            rn=Imm(bits(6, 5)),
        )

    # 10: 0b1000----
    # Load/store halfword
    elif 0b1000_0_000 <= prefix <= 0b1001_0_000:
        return Instruction(
            op=Op.STRH if bit(11) else Op.LDRH,  # L
            rd=reg(0),
            rs=reg(3),
            rn=Imm(bits(6, 5)),
        )

    # 11: 0b1001----
    # SP-relative load/store
    elif 0b1001_0_000 <= prefix <= 0b1010_0_000:
        return Instruction(
            op=Op.STR if bit(11) else Op.LDR,  # L
            rd=reg(8),
            rs=Reg.sp,
            rn=Imm((bits(0, 8) << 2)),
        )

    # 12: 0b1010----
    # Load address
    elif 0b1010_0000 <= prefix <= 0b1011_0000:
        return Instruction(
            op=Op.ADD,
            rd=reg(8),
            rs=Reg.sp if bit(11) else Reg.pc,
            rn=Imm((bits(0, 8) << 2)),
        )

    # 13: 0b10110000
    # Add offset to stack pointer
    if prefix == 0b10110000:
        sword7 = bits(0, 7)

        return Instruction(
            op=Op.ADD,
            rd=Reg.sp,
            rs=Imm(-sword7 if bit(7) else sword7),
        )

    # 14: 0b1011-10-
    # Push/pop registers
    elif prefix in {0b1011_0_10_0,
                    0b1011_0_10_1,
                    0b1011_1_10_0,
                    0b1011_1_10_1}:
        return Instruction(
            op=Op.POP if bit(11) else Op.PUSH,  # L
            rd=Imm(bits(0, 8)),
            flag=bit(8)  # R
        )

    # 15: 0b1100----
    # Multiple load/store
    elif 0b1100_0_000 <= prefix <= 0b1101_0_000:
        return Instruction(
            op=Op.LDMIA if bit(11) else Op.STMIA,  # L
            rd=reg(8),
            rs=Imm(bits(0, 8)),
        )

    # 16: 0b1101----
    # Conditional branch
    if 0b1101_0000 <= prefix <= 0b1101_1111:
        value = bits(0, 8) << 1
        if bit(7):
            value |= ~0b11111111
            # TODO: signed?

        value += 4

        return Instruction(
            op=P16_OP_TABLE[bits(8, 4)],
            rd=Imm(value)
        )

    # 17= 0b11011111
    # Software Interrupt
    elif prefix == 0b11011111:
        return Instruction(
            op=Op.SWI,
            rd=Imm(bits(0, 8)),
        )

    # 18: 0b11100---
    # Unconditional branch
    elif 0b11100_000 <= prefix <= 0b11101_000:
        offset = bits(0, 10)
        value = offset << 1
        if bit(10):
            value |= ~0b11_1111_1111
            # TODO: signed

        value += 4

        return Instruction(
            op=Op.B,
            rd=Imm(value),
        )

    # 19: 0b1111----
    # Long branch with link
    elif 0b1111_0_000 <= prefix <= 0b1111_1_111 or \
            prefix == 0b1111_1_111:
        return Instruction(
            op=Op.BL,
            rd=Imm(bits(0, 11)),
            flag=bit(11),  # h
        )

    # ?: 0b10110010
    # SXTH, SXTB, UXTH, UXTB
    elif prefix == 0b10110010:
        return Instruction(
            op=U1_OP_TABLE[bits(6, 2)],
            rd=reg(0),
            rs=reg(3),
        )

    # ?: 0b10111010
    # REV
    elif prefix == 0b10111010:
        return Instruction(
            op=U2_OP_TABLE[bits(6, 2)],
            rd=reg(0),
            rs=reg(3),
        )

    else:
        raise ValueError("invalid code")


for i in range(0x10000):
    try:
        print(hex(i), decode(i))
    except Exception as e:
        print(hex(i), repr(e))
