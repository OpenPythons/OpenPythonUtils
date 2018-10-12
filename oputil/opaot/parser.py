# noinspection PyPep8Naming
# noinspection SpellCheckingInspection

from oputil.opaot import I7, I8, I9, I10, I11, I12, L1, L2, L3, L4, L5, L7, L8, L10, L11
from oputil.opaot import UnsupportedInstructionException, UnknownInstructionException


def parse(addr, code, next_code=None):
    prefix = code >> 12 & L4
    if prefix == 0 or prefix == 1:  #
        Rs = Reg(code >> 3 & L3)
        Rd = Reg(code & L3)
        prefix = code >> 11 & L2  # move shifted register
        if prefix == 0:  # LSL Rd, Rs, #Offset5
            offset = Imm(code >> 6 & L5)  # 0 ~ 31
            if offset.value == 0:
                return Insn2(Op.MOVS, Rd, Rs)
            else:
                return Insn3(Op.LSLS, Rd, Rs, offset)
        elif prefix == 1:  # LSR Rd, Rs, #Offset5
            offset = Imm((code >> 6 & L5) or 0x20)  # 1 ~ 32
            return Insn3(Op.LSRS, Rd, Rs, offset)
        elif prefix == 2:  # ASR Rd, Rs, #Offset5
            offset = Imm((code >> 6 & L5) or 0x20)  # 1 ~ 32
            return Insn3(Op.ASRS, Rd, Rs, offset)
        elif prefix == 3:  # add/subtract
            I = code >> 10 & 1 != 0
            target = (Imm if I else Reg)(code >> 6 & L3)
            Rs = Reg(code >> 3 & L3)
            Rd = Reg(code & L3)
            prefix = code >> 9 & L1
            if prefix == 0:
                return Insn3(Op.ADDS, Rd, Rs, target)  # ADD Rd, Rs, Rn | ADD Rd, Rs, #Offset3
            elif prefix == 1:
                return Insn3(Op.SUBS, Rd, Rs, target)  # SUB Rd, Rs, Rn | SUB Rd, Rs, #Offset3
    elif prefix == 2 or prefix == 3:  # move/compare/add/subtract immediate
        Rd = Reg(code >> 8 & L3)
        offset = Imm(code & L8)
        prefix = code >> 11 & L2
        if prefix == 0:
            return Insn2(Op.MOVS, Rd, offset)  # MOV Rd, #Offset8
        elif prefix == 1:
            return Insn2(Op.CMP, Rd, offset)  # CMP Rd, #Offset8
        elif prefix == 2:
            return Insn2(Op.ADDS, Rd, offset)  # ADD Rd, #Offset8
        elif prefix == 3:
            return Insn2(Op.SUBS, Rd, offset)  # SUB Rd, #Offset8
    elif prefix == 4:
        prefix = code >> 10 & L2
        if prefix == 0:  # ALU operations
            Rs = Reg(code >> 3 & L3)
            Rd = Reg(code & L3)
            prefix = code >> 6 & L4
            if prefix == 0:
                return Insn2(Op.ANDS, Rd, Rs)  # AND Rd, Rs Rd:= Rd AND Rs
            elif prefix == 1:
                return Insn2(Op.EORS, Rd, Rs)  # EOR Rd, Rs Rd:= Rd EOR Rs
            elif prefix == 2:
                return Insn2(Op.LSLS, Rd, Rs)  # LSL Rd, Rs Rd := Rd << Rs
            elif prefix == 3:
                return Insn2(Op.LSRS, Rd, Rs)  # LSR Rd, Rs Rd := Rd >>> Rs
            elif prefix == 4:
                return Insn2(Op.ASRS, Rd, Rs)  # ASR Rd, Rs Rd := Rd ASR Rs
            elif prefix == 5:
                return Insn2(Op.ADCS, Rd, Rs)  # ADC Rd, Rs Rd := Rd + Rs + C-bit
            elif prefix == 6:
                return Insn2(Op.SBCS, Rd, Rs)  # SBC Rd, Rs Rd := Rd - Rs - NOT C-bit
            elif prefix == 7:
                return Insn2(Op.RORS, Rd, Rs)  # ROR Rd, Rs Rd := Rd ROR Rs
            elif prefix == 8:
                return Insn2(Op.TSTS, Rd, Rs)  # TST Rd, Rs set condition codes on Rd AND Rs
            elif prefix == 9:
                return Insn2(Op.RSBS, Rd, Rs)  # NEG Rd, Rs Rd = Reg(-Rs)
            elif prefix == 10:
                return Insn2(Op.CMP, Rd, Rs)  # CMP Rd, Rs set condition codes on Rd - Rs
            elif prefix == 11:
                return Insn2(Op.CMN, Rd, Rs)  # CMN Rd, Rs set condition codes on Rd + Rs
            elif prefix == 12:
                return Insn2(Op.ORRS, Rd, Rs)  # ORR Rd, Rs Rd := Rd OR Rs
            elif prefix == 13:
                return Insn3(Op.MULS, Rd, Rs, Rd)  # MUL Rd, Rs Rd := Rs * Rd
            elif prefix == 14:
                return Insn2(Op.BICS, Rd, Rs)  # BIC Rd, Rs Rd := Rd AND NOT Rs
            elif prefix == 15:
                return Insn2(Op.MVNS, Rd, Rs)  # MVN Rd, Rs Rd := NOT Rs
        elif prefix == 1:  # Hi register operations/branch exchange
            H1 = code >> 7 & L1 != 0
            H2 = code >> 6 & L1 != 0
            Rd = Reg((code & L3) + (8 if H1 else 0))
            Rs = Reg((code >> 3 & L3) + (8 if H2 else 0))
            prefix = code >> 8 & L2
            if prefix == 0:
                if Rs == Reg.sp:
                    return Insn3(Op.ADD, Rd, Rs, Rd)  # ADD Rd, SP, Rd
                else:
                    return Insn2(Op.ADD, Rd, Rs)  # ADD Rd, Hs ADD Hd, Rs ADD Hd, Hs
            elif prefix == 1:
                return Insn2(Op.CMP, Rd, Rs)  # CMP Rd, Hs CMP Hd, Rs CMP Hd, Hs
            elif prefix == 2:
                return Insn2(Op.MOV, Rd, Rs)  # MOV Rd, Hs MOV Hd, Rs MOV Hd, Hs
            elif prefix == 3:
                if H1:
                    if Rd.value != 8:
                        raise UnknownInstructionException

                    return InsnBranch(Op.BLX, Rs)  # BLX Rs BX Hs
                else:
                    return InsnBranch(Op.BX, Rs)  # BX Rs BX Hs
        elif prefix == 2 or prefix == 3:  # PC-relative load
            Rd = Reg(code >> 8 & L3)
            offset = Imm((code & L8) << 2)
            return InsnMem(Op.LDR, Rd, Reg.pc, offset)  # LDR Rd, [PC, #Imm]
    elif prefix == 5:  #
        Ro = Reg(code >> 6 & L3)
        Rb = Reg(code >> 3 & L3)
        Rd = Reg(code & L3)
        if code & I9 == 0:  # load/store with register offset
            L = code & I11 != 0
            B = code & I10 != 0
            if L:
                if B:
                    return InsnMem(Op.LDRB, Rd, Rb, Ro)  # LDRB Rd, [Rb, Ro]
                else:
                    return InsnMem(Op.LDR, Rd, Rb, Ro)  # LDR Rd, [Rb, Ro]
            else:
                if B:
                    return InsnMem(Op.STRB, Rd, Rb, Ro)  # STRB Rd, [Rb, Ro]
                else:
                    return InsnMem(Op.STR, Rd, Rb, Ro)  # STR Rd, [Rb, Ro]
        else:  # load/store sign-extended byte/halfword
            H = code & I11 != 0
            S = code & I10 != 0
            if S:
                if H:
                    return InsnMem(Op.LDRSH, Rd, Rb, Ro)  # LDSH Rd, [Rb, Ro]
                else:
                    return InsnMem(Op.LDRSB, Rd, Rb, Ro)  # LDSB Rd, [Rb, Ro]
            else:
                if H:
                    return InsnMem(Op.LDRH, Rd, Rb, Ro)  # LDRH Rd, [Rb, Ro]
                else:
                    return InsnMem(Op.STRH, Rd, Rb, Ro)  # STRH Rd, [Rb, Ro]
    elif prefix == 6 or prefix == 7:  # load/store with immediate offset
        B = code & I12 != 0
        L = code & I11 != 0
        Rb = Reg(code >> 3 & L3)
        Rd = Reg(code & L3)
        offset = Imm(code >> 6 & L5)

        if not B:
            offset.value <<= 2

        if L:
            if not B:
                return InsnMem(Op.LDR, Rd, Rb, offset)  # LDR Rd, [Rb, #Imm]
            else:
                return InsnMem(Op.LDRB, Rd, Rb, offset)  # LDRB Rd, [Rb, #Imm]
        else:
            if not B:
                return InsnMem(Op.STR, Rd, Rb, offset)  # STR Rd, [Rb, #Imm]
            else:
                return InsnMem(Op.STRB, Rd, Rb, offset)  # STRB Rd, [Rb, #Imm]
    elif prefix == 8:  # load/store halfword
        L = code & I11 != 0
        Rb = Reg(code >> 3 & L3)
        Rd = Reg(code & L3)
        offset = Imm((code >> 6 & L5) << 1)

        if L:
            return InsnMem(Op.LDRH, Rd, Rb, offset)  # LDRH Rd, [Rb, #Imm]
        else:
            return InsnMem(Op.STRH, Rd, Rb, offset)  # STRH Rd, [Rb, #Imm]
    elif prefix == 9:  # SP-relative load/store
        L = code & I11 != 0
        Rd = Reg(code >> 8 & L3)
        offset = Imm((code & L8) << 2)

        if L:
            return InsnMem(Op.LDR, Rd, Reg.sp, offset)  # LDR Rd, [SP, #Imm]
        else:
            return InsnMem(Op.STR, Rd, Reg.sp, offset)  # STR Rd, [SP, #Imm]
    elif prefix == 10:  # load address
        fSP = code & I11 != 0
        Rd = Reg(code >> 8 & L3)
        offset = Imm((code & L8) << 2)

        if fSP:
            return InsnAddr(Op.ADD, Rd, Reg.sp, offset)  # ADD Rd, SP, #Imm
        else:
            # (side-effect) || REGS[PC] + 4 and I1.inv()
            return InsnAddr(Op.ADD, Rd, Reg.pc, offset)  # ADD Rd, PC, #Imm
    elif prefix == 11:  #
        prefix = code >> 8 & L4
        if prefix == 0:  # add offset to Stack Pointer
            S = code & I7 != 0
            value = (code & L7) << 2

            if S:
                return Insn2(Op.SUB, Reg.sp, Imm(value))
            else:
                return Insn2(Op.ADD, Reg.sp, Imm(value))
        elif prefix == 1:
            Rd = Reg(code & L3)
            value = (code >> 3) & L5
            value <<= 1
            value += 4
            offset = Offset(value, addr)

            return InsnBranchIf2(Op.CBZ, Rd, offset)  # CBZ Rd, #Imm
        elif prefix == 2:  # SXTH, SXTB, UXTH, UXTB
            Rs = Reg(code >> 3 & L3)
            Rd = Reg(code & L3)
            prefix = code >> 6 & L2
            if prefix == 0:
                return Insn2(Op.SXTH, Rd, Rs)  # SXTH Rd, Rs
            elif prefix == 1:
                return Insn2(Op.SXTB, Rd, Rs)  # SXTB Rd, Rs
            elif prefix == 2:
                return Insn2(Op.UXTH, Rd, Rs)  # UXTH Rd, Rs
            elif prefix == 3:
                return Insn2(Op.UXTB, Rd, Rs)  # UXTB Rd, Rs
        elif prefix == 3:
            Rd = Reg(code & L3)
            value = (code >> 3) & L5
            value <<= 1
            value += 4 + 0x40
            offset = Offset(value, addr)

            return InsnBranchIf2(Op.CBZ, Rd, offset)  # CBZ Rd, #Imm
        elif prefix == 4 or prefix == 5:  # push/pop registers
            R = code & I8 != 0
            Rlist = code & L8
            if not Rlist and not R:
                raise UnknownInstructionException

            return InsnStack(Op.PUSH, Rlist, R)
        elif prefix == 6 or prefix == 7 or prefix == 8:
            raise UnknownInstructionException()
        elif prefix == 9:
            Rd = Reg(code & L3)
            value = (code >> 3) & L5
            value <<= 1
            value += 4
            offset = Offset(value, addr)

            return InsnBranchIf2(Op.CBNZ, Rd, offset)  # CBNZ Rd, #Imm
        elif prefix == 10:  #
            Rs = Reg(code >> 3 & L3)
            Rd = Reg(code & L3)
            prefix = code >> 6 & L2
            if prefix == 0:
                return Insn2(Op.REV, Rd, Rs)  # REV Rd, Rs
            elif prefix == 1:
                raise UnsupportedInstructionException()  # REV16 Rd, Rs
            elif prefix == 2:
                raise UnknownInstructionException()  # INVALID
            elif prefix == 3:
                raise UnsupportedInstructionException()  # REVSH Rd, Rs
        elif prefix == 11:
            Rd = Reg(code & L3)
            value = (code >> 3) & L5
            value <<= 1
            value += 4 + 0x40
            offset = Offset(value, addr)

            return InsnBranchIf2(Op.CBNZ, Rd, offset)  # CBNZ Rd, #Imm
        elif prefix == 12 or prefix == 13:  # push/pop registers
            R = code & I8 != 0
            Rlist = code & L8
            if not Rlist and not R:
                raise UnknownInstructionException

            return InsnStack(Op.POP, Rlist, R)
        elif prefix == 14 or prefix == 15:
            raise UnknownInstructionException()
    elif prefix == 12:  # multiple load/store
        L = code & I11 != 0
        Rlist = code & L8
        Rb = Reg(code >> 8 & L3)
        if not Rlist:
            raise UnknownInstructionException

        if not L:
            return InsnMemStack(Op.STAIM, Rb, Rlist)
        else:
            return InsnMemStack(Op.LDMIA, Rb, Rlist)
    elif prefix == 13:  # conditional branch (or software interrupt)
        value = code & L8
        cond = code >> 8 & L4
        if cond == 15:
            return InsnSVC(Op.SVC, Imm(value))  # software interrupt
        else:
            value = value << 1
            if (value & I8) != 0:
                value |= 0b11111110_00000000
                value = int.from_bytes(value.to_bytes(2, "big", signed=False), "big", signed=True)

            offset = Offset(value + 4, addr)
            if cond == 0:  # BEQ label
                return InsnBranchIf(Op.BEQ, offset)  # z
            elif cond == 1:  # BNE label
                return InsnBranchIf(Op.BNE, offset)  # !z
            elif cond == 2:  # BCS label
                return InsnBranchIf(Op.BCS, offset)  # c
            elif cond == 3:  # BCC label
                return InsnBranchIf(Op.BCC, offset)  # !c
            elif cond == 4:  # BMI label
                return InsnBranchIf(Op.BMI, offset)  # n
            elif cond == 5:  # BPL label
                return InsnBranchIf(Op.BPL, offset)  # !n
            elif cond == 6:  # BVS label
                return InsnBranchIf(Op.BVS, offset)  # v
            elif cond == 7:  # BVC label
                return InsnBranchIf(Op.BVC, offset)  # !v
            elif cond == 8:  # BHI label
                return InsnBranchIf(Op.BHI, offset)  # c && !z
            elif cond == 9:  # BLS label
                return InsnBranchIf(Op.BLS, offset)  # !c || z
            elif cond == 10:  # BGE label
                return InsnBranchIf(Op.BGE, offset)  # n == v // (n && v) || (!n && !v)
            elif cond == 11:  # BLT label
                return InsnBranchIf(Op.BLT, offset)  # n != v // (n && !v) || (!n && v)
            elif cond == 12:  # BGT label
                return InsnBranchIf(Op.BGT, offset)  # !z && n == v // !z && (n && v || !n && !v)
            elif cond == 13:  # BLE label
                return InsnBranchIf(Op.BLE, offset)  # z || n != v  / z || (n && !v) || (!n && v)
            elif cond == 14:
                raise UnknownInstructionException()

        assert False
    elif prefix == 14:  # unconditional branch
        if code & I11 != 0:
            raise UnknownInstructionException()

        value = (code & L10) << 1
        if (code & I10) != 0:
            value |= 0b11111000_00000000
            value = int.from_bytes(value.to_bytes(2, "big", signed=False), "big", signed=True)

        offset = Offset(value + 4, addr)
        return InsnBranch(Op.B, offset)
    elif prefix == 15:  # long branch with link
        H = code >> 11 & L1 != 0
        imm = Imm(code & L11)
        if next_code is None:
            if not H:
                return InsnBranch2(Op.BLH, imm, H)
            else:
                return InsnBranch(Op.BL, imm)
        else:
            if H:
                return InsnBranch(Op.BL, imm)

            next_insn: InsnBranch2 = parse(addr + 2, next_code)
            if next_insn.op != Op.BL or not isinstance(next_insn.dest, Imm):
                raise UnknownInstructionException(repr((H, next_insn)))  # another exception?

            value = imm.value << 12
            value |= next_insn.dest.value << 1
            if (value & (1 << 22)) != 0:
                value |= 0b11111111_10000000_00000000_00000000
                value = int.from_bytes(value.to_bytes(4, "big", signed=False), "big", signed=True)

            offset = Offset(value + 2, addr + 2)
            return InsnLongBranch(Op.BL, offset)
