from unicorn.arm_const import UC_ARM_REG_CPSR

from oputil.opsim import REGS, REGS_NAME
from oputil.opsim.util import from_bytes, get_CPSR, hex32


def check_failures(cpu, sim):
    target_regs: set = None
    sim_regs = sim.Regs.Load()

    failure = False
    for reg, tc_value in zip(REGS, sim_regs):
        uc_value = cpu.uc.reg_read(reg)
        tc_value &= 0xFFFFFFFF

        if reg == UC_ARM_REG_CPSR:
            if (uc_value & 0xfff00000) != (tc_value & 0xfff00000):
                failure = True
        elif uc_value != tc_value:
            if not failure:
                failure = True
                target_regs = set()

            target_regs.add(reg)

    if failure and target_regs is None:
        target_regs = set()

    return failure, target_regs, sim_regs


def print_failures(cpu, sim, prev_pc, target_regs, sim_regs, count, *, last_sim_regs=None):
    print(end="> ")
    addr = prev_pc
    buf = cpu.uc.mem_read(addr, 2)

    print("addr = ", hex(addr))
    bcode = bin(from_bytes(buf))[2:].zfill(16)
    print(":", bcode[0:4], bcode[4:8], bcode[8:12], bcode[12:16])

    inst = None
    for inst in cpu.cs.disasm(buf, addr, 1):  # type: CsInsn
        if cpu.firmware:
            print("@", cpu.firmware.mapping[inst.address])

        if inst.bytes:
            assert len(inst.bytes) == 2, (inst.bytes)
            print(inst.mnemonic, inst.op_str)

            for operand in inst.operands:  # type: ArmOp
                target_regs.add(operand.reg)
        else:
            break

    for no, (reg, tc_value) in enumerate(zip(REGS, sim_regs)):
        uc_value = cpu.uc.reg_read(reg)
        tc_value &= 0xFFFFFFFF

        if reg == UC_ARM_REG_CPSR:
            print(
                REGS_NAME[reg].ljust(5),
                get_CPSR(uc_value & 0xfff00000),
                get_CPSR(tc_value),
                (uc_value & 0xfff00000 != tc_value and "[!]" or ""),
                sep='\t'
            )
        else:
            if reg in target_regs:
                last_uc_value = last_sim_regs[no] if last_sim_regs else None

                print(
                    REGS_NAME[reg].ljust(5),
                    hex32(uc_value),
                    hex32(tc_value),
                    hex32(last_uc_value) if last_uc_value is not None else "-",
                    (uc_value != tc_value and "[!]" or ""),
                    sep='\t'
                )

    print("addr:", prev_pc)
    print("count:", count)
    return bcode, inst
