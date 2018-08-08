import pickle

from unicorn.arm_const import *

from opsim.cpu import CPU


class CpuContext:
    @staticmethod
    def save(cpu: CPU):
        registers = {
            reg: cpu.uc.reg_read(reg)
            for reg in range(UC_ARM_REG_APSR, UC_ARM_REG_ENDING)}

        regions = []

        for begin, end, perm in cpu.uc.mem_regions():
            size = end - begin + 1
            buffer = cpu.uc.mem_read(begin, size)
            regions.append((begin, end, perm, buffer))

        cpu.uc = cpu.cs = None
        ctx = registers, regions, cpu.state
        buffer = pickle.dumps(ctx)
        return buffer

    @staticmethod
    def load(buffer, cpu: CPU = None):
        if cpu is None:
            cpu = CPU()

        ctx = pickle.loads(buffer)
        registers, regions, cpu.state = ctx

        for begin, end, perm, buffer in regions:
            size = end - begin + 1
            cpu.uc.mem_map(begin, size, perm)
            cpu.uc.mem_write(begin, bytes(buffer))

        for reg, val in registers.items():
            cpu.uc.reg_write(reg, val)

        cpu.init_hook()
        return cpu
