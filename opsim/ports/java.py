import os
import sys
from pathlib import Path
from pprint import pprint

from unicorn.arm_const import UC_ARM_REG_PC

from opsim.address import MemoryMap
from opsim.firmware import firmware

# noinspection PyUnresolvedReferences
__all__ = ["ThumbSJ", "run_sj"]

cwd = os.getcwd()
os.chdir(r"C:\Program Files\Java\jdk1.8.0_171\jre\bin\server")

import jnius_config

jnius_config.expand_classpath()
jnius_config.add_classpath(r"C:\Users\EcmaXp\Dropbox\Projects\ThumbSJ\out\production\ThumbSJ")
jnius_config.options += [
    "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005"
    # "-XX:+UnlockDiagnosticVMOptions",
    # "-XX:+PrintCompilation",
    # "-XX:+PrintInlining",
]

# noinspection PyUnresolvedReferences
import java

with java:
    # noinspection PyUnresolvedReferences
    from kr.pe.ecmaxp.thumbsj import CPU, MemoryFlag, Handler

os.chdir(cwd)


class Regs:
    def __init__(self, regs):
        self.regs = regs

    def Load(self):
        return self.regs.load()

    def Set(self, reg, value):
        self.regs.set(reg, value)

    def Get(self, reg):
        return self.regs.get(reg)


class ThumbSJ:
    def __init__(self):
        self.cpu = CPU()

    @property
    def Regs(self):
        return Regs(self.cpu.regs)

    @property
    def Memory(self):
        return self.cpu.memory

    def Run(self, count):
        return self.cpu.run(count)


def ready_sim_java(cpu, sim):
    PC = 15
    sim.Regs.Set(PC, cpu.uc.reg_read(UC_ARM_REG_PC))
    flags = [MemoryFlag.RX, MemoryFlag.RW, Handler(), MemoryFlag.RW, MemoryFlag.RW]
    for (begin, end, perms) in cpu.uc.mem_regions():
        print(hex(begin), hex(end - begin + 1))
        sim.Memory.map(begin, end - begin + 1, flags.pop(0))
    sim.Memory.writeBuffer(MemoryMap.FLASH.address, firmware.buffer)


prefix_map = {}
core_path = r"C:\Users\EcmaXp\Dropbox\Projects\ThumbSJ\src\kr\pe\ecmaxp\thumbsj\CPU.java"
for lineno, line in enumerate(Path(core_path).read_text().splitlines(), 1):
    if "// :" in line:
        for prefix in line[line.index("// :") + len("// :"):].split(" | :"):
            prefix_map[prefix] = lineno


def trace_code_java(bcode, inst):
    prefix_score = []
    for prefix in prefix_map:
        if bcode[:len(prefix)] == prefix:
            prefix_score.append((-len(prefix), prefix))

    for score, prefix in sorted(prefix_score):
        lineno = prefix_map[prefix]
        if inst:
            print(f"\tat kr.{inst.mnemonic}(ThumbSJ.java:{lineno + 1})", file=sys.stderr)

        break
    else:
        pprint(prefix_map)
        pprint(prefix_score)
        assert False, ("no prefix", bcode)
