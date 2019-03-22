from contextlib import contextmanager

from pathlib import Path

import pickle
from typing import Set, Optional, Sequence, List, Dict

from dataclasses import field

from oputil.opaot.instr.parser import parse
from oputil.opaot.instr.types import *
from oputil.opsim.address import MemoryMap
from oputil.opsim.firmware import Firmware
from oputil.opsim.types import RawFunction
from oputil.opsim.util import from_bytes
from pprint import pprint
import json

FLASH = MemoryMap.FLASH
THUMB_MASK = 0b11111111_11111111_11111111_11111110


@dataclass(repr=False)
class Block(Dict[int, Insn]):
    start: int = -1
    end: int = -1
    is_tail_call: bool = False


@dataclass(unsafe_hash=True)
class Function(RawFunction):
    address: int
    size: Optional[int]
    name: str
    path: str

    blocks: List[Block] = field(default_factory=list, repr=False, hash=False)

    has_indirect: bool = False
    indirect_offset: Set[int] = field(default_factory=set, repr=False, hash=False)
    direct_offset: Set[int] = field(default_factory=set, repr=False, hash=False)
    finish_offset: Set[int] = field(default_factory=set, repr=False, hash=False)


class Visitor:
    def __init__(self, firmware: Firmware):
        self.firmware = firmware
        self.memory = firmware.buffer

    def read_ubyte(self, pc):
        addr = pc - FLASH.address
        return self.memory[addr]

    def read_ushort(self, pc):
        addr = pc - FLASH.address
        return from_bytes(self.memory[addr:addr + 2])

    def read_int(self, addr):
        return from_bytes(self.memory[addr:addr + 4])

    def load(self, pc) -> Insn:
        insn = parse(
            pc,
            self.read_ushort(pc),
            self.read_ushort(pc + 2)
        )

        return insn

    def parse(self, func: RawFunction) -> Function:
        new_func = Function(
            func.address,
            func.size,
            func.name,
            func.path,
        )

        new_func.direct_offset.add(0)

        visited = set()
        self.visit(new_func, new_func.address, visited)
        self.walk(new_func, visited)

        return new_func

    def walk(self, func: Function, visited: set):
        pc = func.address
        block = Block()

        def handle():
            nonlocal block
            if block:
                block.start = min(block)
                block.end = max(block)
                func.blocks.append(block)

            block = Block()

        visited = set(visited)
        while pc in func and visited:
            if pc not in visited:
                handle()
                pc += 2
                continue

            visited.remove(pc)

            offset = pc - func.address
            if offset in func.direct_offset or offset in func.indirect_offset:
                handle()

            insn = self.load(pc)
            block[offset] = insn

            if offset in func.finish_offset:
                block.is_tail_call = True
                handle()

            pc += 2

        handle()

    def visit(self, func: Function, pc, visited: set):
        lr: int = None

        func.direct_offset.add(pc - func.address)
        while pc in func and pc not in visited:
            visited.add(pc)
            insn = self.load(pc)

            target = None
            next_pc = None

            if insn.op == Op.BL or insn.op == Op.BLX or isinstance(insn, InsnSVC):
                pc_offset = pc - func.address
                cb_offset = pc_offset + (2 if insn.op != Op.BL else 4)
                func.finish_offset.add(pc_offset)
                func.indirect_offset.add(cb_offset)

            if isinstance(insn, Insn2) and insn.op == Op.MOV and isinstance(insn.src, Reg) and insn.dest == Reg.pc:
                next_pc = None
            elif isinstance(insn, InsnStack) and insn.op == Op.POP and insn.special_reg == Reg.pc:
                next_pc = None
            elif insn.op == Op.B:
                assert isinstance(insn, InsnBranch)
                assert isinstance(insn.dest, Offset)
                target = insn.dest.target
            elif insn.op == Op.BL:
                if isinstance(insn, (InsnBranch2, InsnBranch)):
                    func.finish_offset.add(pc - 2 - func.address)
                    break
                else:
                    assert isinstance(insn, InsnLongBranch)
                    assert isinstance(insn.dest, Offset)
                    target = insn.dest.target
                    next_pc = (pc + 3 + 2) & THUMB_MASK
            elif insn.op == Op.BX:
                if insn.dest == Reg.lr:
                    target = lr
                elif isinstance(insn.dest, Reg):
                    pass
            elif insn.op == Op.BLX:
                next_pc = pc + 2
                if insn.dest == Reg.lr:
                    target = lr
                    lr = next_pc
                else:
                    func.direct_offset.add(next_pc - func.address)  # dup
            elif insn.op == Op.POP:
                if Reg.pc not in insn.regs:
                    next_pc = pc + 2
            elif isinstance(insn, InsnBranchIf):
                target = insn.dest.target
                next_pc = pc + 2
            elif isinstance(insn, InsnMem):
                assert isinstance(insn.dest, Reg)
                assert insn.dest.value <= 7

                if insn.op.name.startswith("LDR"):
                    if insn.base == Reg.pc:
                        maddr = (pc + insn.offset.value + 4) & 0b11111111_11111111_11111111_11111101
                        mvalue = self.read_int(maddr)
                        mfunc: RawFunction = self.firmware.text_map[mvalue]
                        if mfunc is not None:
                            if (mvalue & THUMB_MASK) == mfunc.address:
                                mfunc.has_indirect = True  # referenced

                next_pc = pc + 2
            elif isinstance(insn, InsnSVC):
                next_pc = pc + 2
                func.direct_offset.add(next_pc - func.address)  # dup
            else:
                next_pc = pc + 2

            if target is not None:
                new_func: RawFunction = self.firmware.text_map[target]
                if func == new_func:
                    self.visit(func, target, visited)
                else:
                    if self.is_tail_call(new_func):
                        next_pc = None

                if next_pc is not None:
                    func.direct_offset.add(next_pc - func.address)

                    if insn.op == Op.BL or insn.op == Op.BLX:
                        func.indirect_offset.add(next_pc - func.address)

            if next_pc is None:
                func.finish_offset.add(pc - func.address)
                break

            pc = next_pc
            continue

    def is_tail_call(self, func: RawFunction):
        if func.name.startswith("mp_raise_"):
            return True
        elif func.name == "nlr_jump":
            return True
        elif func.name == "nlr_jump_fail":
            return True
        elif func.name == "__fatal_error":
            return True
        elif func.name.startswith("__gnu_thumb1_case_"):
            assert False

        return False

    def build(self, func: Function):
        level = 0

        @contextmanager
        def indent(*args):
            nonlocal level

            write_indent()
            print(*args, "{")

            level += 1
            try:
                yield
            finally:
                level -= 1

            write_indent()
            print("}")

        def write_indent():
            print("    " * level, end="")

        def write(*args, comment=None):
            if not args and not comment:
                print()
                return

            write_indent()

            if not comment:
                print(*args, end=';\n')
            else:
                if args:
                    print(*args, end=';')
                    print(' //', comment)
                else:
                    print('//', comment)

        def wrap(arg):
            if isinstance(arg, Reg):
                return f"cpu.{arg}"
            elif isinstance(arg, str):
                return arg

            return repr(arg)

        def calc(*args):
            return " ".join(map(wrap, args))

        def assign(dest, line):
            return f"{wrap(dest)} = {line}"

        def call(op, *args):
            return f"cpu.{op}({', '.join(map(wrap, args))})"

        def jump(offset):
            write(assign("offset", offset))
            write("continue")

        def stop():
            write("return")

        def write_insn(offset: int, insn: Insn):
            pc = func.address + offset

            branch_args = ()
            branch_link_arg = ()
            branch_offset = None
            cb_offset = None

            if insn.op == Op.BL or insn.op == Op.BLX or isinstance(insn, InsnSVC):
                cb_offset = offset + (2 if insn.op != Op.BL else 4)
                branch_link_arg = f"{func.name} + {cb_offset} | 1", cb_offset

            if isinstance(insn, (InsnBranch, InsnLongBranch, InsnBranchIf, InsnBranchIf2, InsnBranch2)):
                if isinstance(insn.dest, Offset):
                    target = insn.dest.target
                    new_func = self.firmware.text_map[target]
                    if func == new_func:
                        branch_offset = target - new_func.address

                    if isinstance(insn, InsnBranchIf):
                        branch_args = target - new_func.address,
                    elif func == new_func or (target - new_func.address) != 0:
                        branch_args = new_func.name, target - new_func.address
                    else:
                        branch_args = new_func.name,

                    if insn.op == Op.BL or insn.op == Op.BLX:
                        branch_args += branch_link_arg

            if isinstance(insn, Insn2):
                if insn.op == Op.MOV and isinstance(insn.src, Reg):
                    write(assign(insn.dest, call(insn.op, insn.src)))
                    if insn.dest == Reg.pc:
                        write("jump(pc)")
                elif insn.op == Op.MOVS and isinstance(insn.src, Reg):
                    write(assign(insn.dest, call(insn.op, insn.src)))
                    if insn.dest == Reg.pc:
                        write("jump(pc)")
                elif insn.op == Op.CMP or insn.op == Op.TSTS or insn.op == Op.CMN:
                    write(call(insn.op, insn.dest, insn.src))
                elif insn.op == Op.SXTH or insn.op == Op.SXTB or insn.op == Op.UXTH or insn.op == Op.UXTB or \
                        insn.op == Op.REV or insn.op == Op.RSBS:
                    write(assign(insn.dest, call(insn.op, insn.src)))
                else:
                    write(assign(insn.dest, call(insn.op, insn.dest, insn.src)))
            elif isinstance(insn, Insn3):
                write(assign(insn.dest, call(insn.op, insn.src, insn.offset)))
            elif isinstance(insn, InsnMem):
                assert isinstance(insn.dest, Reg)
                assert insn.dest.value <= 7

                if insn.op.name.startswith("LDR"):
                    if insn.base == Reg.pc:
                        moffset10 = insn.offset.value + 4  # make ~10
                        assert moffset10 > 0
                        maddr = (pc + insn.offset.value + 4) & 0b11111111_11111111_11111111_11111101
                        mvalue = self.read_int(maddr)
                        mfunc = self.firmware.text_map[mvalue]

                        if mfunc is not None:
                            if (mvalue & THUMB_MASK) == mfunc.address:
                                write(assign(insn.dest, call("mov", f"{mfunc.name} | 1")))
                            else:
                                raise Exception("invalid memory read")
                        else:
                            assert insn.op == Op.LDR
                            vfunc = self.firmware.symbol_map[mvalue]
                            write(
                                assign(insn.dest, call(insn.op, f"{func.name} + {maddr - func.address}")),
                                comment=vfunc.name if vfunc is not None and mvalue == vfunc.address else None)
                    else:
                        is_zero_imm = isinstance(insn.offset, Imm) and insn.offset.value == 0

                        if is_zero_imm:
                            maddr = f"{insn.base!r}"
                        else:
                            maddr = f"{insn.base!r} + {insn.offset!r}"

                        write(assign(insn.dest, call(insn.op, maddr)))
                elif insn.op.name.startswith("STR"):
                    if isinstance(insn.offset, Imm) and insn.offset.value == 0:
                        write(call(insn.op, insn.base, insn.dest))
                    else:
                        write(call(insn.op, f"{insn.base!r} + {insn.offset!r}", insn.dest))
                else:
                    assert False, insn.op
            elif isinstance(insn, InsnAddr):
                if insn.Rs == Reg.pc:
                    write(assign(insn.Rd, call(insn.op, insn.Rs, insn.dest_pc(pc) - pc)),
                          comment=f"pc + {insn.soffset.value}")
                else:
                    write(assign(insn.Rd, call(insn.op, insn.Rs, insn.soffset)))
            elif isinstance(insn, InsnStack):
                assert insn.op == Op.PUSH or insn.op == Op.POP
                regs_s = list(map(repr, insn.pure_regs))
                if insn.op == Op.POP:
                    regs_s = [reg.upper() for reg in regs_s]

                if regs_s:
                    write(call(insn.op, 'true' if insn.R else 'false', regs_s))
                else:
                    write(call(insn.op, 'true' if insn.R else 'false'))
            elif isinstance(insn, InsnMemStack):
                regs_s = list(map(repr, insn.regs))
                assert regs_s
                if insn.op == Op.LDMIA:
                    regs_s = [reg.upper() for reg in regs_s]

                write(assign(insn.Rb, call(insn.op, insn.Rb, regs_s)))
            elif isinstance(insn, (InsnBranch, InsnLongBranch)):
                if insn.op == Op.B and branch_offset is not None:
                    write(call("step"))
                    jump(branch_offset)
                else:
                    if branch_args:
                        write(call(insn.op, *branch_args))
                    else:
                        if insn.op == Op.BLX:
                            write(call(insn.op, insn.dest, *branch_link_arg))
                        elif insn.op == Op.BL:
                            # TODO: joint_set is full
                            write("crash(); // error")
                            write(call(insn.op, insn.dest))
                        else:
                            write(call(insn.op, insn.dest))
            elif isinstance(insn, InsnBranchIf):
                if branch_offset is not None:
                    with indent(f"if {call(insn.op)}"):
                        jump(branch_offset)
                elif branch_args:
                    with indent(f"if {call(insn.op, *branch_args)}"):
                        stop()
                else:
                    with indent(f"if {call(insn.op, insn.dest)}"):
                        stop()
            elif isinstance(insn, InsnBranchIf2):
                if branch_args:
                    with indent(f"if {call(insn.op, insn.src, *branch_args)}"):
                        stop()
                else:
                    with indent(f"if {call(insn.op, insn.src, insn.dest)}"):
                        stop()
            elif isinstance(insn, InsnSVC):
                write(call(insn.op, insn.soffset, cb_offset))
            else:
                raise Exception(repr(insn))

        def write_block(no: int, block: Block):
            for offset, insn in block.items():
                write_insn(offset, insn)

            if block.is_tail_call:
                stop()
            else:
                next_offset = min(func.blocks[no + 1]) if no + 1 < len(func.blocks) else None
                if next_offset:
                    jump(next_offset)
                else:
                    stop()

        with indent(f"fn {func.name}(cpu: Cpu, offset: i32)"):
            if len(func.blocks) == 1 and min(func.blocks[0]) == 0:
                write("assert!(offset == 0)")
                write_block(0, func.blocks[0])
            else:
                write("let mut offset = offset")
                write()
                with indent("loop"):
                    with indent("match offset"):
                        for no, block in enumerate(func.blocks):
                            with indent(min(block), "=>"):
                                write_block(no, block)



def main():
    cache_path = Path("firmware.pickle")
    if not cache_path.exists():
        from oputil.opsim.firmware import firmware
        firmware.refresh()
        cache_path.write_bytes(pickle.dumps(firmware))
    else:
        firmware: Firmware = pickle.loads(cache_path.read_bytes())

    visitor = Visitor(firmware)
    functions = {func.name: func for func in firmware.text_map.vmap}
    json_funcs = []
    for func in functions.values():  # type: Function
        json_funcs.append({
            'name': func.name,
            'offset': func.address - 0x08000000,
            'size': func.size,
        })

        # func = visitor.parse(func)
        # visitor.build(func)

    result = {
        'functions': json_funcs,
    }

    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
