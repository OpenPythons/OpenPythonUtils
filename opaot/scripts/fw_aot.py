import io
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Optional

from opaot.errors import UnknownInstructionException, UnsupportedInstructionException
from opaot.parser import parse
from opaot.types import *
from opsim.address import MemoryMap
from opsim.cpu import CPU
from opsim.firmware import firmware, Function
from opsim.state import CpuState
from opsim.util import from_bytes

FEATURE_JUMP_TABLE = False
cpu = CPU(firmware, CpuState(), verbose=1)

addr_begin = MemoryMap.FLASH.address
addr_until = MemoryMap.FLASH.address_until

memory = firmware.buffer

functions = {}
branches = {}

text_map = firmware.text_map
symbol_map = firmware.symbol_map

THUMB_MASK = 0b11111111_11111111_11111111_11111110

if FEATURE_JUMP_TABLE:
    def get_jump_table_type(func: Function):
        if func.name.startswith("__gnu_thumb1_case_"):
            return func.name[len("__gnu_thumb1_case_"):]

        return None


def no_return_func(func: Function):
    if func.name.startswith("mp_raise_"):
        return True
    elif func.name == "nlr_jump":
        return True
    elif func.name == "nlr_jump_fail":
        return True
    elif func.name == "__fatal_error":
        return True
    elif FEATURE_JUMP_TABLE and get_jump_table_type(func):
        raise Exception("jump table func!!")

    return False


# stop_set: Set[int] = set()
# joint_set: Set[int] = set()
insns: Dict[int, Insn] = {}

if FEATURE_JUMP_TABLE:
    def walk_jumptable(target_func: Function, table_ptr: int, cases: int):
        jtype = get_jump_table_type(target_func)

        is_byte, signed = {
            "uqi": (True, False),
            "sqi": (True, True),
            "uhi": (False, False),
            "shi": (False, True),
        }[jtype]

        if is_byte:
            for i in range(cases):
                ptr = read_ubyte(table_ptr + i)
                if signed:
                    ptr = int.from_bytes(ptr.to_bytes(1, "little", signed=False), "little", signed=True)

                yield ptr << 1
        else:
            for i in range(cases):
                ptr = read_ushort(table_ptr + i * 2)

                if signed:
                    ptr = int.from_bytes(ptr.to_bytes(2, "little", signed=False), "little", signed=True)

                yield ptr << 1


def read_ubyte(pc):
    return memory[pc - addr_begin]


def read_ushort(pc):
    return read_ubyte(pc) | (read_ubyte(pc + 1) << 8)


def read_code(pc):
    return read_ushort(pc)


def walk(func: Function, pc, *, indent=1, visited=None):
    def print_indent():
        print(end=" " * indent * 4)

    if visited is None:
        visited = set()

    lr: int = None

    func.joint_set.add(pc - func.address)
    assert 0 in func.joint_set

    while pc in func:
        if pc in visited:
            return

        code = read_code(pc)
        code2 = read_code(pc + 2)
        insn = parse(pc, code, code2)
        visited.add(pc)

        assert pc not in insns
        insns[pc] = insn

        print_indent()
        print(hex(pc - func.address), insn, sep="\t")

        target = None
        next_pc = None

        if insn.op == Op.B:
            assert isinstance(insn, InsnBranch)
            assert isinstance(insn.dest, Offset)
            target = insn.dest.target
        elif insn.op == Op.BL:
            if isinstance(insn, (InsnBranch2, InsnBranch)):
                print("warning", insn)
                func.stop_set.add(pc - 2 - func.address)
                return
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
        elif insn.op == Op.POP:
            if Reg.pc in insn.regs:
                print(insn.regs)
            else:
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
                    mvalue = from_bytes(cpu.uc.mem_read(maddr, 4))
                    mfunc: Function = text_map[mvalue]

                    if mfunc is not None:
                        if (mvalue & THUMB_MASK) == mfunc.address:
                            mfunc.has_indirect = True  # referenced

            next_pc = pc + 2
        else:
            next_pc = pc + 2

        if target is not None:
            new_func: Function = text_map[target]
            if func == new_func:
                walk(func, target, indent=indent + 1, visited=visited)
            else:
                if no_return_func(new_func):
                    next_pc = None

                if next_pc is not None:
                    print("call", new_func)

            if next_pc is not None:
                func.joint_set.add(next_pc - func.address)

        if next_pc is None:
            func.stop_set.add(pc - func.address)
            return

        pc = next_pc
        continue


def build_header(func: Function):
    print("    // function:", func)
    print(f"    abstract protected void {func.name}(int offset) throws Exception;")
    print(f"    protected int {func.name} = 0x{hex(func.address)[2:].zfill(8)};")
    print(f"    public void {func.name}() throws Exception")
    print("    {")
    print(f"        call(this.{func.name}, this::{func.name});")
    print("    }")
    print()


def is_ignored(func: Function):
    raise NotImplemented


def build_body(func: Function):
    is_clean = func.joint_set == {0}

    if is_ignored(func):
        return

    print("    // function:", func)
    print(f"    protected void {func.name}(int offset) throws Exception")
    print("    {")

    if not is_clean:
        write = lambda line, end=None: print(f"                {line};", end=end)
        print("        switch (offset)")
        print("        {")
    else:
        write = lambda line, end=None: print(f"        {line};", end=end)
        write("assert offset == 0")

    visited = set()
    for offset in sorted(func.joint_set):
        pc = func.address + offset
        while pc in func:
            if pc in visited:
                break
            else:
                visited.add(pc)

            new_func = text_map[pc]
            if func != new_func:
                if not new_func.name.startswith("__aeabi_"):
                    print(func, text_map[pc])
                    assert func == text_map[pc]

            offset = pc - func.address
            if not is_clean and offset in func.joint_set:
                print(f"            case {offset}:")

            code = memory[pc - addr_begin] | (memory[pc - addr_begin + 1] << 8)
            code2 = memory[pc - addr_begin + 2] | (memory[pc - addr_begin + 3] << 8)

            try:
                insn = parse(pc, code, code2)
            except UnsupportedInstructionException:
                write(f"// unsupported instruction: {hex(code)}")
                write(f"crash()")
                continue
            except UnknownInstructionException:
                write(f"// unknown instruction: {hex(code)}")
                write(f"crash()")
                continue

            target: Optional[int] = None
            branch_args = ""
            if isinstance(insn, (InsnBranch, InsnLongBranch, InsnBranchIf, InsnBranchIf2, InsnBranch2)):
                if isinstance(insn.dest, Offset):
                    target = insn.dest.target
                    new_func = text_map[target]
                    branch_args = f"this.{new_func.name}, this::{new_func.name}, {target - new_func.address}"
                    if insn.op == Op.BL or insn.op == Op.BLX:
                        branch_args += f", this.{func.name}, this::{func.name}, {pc - func.address + (2 if insn.op == Op.BLX else 4)}"

            if isinstance(insn, Insn2):
                if insn.op == Op.MOV and isinstance(insn.src, Reg):
                    write(
                        f"{insn.dest!r} = {insn.op}({insn.src!r}, {repr(insn.dest).upper()}, {repr(insn.src).upper()})")
                elif insn.op == Op.CMP or insn.op == Op.TSTS or insn.op == Op.CMN:
                    write(f"{insn.op}({insn.dest!r}, {insn.src!r})")
                elif insn.op == Op.SXTH or insn.op == Op.SXTB or \
                        insn.op == Op.UXTH or insn.op == Op.UXTB or \
                        insn.op == Op.REV:
                    write(f"{insn.dest!r} = {insn.op}({insn.src!r})")
                else:
                    write(f"{insn.dest!r} = {insn.op}({insn.dest!r}, {insn.src!r})")
            elif isinstance(insn, Insn3):
                write(f"{insn.dest} = {insn.op}({insn.src!r}, {insn.offset!r})")
            elif isinstance(insn, InsnMem):
                assert isinstance(insn.dest, Reg)
                assert insn.dest.value <= 7

                if insn.op.name.startswith("LDR"):
                    is_zero_imm = isinstance(insn.offset, Imm) and insn.offset.value == 0

                    if is_zero_imm:
                        maddr = f"{insn.base!r}"
                    else:
                        maddr = f"{insn.base!r} + {insn.offset!r}"

                    if insn.base == Reg.pc:
                        maddr = (pc + insn.offset.value + 4) & 0b11111111_11111111_11111111_11111101
                        mvalue = from_bytes(cpu.uc.mem_read(maddr, 4))
                        hvalue = f"0x{hex(mvalue)[2:].zfill(8)}"
                        mfunc = text_map[mvalue]

                        if mfunc is not None:
                            if (mvalue & THUMB_MASK) == mfunc.address:
                                write(f"{insn.dest} = this.{mfunc.name} | 1")
                            else:
                                assert False, insn
                                # noinspection PyUnreachableCode
                                if mfunc != func:
                                    write(f"{insn.dest} = this.{mfunc.name} + {mvalue - mfunc.address} // (bug)")
                                elif mfunc == func:
                                    write(f"{insn.dest} = {hvalue}; // this.{mfunc.name} + {mvalue - mfunc.address}")
                        else:
                            vfunc = symbol_map[mvalue]
                            if vfunc is not None and mvalue == vfunc.address:
                                write(f"{insn.dest} = this.{vfunc.name}")
                            else:
                                write(f"{insn.dest} = {hvalue}")
                    else:
                        write(f"{insn.dest} = {insn.op}({maddr})")
                elif insn.op.name.startswith("STR"):
                    if isinstance(insn.offset, Imm) and insn.offset.value == 0:
                        write(f"{insn.op}({insn.base!r}, {insn.dest!r})")
                    else:
                        write(f"{insn.op}({insn.base!r} + {insn.offset!r}, {insn.dest!r})")
                else:
                    assert False, insn.op
            elif isinstance(insn, InsnAddr):
                if insn.Rd == Reg.pc:
                    write(f"{insn.Rd!r} = {insn.op}({insn.Rs!r}, {hex(insn.dest_pc(pc))})")
                else:
                    write(f"{insn.Rd!r} = {insn.op}({insn.Rs!r}, {insn.soffset!r})")
            elif isinstance(insn, InsnStack):
                assert insn.op == Op.PUSH or insn.op == Op.POP
                regs_s = ', '.join(map(repr, insn.pure_regs))
                if insn.op == Op.POP:
                    regs_s = regs_s.upper()

                if regs_s:
                    write(f"{insn.op}({'true' if insn.R else 'false'}, {regs_s})")
                else:
                    write(f"{insn.op}({'true' if insn.R else 'false'})")

                if insn.op == Op.POP and insn.special_reg == Reg.pc:
                    write("return")
                    break
            elif isinstance(insn, InsnMemStack):
                regs_s = ', '.join(map(repr, insn.regs)).upper()
                assert regs_s
                if insn.op == Op.LDMIA:
                    regs_s = regs_s.upper()

                write(f"{insn.Rb} = {insn.op}({insn.Rb!r}, {regs_s})")
            elif isinstance(insn, (InsnBranch, InsnLongBranch)):
                if target is not None:
                    write(f"{insn.op}({branch_args})")
                else:
                    write(f"{insn.op}({insn.dest!r})")

                if not is_clean:
                    write("return")
                break
            elif isinstance(insn, InsnBranchIf):
                if target is not None:
                    write(f"if ({insn.op}({branch_args})) return")
                else:
                    write(f"if ({insn.op}({insn.dest!r})) return")
            elif isinstance(insn, InsnBranchIf2):
                if target is not None:
                    write(f"if ({insn.op}({insn.src!r}, {branch_args})) return")
                else:
                    write(f"if ({insn.op}({insn.src!r}, {insn.dest!r})) return")
            elif isinstance(insn, InsnSVC):
                write(f"{insn.op}({insn.soffset!r})")
            else:
                raise Exception(repr(insn))

            if offset in func.stop_set:
                if not is_clean:
                    write("return")
                break

            if insn.op == Op.BL:
                pc = (pc + 5) & THUMB_MASK
            else:
                pc += 2
        else:
            write("// auto leave")
            write("crash()")
            write("return")

    if not is_clean:
        print("            default:")
        write("crash()")
        print("        }")

    print("    }")
    print()


@contextmanager
def captrue_stdout(captrue=True, *, mirror=False):
    fp = io.StringIO()
    stdout = None

    if captrue:
        stdout, sys.stdout = sys.stdout, fp

    try:
        yield fp
    finally:
        if stdout is not None:
            sys.stdout = stdout

        if mirror:
            content = fp.getvalue()
            if content:
                print(content, end="")


for mapping in text_map, symbol_map:
    for func in mapping.values():
        func.name = func.name.replace(".", "_")

    funcs = {}
    counter = Counter()
    for func in mapping.values():
        counter[func.name] += 1
        if func.name not in funcs:
            funcs[func.name] = func
        else:
            cnt = counter[func.name]
            if cnt == 1:
                funcs[func.name].name += "__0"

            func.name += f"__{cnt}"

with captrue_stdout() as stdout:
    for addr, func in sorted(text_map.items()):
        print(func)
        walk(func, addr)
        print()

    Path("fw_aot.txt").write_text(stdout.getvalue())
    # exit()

with captrue_stdout() as stdout:
    for addr, func in sorted(symbol_map.items()):
        print("    // value:", func)
        print(f"    protected int {func.name} = 0x{hex(func.address)[2:].zfill(8)};")
        print()

    Path("fw_aot2.txt").write_text(stdout.getvalue())
    # exit()

# tags = set(list(filter(None, func.name.split("_")))[0] for func in table.values())
# TODO: determine category by file origin
is_ignored = lambda func: not func.name.startswith("mp")

print()
print()
count = 0
for addr, func in sorted(text_map.items()):  # type: int, Function
    assert func is not None
    assert addr_begin <= addr <= addr_until
    buffer = None

    with captrue_stdout(mirror=True):
        # build_header(func)
        build_body(func)

    count += 1
    if count > 100:
        pass
print()
print()
