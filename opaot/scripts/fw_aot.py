import io
import re
import sys
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from opaot.errors import UnknownInstructionException, UnsupportedInstructionException
from opaot.parser import parse
from opaot.types import *
from opsim.address import MemoryMap
from opsim.cpu import CPU
from opsim.firmware import firmware
from opsim.state import CpuState
from opsim.types import Function
from opsim.util import from_bytes

firmware.build()

cpu = CPU(firmware, CpuState(), verbose=1)
flash = MemoryMap.FLASH
memory = firmware.buffer

text_map = firmware.text_map
symbol_map = firmware.symbol_map

THUMB_MASK = 0b11111111_11111111_11111111_11111110

MP_FROZEN_MPY_CONSTS = {
    "mp_frozen_str_content",
    "mp_frozen_str_names",
    "mp_frozen_str_sizes",
    "mp_frozen_mpy_content",
    "mp_frozen_mpy_names",
    "mp_qstr_frozen_const_pool",
}


def no_return_func(func: Function):
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


def read_ubyte(pc):
    addr = pc - flash.address
    return memory[addr]


def read_ushort(pc):
    addr = pc - flash.address
    return from_bytes(memory[addr:addr + 2])


def read_int(addr):
    return from_bytes(cpu.uc.mem_read(addr, 4))


def walk(func: Function, pc, *, indent=1, visited=None, do_write):
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

        insn = parse(pc, read_ushort(pc), read_ushort(pc + 2))
        visited.add(pc)

        if do_write:
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
                if do_write:
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
            else:
                func.joint_set.add(next_pc - func.address)  # dup
        elif insn.op == Op.POP:
            if Reg.pc in insn.regs:
                if do_write:
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
                    mvalue = read_int(maddr)
                    mfunc: Function = text_map[mvalue]

                    if mfunc is not None:
                        if (mvalue & THUMB_MASK) == mfunc.address:
                            mfunc.has_indirect = True  # referenced

            next_pc = pc + 2
        elif isinstance(insn, InsnSVC):
            next_pc = pc + 2
            func.joint_set.add(next_pc - func.address)  # dup
        else:
            next_pc = pc + 2

        if target is not None:
            new_func: Function = text_map[target]
            if func == new_func:
                walk(func, target, indent=indent + 1, visited=visited, do_write=do_write)
            else:
                if no_return_func(new_func):
                    next_pc = None

                if next_pc is not None:
                    if do_write:
                        print("call", new_func)

            if next_pc is not None:
                func.joint_set.add(next_pc - func.address)

                if insn.op == Op.BL or insn.op == Op.BLX:
                    func.point_set.add(next_pc - func.address)

        if next_pc is None:
            func.stop_set.add(pc - func.address)
            return

        pc = next_pc
        continue


def conv(name: str):
    return name


def build_link(func: Function):
    print("    // function:", func)
    print(f"    abstract protected void {func.name}(int offset) throws Exception;")
    print(f"    public static final int {conv(func.name)} = 0x{hex(func.address)[2:].zfill(8)};")
    print(f"    public void {func.name}(InterruptHandler handler) throws Exception")
    print("    {")
    print(f"        call(this::{func.name}, handler);")
    print("    }")
    print()


def build_val(func: Function):
    print("    // function:", func)
    print(f"    public static final int {conv(func.name)} = 0x{hex(func.address)[2:].zfill(8)};")
    print()


def build_body(func: Function):
    is_clean = func.joint_set == {0}

    print("    // function:", func)
    print(f"    protected void {func.name}(int offset) throws Exception")
    print("    {")

    write = lambda line, end=None, semi=";": print(f"        {line}{semi}", end=end)
    if not is_clean:
        write = lambda line, end=None, semi=";": print(f"                    {line}{semi}", end=end)
        print("        while (true)")
        print("        {")
        print(f"            pc = {conv(func.name)} + offset;")
        print("            switch (offset)")
        print("            {")
    else:
        write("assert offset == 0")
        write(f"pc = {conv(func.name)} + offset")

    visited = set()
    for pc_offset in sorted(func.joint_set):
        pc = func.address + pc_offset
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

            pc_offset = pc - func.address
            if not is_clean and pc_offset in func.joint_set:
                print(f"                case {pc_offset}:")

            try:
                insn = parse(pc, read_ushort(pc), read_ushort(pc + 2))
            except (UnknownInstructionException, UnsupportedInstructionException):
                raise

            assert insn.op != Op.CBZ and insn.op != Op.CBNZ

            next_pc = (pc + 5) & THUMB_MASK if (insn.op == Op.BL) else pc + 2

            target: Optional[int] = None
            branch_args = ""
            branch_link_arg = ""
            branch_offset = None
            cb_offset = None

            if insn.op == Op.BL or insn.op == Op.BLX or isinstance(insn, InsnSVC):
                cb_offset = pc_offset + (2 if insn.op != Op.BL else 4)
                branch_link_arg = f"{conv(func.name)} + {cb_offset} | 1, {cb_offset}"
                func.point_set.add(cb_offset)

            if isinstance(insn, (InsnBranch, InsnLongBranch, InsnBranchIf, InsnBranchIf2, InsnBranch2)):
                if isinstance(insn.dest, Offset):
                    target = insn.dest.target
                    new_func = text_map[target]
                    new_func_name = f"this::{new_func.name}" if new_func != func else "null"
                    if func == new_func:
                        branch_offset = target - new_func.address

                    if isinstance(insn, InsnBranchIf):
                        branch_args = f"{target - new_func.address}"
                    elif func == new_func or (target - new_func.address) != 0:
                        branch_args = f"{new_func_name}, {target - new_func.address}"
                    else:
                        branch_args = f"{new_func_name}"

                    if insn.op == Op.BL or insn.op == Op.BLX:
                        branch_args += ", " + branch_link_arg

            if isinstance(insn, Insn2):
                if insn.op == Op.MOV and isinstance(insn.src, Reg):
                    write(f"{insn.dest!r} = {insn.op}({insn.src!r})")
                    if insn.dest == Reg.pc:
                        if not is_clean:
                            write("autob(pc); // auto")
                            write("return")
                        break
                elif insn.op == Op.CMP or insn.op == Op.TSTS or insn.op == Op.CMN:
                    write(f"{insn.op}({insn.dest!r}, {insn.src!r})")
                elif insn.op == Op.SXTH or insn.op == Op.SXTB or \
                        insn.op == Op.UXTH or insn.op == Op.UXTB or \
                        insn.op == Op.REV or \
                        insn.op == Op.RSBS:
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
                        moffset10 = insn.offset.value + 4  # make ~10
                        assert moffset10 > 0
                        maddr = (pc + insn.offset.value + 4) & 0b11111111_11111111_11111111_11111101
                        mvalue = read_int(maddr)
                        hvalue = f"0x{hex(mvalue)[2:].zfill(8)}"
                        mfunc = text_map[mvalue]

                        if mfunc is not None:
                            if (mvalue & THUMB_MASK) == mfunc.address:
                                write(f"{insn.dest} = mov({conv(mfunc.name)} | 1)")
                                # write(f"hint({conv(mfunc.name)} | 1, this::{mfunc.name})")
                            else:
                                raise Exception("invalid memory read (?)")
                        else:
                            assert insn.op == Op.LDR
                            vfunc = symbol_map[mvalue]
                            if vfunc is not None and mvalue == vfunc.address:
                                write(
                                    f"{insn.dest} = {insn.op}({func.name} + {maddr - func.address}); // {conv(vfunc.name)}")
                            else:
                                write(f"{insn.dest} = {insn.op}({func.name} + {maddr - func.address})")
                                # write(f"{insn.dest} = mov({hvalue})")
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
                if insn.Rs == Reg.pc:
                    write(
                        f"{insn.Rd!r} = {insn.op}({insn.Rs!r}, {insn.dest_pc(pc) - pc!r}); // pc + {insn.soffset.value}")
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
                    if not is_clean:
                        write("return")
                    break
            elif isinstance(insn, InsnMemStack):
                regs_s = ', '.join(map(repr, insn.regs))
                assert regs_s
                if insn.op == Op.LDMIA:
                    regs_s = regs_s.upper()

                write(f"{insn.Rb} = {insn.op}({insn.Rb!r}, {regs_s})")
            elif isinstance(insn, (InsnBranch, InsnLongBranch)):
                if insn.op == Op.B and branch_offset is not None:
                    write("step()")
                    write(f"offset = {branch_offset}")
                    write(f"continue")
                else:
                    if target is not None:
                        write(f"{insn.op}({branch_args})")
                    else:
                        if insn.op == Op.BLX:
                            write(f"{insn.op}({insn.dest!r}, {branch_link_arg})")
                        elif insn.op == Op.BL:
                            # TODO: joint_set is full
                            write("crash(); // error")
                        else:
                            write(f"{insn.op}({insn.dest!r})")

                    if not is_clean:
                        write("return")
                break
            elif isinstance(insn, InsnBranchIf):
                if branch_offset is not None:
                    write(f"if ({insn.op}()) {{", semi="")
                    write(f"    offset = {branch_offset}")
                    write(f"    continue")
                    write(f"}}", semi="")
                elif target is not None:
                    write(f"if ({insn.op}({branch_args})) return")
                else:
                    write(f"if ({insn.op}({insn.dest!r})) return")
            elif isinstance(insn, InsnBranchIf2):
                if target is not None:
                    write(f"if ({insn.op}({insn.src!r}, {branch_args})) return")
                else:
                    write(f"if ({insn.op}({insn.src!r}, {insn.dest!r})) return")
            elif isinstance(insn, InsnSVC):
                write(f"{insn.op}({insn.soffset!r}, {cb_offset})")
            else:
                raise Exception(repr(insn))

            if pc_offset in func.stop_set:
                if not is_clean:
                    write("return")
                break

            pc = next_pc
        else:
            write("crash(); // auto leave")

    if not is_clean:
        print("                default:")
        write("crash()")
        print("            }")
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


def main():
    for mapping in text_map,:  # symbol_map
        for func in mapping.values():
            func.name = func.name.replace(".", "_")

        funcs = {}
        counter = Counter()
        for func in mapping.values():
            counter[func.name] += 1
            if func.name not in funcs:
                funcs[func.name] = func
            else:
                assert False
                cnt = counter[func.name]
                if cnt == 1:
                    funcs[func.name].name += "__0"

                func.name += f"__{cnt}"

    do_write = False
    with captrue_stdout() as stdout:
        for addr, func in sorted(text_map.items()):
            if do_write:
                print(func)
            walk(func, addr, do_write=do_write)
            if do_write:
                print()

        if do_write:
            Path("fw_aot.txt").write_text(stdout.getvalue())
        # exit()

    for addr in range(flash.address, flash.address_until, 4):
        if read_int(addr) in flash:
            func = text_map[addr]
            if func is None:
                continue

            if func.name in ("__aeabi_fmul",):
                for offset in range(0, max(func.joint_set), 2):
                    func.joint_set.add(offset)

                # print(func, addr, addr - func.address)
                # func.joint_set.add(addr - func.address)

    for addr, func in text_map.items():
        assert addr in flash

    CLASS_TEMPLATE = """
%header%

%access% class %name% %extends%%parent%
{
    %init%

%content%

} // %name%
""".lstrip()

    def build_class(**kwargs):
        return re.sub("%(.*?)%", lambda m: kwargs[m[1]], CLASS_TEMPLATE)

    default_prefix = "build/"

    categories = {
        "build/py": "py",
        "build/extmod": "extmod",
        "build/lib": "lib",
        "/": "system",
    }

    functions = {
        "main": {},
        "py": {},
        "upy": {},
        "extmod": {},
        "lib": {},
        "system": {},
    }

    parents = {
        "main": "py",
        "py": "upy",
        "upy": "extmod",
        "extmod": "lib",
        "lib": "system",
        "system": "link",
    }

    rtext_dict = {func.name: func for func in text_map.values()}

    found = False
    for addr, func in symbol_map.items():
        if func.name.startswith("entry_table."):
            assert not found
            found = True
            print(func)
            mp_execute_bytecode = rtext_dict["mp_execute_bytecode"]  # type: Function
            for i in range(256):
                case_addr = read_int(func.address + i * 4)
                assert mp_execute_bytecode.address <= case_addr <= mp_execute_bytecode.address + mp_execute_bytecode.size, (
                    case_addr, mp_execute_bytecode)
                mp_execute_bytecode.point_set.add(case_addr - mp_execute_bytecode.address)
                walk(mp_execute_bytecode, case_addr, do_write=False)

    for addr, func in sorted(text_map.items()):  # type: int, Function
        for prefix, name in categories.items():
            if func.path.startswith(prefix):
                category = name
                break
        else:
            assert func.path.startswith(default_prefix), func.path
            category = "main"

        if category == "py":
            if not func.name.startswith("mp"):
                category = "upy"

        functions[category][addr] = func

    def build_cls(name, parent, bfp):
        package = "kr.pe.ecmaxp.micropython.example"
        clsname = f"MicroPython_{name}" if name else "MicroPython"
        header = ""
        if parent:
            if name:
                header = """
package %package%;

import kotlin.Pair;
import kr.pe.ecmaxp.thumbjk.Callback;
import kr.pe.ecmaxp.thumbjk.KotlinCPU;
import kr.pe.ecmaxp.thumbjk.InterruptHandler;
import kr.pe.ecmaxp.thumbsk.Memory;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;

import static kr.pe.ecmaxp.thumbsk.helper.RegisterIndex.*;
""".strip()
            else:
                header = """
package %package%;

import kr.pe.ecmaxp.thumbsk.Memory;
import org.jetbrains.annotations.NotNull;
""".strip()
        else:
            header = """
package %package%;
""".strip()

        return build_class(
            package=package,
            name=clsname,
            parent=f"MicroPython_{parent}" if parent != "KotlinCPU" and parent else parent,
            content=bfp.getvalue().rstrip(),
            access="abstract public" if name and parent else "public",
            extends="extends " if parent else "",
            header=header.replace("%package%", package),
            init=("""
    public %name%(@NotNull Memory memory)
    {
        super(memory);
    }
            """.strip() if parent else """
    private %name%()
    {
    }       
    """).strip().replace("%name%", clsname)
        )

    folder = Path(r"C:\Users\EcmaXp\Dropbox\Projects\OpenPie\opmod\src\main\java\kr\pe\ecmaxp\micropython\example")

    def write_cls(name, parent: Optional[str], bfp):
        fname = f"MicroPython_{name}.java" if name else f"MicroPython.java"
        clsbuf = build_cls(name, parent, bfp)
        path = folder / fname
        if path.exists():
            if path.read_text() == clsbuf:
                return

        print("update", path.name)
        path.write_text(clsbuf)

    # noinspection PyUnreachableCode
    if False:
        with captrue_stdout() as bfp:
            for mapping in firmware.common_map,:
                for addr, func in sorted(mapping.items()):
                    build_val(func)

        write_cls("vals", None, bfp)

    # noinspection PyUnreachableCode
    if False:
        path_mpy_files = "build/build/frozen.o", "build/build/frozen_mpy.o"

        with captrue_stdout() as bfp:
            for mapping in firmware.rodata_map,:
                for addr, func in sorted(mapping.items()):
                    if func.path in path_mpy_files and func.name in MP_FROZEN_MPY_CONSTS:
                        build_val(func)

        write_cls("frozen", None, bfp)

    for category, funcs in functions.items():
        parent = parents[category]

        with captrue_stdout() as bfp:
            for addr, func in sorted(funcs.items()):  # type: int, Function
                build_body(func)

        write_cls(category, parent, bfp)

    with captrue_stdout() as bfp:
        hints = []
        for addr, func in sorted(text_map.items()):
            if func.name.startswith("__aeabi"):
                func.point_set = func.joint_set

            hints.append((func.name, 0))
            if func.point_set:
                for offset in sorted(func.point_set):
                    if offset != 0:
                        hints.append((func.name, offset))

        count = 0
        while hints:
            count += 1
            print(f"    private void gen_hints_{count}() {{")

            for i in range(500):
                if not hints:
                    break

                name, offset = hints.pop(0)
                print(f"        hint({name}, this::{name}, {offset});")
            else:
                print("    }")
                print()
                continue

            print("    }")
            print()
            break

        print("    " + ("""
    @Override
    protected void gen_hints() {
        """).strip())

        for i in range(1, count + 1):
            print(f"        gen_hints_{i}();")

        print("    }")
        print()

        for addr, func in sorted(text_map.items()):  # type: int, Function
            # build_val(func) gen by build_link(func)
            build_link(func)

    write_cls("link", "KotlinCPU", bfp)


if __name__ == '__main__':
    main()
