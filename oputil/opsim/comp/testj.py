import faulthandler
import time
from itertools import zip_longest
from pathlib import Path

from unicorn.arm_const import *

from oputil.opsim.cpu import CPU
from oputil.opsim import firmware
from oputil.opsim import ThumbSJ, ready_sim_java, trace_code_java
from oputil.opsim.state import CpuState
from oputil.opsim.valid import check_failures, print_failures


def run_test(cpu, state, code, fast_cycle):
    sim = ThumbSJ()

    ready_sim_java(cpu, sim)

    count = 0
    def push(line):
        buf = (line + "\r\n").encode()
        cpu.state.input_buffer += buf
        for ch in buf:
            sim.PushCode(ch)

    # please check ThumbAlt/Main.java
    push('code = """')
    push(code)
    push('"""[1:-1]')
    push('print("===START===")')
    push("exec(code)")
    push('print("===END===")')
    push("import usystem")
    push("_ = usystem.syscall('')")

    FLAG = False
    if FLAG:
        while True:
            sim.Run(10000000)

    hook_installed = False
    cpu.state.cycle = cycle = 75700  # 3437200
    cpu.state.write_to_stdout = False
    buffer = bytearray()
    buffer2 = bytearray()
    has_mismatch = False
    last_sim_regs = sim.Regs.Load()
    epoch = time.time()

    while True:
        prev_pc = cpu.uc.reg_read(UC_ARM_REG_PC)
        cpu.step()

        has_exception = sim.RunSafe(cycle)

        if time.time() > epoch + 60 and fast_cycle != 1:
            print("timeout")
            break

        while state.output_storage:
            ch = state.output_storage.pop(0)
            ch2 = sim.GetOutputChar()
            buffer.append(ch)
            if ch2 != -1:
                buffer2.append(ch2)
            if ch != ch2:
                has_mismatch = True

        while True:
            ch2 = sim.GetOutputChar()
            if ch2 != -1:
                buffer2.append(ch2)
            else:
                break

        if not has_exception:
            # exception raised
            if sim.IsDone():
                # Interrupted for progs done
                return True, has_mismatch, buffer, buffer2

            break

        count += cycle
        if not hook_installed:
            # sim.Memory.GlobalHook = PyHookMemory(global_hook_memory)
            cpu.state.cycle = cycle = fast_cycle
            hook_installed = True

        if True:
            failure, target_regs, sim_regs = check_failures(cpu, sim)
            if failure:
                bcode, inst = print_failures(cpu, sim, prev_pc, target_regs, sim_regs, count, last_sim_regs=last_sim_regs)
                trace_code_java(bcode, inst)
                break
            last_sim_regs = sim_regs

    return False, has_mismatch, buffer, buffer2

def main():
    faulthandler.enable()

    tests_path = Path("../../micropython/tests")
    tests_path = tests_path.resolve()

    test_dirs = {
        'basics',
        'micropython',
        'float',
        'import',
        'io',
        'misc',
        'stress',
        'unicode',
        'unix'
    }

    test_dirs = {"basics"}

    tests = []
    for test_dir in tests_path.iterdir():
        if test_dir.is_dir() and test_dir.name in test_dirs:
            for test in test_dir.rglob("*.py"):
                tests.append((test, test.relative_to(tests_path)))

    def parse_buffer(buffer):
        lines = buffer.decode('utf-8', 'replace').splitlines()
        START = "===START==="
        END = "===END==="

        if START in lines:
            lines = lines[lines.index(START) + 2:]

        if END in lines:
            lines = lines[:lines.index(END) - 1]

        return lines

    detail_running = {
        r"basics\memoryview2.py": 1310807,
        r"basics\op_error.py": 3922181,
        r"basics\builtin_pow3_intbig.py": None,
        r"basics\string_cr_conversion.py": None,
        r"basics\string_crlf_conversion.py": None,
        r"basics\builtin_help.py": None,  # no problem
    }

    state = CpuState()
    cpu = CPU(firmware, state)


    EMPTY = object()
    for test, rel_test in tests:
        print(rel_test)
        fast_cycle = detail_running.get(str(rel_test), EMPTY)
        if fast_cycle is None:
            print("pass")
            print()
            continue
        elif str(rel_test).startswith(r"micropython\viper_"):
            continue
        elif True and fast_cycle is EMPTY:
            continue

        if fast_cycle is None:
            fast_cycle = 100000000
            continue

        cpu.state = state = CpuState()
        cpu.reset()

        test_exp = test.with_suffix(test.suffix + ".exp")
        source = test.read_text("utf-8", "replace").replace("\n", "\r\n")
        result, has_mismatch, buffer, buffer2 = run_test(cpu, state, source, fast_cycle)

        if has_mismatch:
            print("fail (stdout mismatch)")
            for lineno, (line, line2) in enumerate(zip_longest(parse_buffer(buffer), parse_buffer(buffer2))):
                if line != line2:
                    print("line no:", lineno)
                    print("uc:", repr(line))
                    print("tc:", repr(line2))
                    print()
            print()
        elif test_exp.exists():
            excepted = (test_exp.read_text("utf-8", "replace")).splitlines()
            has_output = False
            content = parse_buffer(buffer)
            if content and content[0] == "SKIP":
                continue

            for lineno, (line, line2) in enumerate(zip_longest(content, excepted)):
                if line != line2:
                    has_output = False
                    print(lineno, repr(line), repr(line2))

            if has_output:
                print()
        elif not result:
            print()
            print()
            time.sleep(0.5)

if __name__ == '__main__':
    main()
