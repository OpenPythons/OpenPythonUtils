from collections import Counter
from pathlib import Path

FUNC_START = "; =============== S U B	R O U T	I N E ======================================="
FUNC_END = "; End of function "

in_func = False

counter = Counter()
for line in Path(r"C:\Users\EcmaXp\Desktop\firmware.asm").read_text("utf-8", "replace").splitlines():
    if line.startswith(FUNC_START):
        in_func = True
        continue
    elif line.startswith(FUNC_END):
        in_func = False
        continue

    if in_func:
        if line.startswith('\t\t') and ";" not in line:
            a, b, c = line[2:].partition("\t")
            if b and len(a.split()) == 1:
                counter[a] += 1


for key, value in counter.most_common():
    print(key, value, sep="\t")


ops = set()
for line in Path(r"C:\Users\EcmaXp\Desktop\firmware.asm").read_text("utf-8", "replace").splitlines():
    if line.startswith(FUNC_START):
        in_func = True
        continue
    elif line.startswith(FUNC_END):
        in_func = False
        if ops:
            print(line[len(FUNC_END):], ops)
            ops.clear()
        continue

    if in_func:
        if line.startswith('\t\t') and ";" not in line:
            a, b, c = line[2:].partition("\t")
            if b and len(a.split()) == 1:
                if counter[a] < 16:
                    ops.add(a)
