from keystone import *
from unicorn import *

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

addr = 0x10000
size = 0x1000
code = "movs r4, #0xf0"

encoding, count = ks.asm(code, addr)
buf = bytes(encoding)
print("%s = [ " % code, end='')
for i in buf:
    print("%02x " % i, end='')
print("]")

uc.mem_map(0x0, size)
uc.mem_map(addr, size)
uc.mem_write(addr, buf)

uc.emu_start(addr, addr + size, 0, count)
