import time

from .address import MemoryMap


class CpuState:
    def __init__(self):
        self.stack_size = 1024 * 4
        self.ram_size = MemoryMap.RAM.size - self.stack_size
        self.stack = []
        self.epoch = time.time()
        self.cycle = 100000

    def verify(self):
        assert self.ram_size + self.stack_size <= MemoryMap.RAM.size, (self.ram_size, self.stack_size, MemoryMap.RAM.size)

    @classmethod
    def load(cls, buffer):
        pass

    def save(self):
        pass