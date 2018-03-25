from unicorn import Uc


class CpuContext:
    def __init__(self, uc: Uc = None):
        self.uc = uc

    def with_uc(self, uc: Uc):
        self.uc = uc

    @classmethod
    def load(cls, buffer):
        pass

    def save(self):
        pass
