from pathlib import Path


class Firmware:
    def __init__(self, path: Path):
        self.path = path
        self.buffer: bytes = None
        self.last_mtime: float = None
        self.refresh()

    def __getitem__(self, item):
        assert self.buffer != None
        return self.buffer.__getitem__(item)

    def refresh(self):
        if not self.path.exists():
            raise Exception

        mtime = self.path.stat().st_mtime_ns
        if self.last_mtime != mtime:
            self.buffer = self.path.read_bytes()
            self.last_mtime = mtime

    def load_bytes(self, *, refresh=True):
        if refresh:
            self.refresh()

        return self.buffer


default_firmware_path = (Path(__file__).parent / "../umport/build/firmware.bin").absolute()
default_firmware = Firmware(default_firmware_path)
