from pathlib import Path

from umpsim.exc import UmpsimFirmwareMissingException
from umpsim.util import MapLookupTable


class Firmware:
    def __init__(self, path: Path, map_path: Path=None):
        self.path = Path(path)
        self.map_path = Path(map_path)
        self.buffer: bytes = None
        self.last_mtime: float = None
        self.mapping = None
        self.refresh()

    def __getitem__(self, item):
        assert self.buffer != None
        return self.buffer.__getitem__(item)

    def refresh(self):
        if not self.path.exists():
            raise UmpsimFirmwareMissingException()

        mtime = self.path.stat().st_mtime_ns
        if self.last_mtime != mtime:
            self.buffer = self.path.read_bytes()
            self.last_mtime = mtime
            self.refresh_map()

    def load_bytes(self, *, refresh=True):
        if refresh:
            self.refresh()

        return self.buffer

    def refresh_map(self):
        if self.map_path is None:
            return

        mapping = []
        with self.map_path.open(encoding="utf-8") as fp:
            for line in fp:
                tokens = line.split()
                # very simple but works!
                if len(tokens) == 2:
                    addr, name = tokens
                    if not addr.startswith("0x"):
                        continue

                    addr = int(addr, 16)
                    mapping.append((addr, name))
                    continue

        self.mapping = MapLookupTable(mapping)
