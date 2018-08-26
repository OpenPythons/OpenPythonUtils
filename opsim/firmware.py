from pathlib import Path
from subprocess import check_call, DEVNULL

from opsim.exc import UmpsimFirmwareMissingException
from opsim.util import MapLookupTable


class Firmware:
    def __init__(self, rom_folder: Path, path: Path, map_path: Path = None):
        self.rom_folder = rom_folder
        self.path = Path(path)
        self.map_path = Path(map_path)
        self.buffer: bytes = None
        self.last_mtime: float = None
        self.mapping = None

    def __getitem__(self, item):
        assert self.buffer != None
        return self.buffer.__getitem__(item)

    def build(self):
        check_call(
            ["wsl", "make"],
            cwd=str(self.rom_folder),
            shell=True,
            stdin=DEVNULL
        )

    def refresh(self):
        if not self.path.exists():
            raise UmpsimFirmwareMissingException()

        mtime = self.path.stat().st_mtime_ns
        if self.last_mtime != mtime:
            self.buffer = self.path.read_bytes()
            self.last_mtime = mtime
            self.refresh_map()

    def load_bytes(self):
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


oprom_path = (Path(__file__).parent / "../oprom")
build_path = oprom_path / "build"

firmware = Firmware(
    oprom_path,
    build_path / "firmware.bin",
    build_path / "firmware.elf.map"
)
