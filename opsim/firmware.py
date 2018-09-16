from collections import defaultdict
from itertools import chain
from pathlib import Path
from pprint import pprint
from subprocess import check_call, DEVNULL
from typing import Dict, Optional, Set

from dataclasses import dataclass, field

from opsim.exc import UmpsimFirmwareMissingException
from opsim.util import MapLookupTable


@dataclass
class Function:
    address: int
    size: Optional[int]
    name: str
    path: str

    has_indirect: bool = False
    joint_set: Set[int] = field(default_factory=set, repr=False)
    stop_set: Set[int] = field(default_factory=set, repr=False)

    def __contains__(self, item):
        return self.address <= item < self.address + self.size


class Firmware:
    def __init__(self, rom_folder: Path, path: Path, map_path: Path = None):
        self.rom_folder = rom_folder
        self.path = Path(path)
        self.map_path = Path(map_path)
        self.buffer: bytes = None
        self.last_mtime: float = None
        self.text_map: MapLookupTable = None
        self.rodata_map: MapLookupTable = None

    def __getitem__(self, item):
        assert self.buffer != None
        return self.buffer.__getitem__(item)

    def build(self):
        check_call(
            ["wsl", "make", "-j8"],
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

        lines = self.map_path.read_text(encoding="utf-8").splitlines()

        def parse_section(prefix_name, section_name, next_section_name):
            last_function = None
            mapping: Dict[int, Function] = {}
            buffer = None
            prefix = None

            def parse_buffer():
                nonlocal buffer, prefix, last_function
                assert 1 <= len(buffer), buffer
                addr, size, path = buffer[0]
                name = prefix.lstrip(".")

                addr = int(addr, 16)
                size = int(size, 16)
                if last_function and last_function.size is None:
                    last_function.size = addr - last_function.address

                mapping[addr] = last_function = Function(addr, size, name, path)

                for tokens in buffer[1:]:
                    if not tokens:
                        break

                    assert tokens
                    if tokens[0] == "*fill*":
                        continue

                    assert len(tokens) == 2, tokens
                    new_addr, new_name = tokens
                    new_addr = int(new_addr, 16)

                    if new_addr == addr:
                        mapping[addr].name = new_name
                    else:
                        if last_function.size is None:
                            last_function.size = new_addr - last_function.address

                        mapping[new_addr] = last_function = Function(new_addr, None, new_name, path)

            enabled = False
            for line in lines:
                line = line.strip()
                if section_name == line:
                    enabled = True
                    continue
                elif next_section_name == line:
                    parse_buffer()
                    enabled = False
                elif "(size before relaxing)" in line:
                    continue
                elif ". =" in line or "= ." in line:
                    continue
                elif "LOADADDR" in line:
                    continue
                elif "0x0 " in line:
                    continue

                if not enabled:
                    continue

                if line.startswith(prefix_name):
                    if buffer is not None:
                        parse_buffer()

                    tokens = line.split()
                    buffer = []
                    if len(tokens) == 1:
                        assert line.startswith(prefix_name)
                        prefix = line[len(prefix_name):]
                        continue
                    else:
                        prefix, *tokens = tokens
                        buffer.append(tokens)
                else:
                    tokens = line.split()
                    buffer.append(tokens)

            return MapLookupTable(mapping)

        sections = ["text", "rodata", "data", "bss", "COMMON"]

        def Section(x):
            if x == "COMMON":
                section_prefix = "COMMON"
                section = "*(COMMON)"
                next_section = "*(.ARM.attributes)"
            else:
                section_prefix = f".{x}"
                section = f"*(.{x}*)"
                next_section = f"*(.{sections[sections.index(x) + 1]}*)"
                if x == "bss":
                    next_section = "*(COMMON)"

            return section_prefix, section, next_section

        self.text_map = parse_section(*Section("text"))
        self.rodata_map = parse_section(*Section("rodata"))
        self.data_map = parse_section(*Section("data"))
        self.bss_map = parse_section(*Section("bss"))
        self.common_map = parse_section(*Section("COMMON"))
        seqs = chain(self.rodata_map.seq, self.data_map.seq, self.bss_map.seq, self.common_map.seq)
        self.symbol_map = MapLookupTable(dict(seqs))


oprom_path = (Path(__file__).parent / "../oprom")
build_path = oprom_path / "build"

firmware = Firmware(
    oprom_path,
    build_path / "firmware.bin",
    build_path / "firmware.elf.map"
)
