from pprint import pprint

from itertools import chain
from pathlib import Path
from typing import Dict

from oprom.build import build
from oputil.opsim.exc import UmpsimFirmwareMissingException
from oputil.opsim.types import RawFunction
from oputil.opsim.util import MapLookupTable


class Firmware:
    def __init__(self, rom_folder: Path, path: Path, *, map_path: Path = None, elf_path: Path = None):
        self.rom_folder = rom_folder
        self.path = Path(path)
        self.map_path = Path(map_path)
        self.elf_path = Path(elf_path)
        self.buffer: bytes = None
        self.last_mtime: float = None
        self.text_map: MapLookupTable = None
        self.rodata_map: MapLookupTable = None
        self.data_map: MapLookupTable = None
        self.bss_map: MapLookupTable = None
        self.common_map: MapLookupTable = None
        self.symbol_map: MapLookupTable = None

    def __getitem__(self, item):
        assert self.buffer is not None
        return self.buffer.__getitem__(item)

    def build(self):
        build(self.rom_folder)

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
        assert self.map_path
        assert self.elf_path

        from oprom.build import process_elf, SimpleSymbol
        from elftools.elf.elffile import ELFFile

        from fpvgcc.fpv import process_map_file
        from fpvgcc.gccMemoryMap import GCCMemoryMapNode
        import logging
        # noinspection PyUnresolvedReferences
        logging.disable(logging.WARNING)

        symbols = {}
        with self.elf_path.open('rb') as fp:
            elf = ELFFile(fp)
            for symbol in process_elf(elf):
                symbols[symbol.name] = symbol

        ignore_regions = {"DISCARDED", "UNDEF"}
        sm = process_map_file(self.map_path)

        text_mapping = {}
        rodata_mapping = {}
        data_mapping = {}
        bss_mapping = {}

        def visit_region(region: GCCMemoryMapNode, mapping: Dict[int, RawFunction]):
            for node in region.children:  # .children vs .all_nodes()
                node: GCCMemoryMapNode
                if node.name == "rodata":
                    visit_region(node, rodata_mapping)
                    continue
                elif node.region in ignore_regions:
                    continue
                elif mapping is None:
                    continue

                address = node._address
                mapping[address] = RawFunction(address, node.size, node.name, f"{node.arfolder}{node.objfile}")

        for region in sm.memory_map.root.children:  # type: GCCMemoryMapNode
            if region.region in ignore_regions:
                continue

            mapping = {
                "text": text_mapping,
                "data": data_mapping,
                "bss": bss_mapping,
            }.get(region.name)

            visit_region(region, mapping)

        self.text_map = MapLookupTable(text_mapping)
        self.rodata_map = MapLookupTable(rodata_mapping)
        self.data_map = MapLookupTable(data_mapping)
        self.bss_map = MapLookupTable(bss_mapping)
        seqs = chain(self.rodata_map.seq, self.data_map.seq, self.bss_map.seq)
        self.symbol_map = MapLookupTable(dict(seqs))


oprom_path = (Path(__file__).parent / "../../oprom")
build_path = oprom_path / "build"

firmware = Firmware(
    oprom_path,
    build_path / "firmware.bin",
    elf_path=build_path / "firmware.elf",
    map_path=build_path / "firmware.elf.map"
)
