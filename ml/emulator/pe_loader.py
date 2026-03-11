"""
PE Loader — Load League of Legends.exe sections into Unicorn emulator memory.

This maps the game binary's .text, .rdata, .data sections so we can call
the game's own packet decoding functions.

Usage:
    from ml.emulator.pe_loader import PELoader
    loader = PELoader("C:/Riot Games/League of Legends/Game/League of Legends.exe")
    loader.load_into(emu)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn import Uc

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class SectionInfo:
    name: str
    virtual_address: int  # RVA
    virtual_size: int
    raw_size: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE


@dataclass
class PEInfo:
    """Parsed PE metadata."""
    image_base: int
    entry_point: int  # RVA
    sections: list[SectionInfo]
    file_size: int
    # Import Address Table entries we might need to hook
    imports: dict[str, dict[str, int]]  # dll -> {func_name: iat_rva}


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


class PELoader:
    """Load a PE (League of Legends.exe) into Unicorn emulator memory."""

    PAGE_SIZE = 0x1000

    def __init__(self, exe_path: str | Path):
        if not HAS_PEFILE:
            raise ImportError("pip install pefile")

        self.path = Path(exe_path)
        if not self.path.exists():
            raise FileNotFoundError(f"Game binary not found: {self.path}")

        self.pe = pefile.PE(str(self.path), fast_load=True)
        self.pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )

        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage

        self._sections: list[SectionInfo] = []
        for sec in self.pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            self._sections.append(SectionInfo(
                name=name,
                virtual_address=sec.VirtualAddress,
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                characteristics=sec.Characteristics,
            ))

    @property
    def info(self) -> PEInfo:
        imports: dict[str, dict[str, int]] = {}
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", errors="replace")
                funcs = {}
                for imp in entry.imports:
                    if imp.name:
                        funcs[imp.name.decode("ascii", errors="replace")] = imp.address - self.image_base
                imports[dll] = funcs

        return PEInfo(
            image_base=self.image_base,
            entry_point=self.entry_point_rva,
            sections=self._sections,
            file_size=self.path.stat().st_size,
            imports=imports,
        )

    def load_into(self, emu: "Uc"):
        """
        Map all PE sections into emulator memory.

        Maps the full SizeOfImage as one block, then writes each section's
        raw data at image_base + section.VirtualAddress.
        """
        from unicorn import UC_PROT_ALL

        # Map the entire image space
        aligned_size = _align(self.size_of_image, self.PAGE_SIZE)
        emu.mem_map(self.image_base, aligned_size, UC_PROT_ALL)

        # Write PE headers (first page)
        header_data = self.pe.header[:self.PAGE_SIZE]
        emu.mem_write(self.image_base, header_data)

        # Write each section
        for sec in self.pe.sections:
            if sec.SizeOfRawData == 0:
                continue
            addr = self.image_base + sec.VirtualAddress
            data = sec.get_data()
            emu.mem_write(addr, data)

        print(f"[PE] Loaded {self.path.name}: "
              f"base=0x{self.image_base:X}, "
              f"size=0x{self.size_of_image:X}, "
              f"{len(self._sections)} sections")

    def find_section(self, name: str) -> SectionInfo | None:
        """Find a section by name (e.g. '.text', '.rdata')."""
        for s in self._sections:
            if s.name == name:
                return s
        return None

    def print_info(self):
        """Print PE info for debugging."""
        info = self.info
        print(f"\n{'='*60}")
        print(f"  PE: {self.path.name}")
        print(f"  Image base:  0x{info.image_base:016X}")
        print(f"  Entry point: 0x{info.image_base + info.entry_point:016X}")
        print(f"  Size:        0x{self.size_of_image:X} ({self.size_of_image / 1024 / 1024:.1f} MB)")
        print(f"  File:        {info.file_size / 1024 / 1024:.1f} MB")

        print(f"\n  Sections:")
        print(f"  {'Name':<10s} {'VAddr':>12s} {'VSize':>10s} {'RawSize':>10s} {'Flags'}")
        for s in info.sections:
            flags = []
            if s.is_executable:
                flags.append("X")
            if s.is_writable:
                flags.append("W")
            print(f"  {s.name:<10s} 0x{s.virtual_address:08X} "
                  f"{s.virtual_size:>10,} {s.raw_size:>10,}  {''.join(flags)}")

        if info.imports:
            print(f"\n  Imports ({len(info.imports)} DLLs):")
            for dll, funcs in sorted(info.imports.items()):
                print(f"    {dll}: {len(funcs)} functions")
                for name, rva in sorted(funcs.items())[:5]:
                    print(f"      {name} @ 0x{rva:08X}")
                if len(funcs) > 5:
                    print(f"      ... ({len(funcs) - 5} more)")
        print(f"{'='*60}")


# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m ml.emulator.pe_loader <path_to_League_of_Legends.exe>")
        sys.exit(1)

    loader = PELoader(sys.argv[1])
    loader.print_info()
