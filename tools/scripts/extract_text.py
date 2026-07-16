#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path


def extract_text_from_coff(data: bytes, path: Path) -> tuple[bytes, int]:
    if len(data) < 20:
        raise ValueError(f"{path}: COFF object is too small")

    machine, section_count, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, 0)
    if machine not in (0x8664, 0x014c):
        raise ValueError(f"{path}: unsupported COFF machine 0x{machine:04x}, expected x64 or x86")
    if opt_size != 0:
        raise ValueError(f"{path}: unexpected optional header in COFF object")

    sec_off = 20
    for i in range(section_count):
        off = sec_off + i * 40
        if off + 40 > len(data):
            raise ValueError(f"{path}: truncated section table")
        name = data[off:off + 8].split(b"\x00", 1)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        reloc_count = struct.unpack_from("<H", data, off + 32)[0]
        if name == b".text" or name.startswith(b".text$"):
            if reloc_count:
                raise ValueError(
                    f"{path}: .text still has {reloc_count} COFF relocations; "
                    "shellcode extraction would be unsafe"
                )
            end = raw_ptr + raw_size
            if raw_ptr == 0 or end > len(data):
                raise ValueError(f"{path}: invalid .text raw range")
            return data[raw_ptr:end], 0

    raise ValueError(f"{path}: .text section not found")


def extract_text_from_pe(data: bytes, path: Path) -> tuple[bytes, int]:
    if data[:2] != b"MZ":
        raise ValueError(f"{path}: missing MZ header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"{path}: invalid PE signature")

    entry_rva = struct.unpack_from("<I", data, e_lfanew + 24 + 16)[0]
    section_count = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size

    for i in range(section_count):
        off = sec_off + i * 40
        if off + 40 > len(data):
            raise ValueError(f"{path}: truncated section table")
        name = data[off:off + 8].split(b"\x00", 1)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        virtual_addr = struct.unpack_from("<I", data, off + 12)[0]
        if name == b".text":
            end = raw_ptr + raw_size
            if raw_ptr == 0 or end > len(data):
                raise ValueError(f"{path}: invalid .text raw range")
            entry_off = entry_rva - virtual_addr
            if entry_off < 0 or entry_off >= raw_size:
                entry_off = 0
            return data[raw_ptr:end], entry_off

    raise ValueError(f"{path}: .text section not found")


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract raw .text bytes from a PE or x64 COFF object")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--entry-file", type=Path, default=None,
                    help="optional file receiving the .text entry offset as hex")
    args = ap.parse_args()

    data = args.input.read_bytes()
    if data[:2] == b"MZ":
        text, entry = extract_text_from_pe(data, args.input)
    else:
        text, entry = extract_text_from_coff(data, args.input)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(text)
    if args.entry_file:
        args.entry_file.write_text(f"0x{entry:x}\n", encoding="ascii")

    print(f"[+] extracted .text: {len(text)} bytes")
    print(f"[+] entry offset:    0x{entry:x}")


if __name__ == "__main__":
    main()
