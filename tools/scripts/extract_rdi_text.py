#!/usr/bin/env python3
import argparse
from pathlib import Path

from extract_text import extract_text_from_coff, extract_text_from_pe


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract raw RDI .text shellcode from a PE or COFF object")
    ap.add_argument("input", type=Path)
    ap.add_argument("-o", "--output", required=True, type=Path)
    ap.add_argument("--entry-file", type=Path, default=None)
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

    print(f"[+] extracted RDI .text: {len(text)} bytes")
    print(f"[+] entry offset:         0x{entry:x}")


if __name__ == "__main__":
    main()
