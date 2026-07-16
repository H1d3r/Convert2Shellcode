#!/usr/bin/env python3
import subprocess
import sys
import shutil
import struct
import tempfile
import os
from dataclasses import dataclass
from pathlib import Path


EXAMPLE = Path(__file__).resolve().parent
ROOT = EXAMPLE.parent
BIN = ROOT / "bin"
FIXTURES = EXAMPLE / "fixtures"
OUT = EXAMPLE / "out"
LOGS = OUT / "logs"
BUILD_TMP: Path | None = None
VCVARSALL: Path | None = None


RUST_TARGETS = {
    "x64": "x86_64-pc-windows-msvc",
    "x86": "i686-pc-windows-msvc",
}


@dataclass
class Fixture:
    name: str
    source: str
    output: str
    dll: bool
    arch: str = "x64"
    tls: bool = False
    lang: str = "c"


@dataclass
class Case:
    name: str
    fixture: str
    rdi_type: str
    arch: str
    expect: tuple[str, ...]
    ordered: bool = False
    export_name: str | None = None
    export_hash: int | None = None
    user_hex: str | None = None
    user_file: str | None = None


FIXTURE_LIST = [
    Fixture("x64_exe_basic", "c/exe_basic.c", "exe_basic.exe", dll=False),
    Fixture("x64_exe_tls", "c/exe_tls.c", "exe_tls.exe", dll=False, tls=True),
    Fixture("x64_exe_tls_data", "c/exe_tls_data.c", "exe_tls_data.exe", dll=False, tls=True),
    Fixture("x64_exe_full", "c/exe_full.c", "exe_full.exe", dll=False, tls=True),
    Fixture("x64_exe_data_reloc", "c/exe_data_reloc.c", "exe_data_reloc.exe", dll=False),
    Fixture("x64_exe_header_scrub", "c/exe_header_scrub.c", "exe_header_scrub.exe", dll=False),
    Fixture("x64_exe_tls_thread", "c/exe_tls_thread.c", "exe_tls_thread.exe", dll=False, tls=True),
    Fixture("x64_exe_unwind_table", "c/exe_unwind_table.c", "exe_unwind_table.exe", dll=False),
    Fixture("x64_dll_basic", "c/dll_basic.c", "dll_basic.dll", dll=True),
    Fixture("x64_dll_tls", "c/dll_tls.c", "dll_tls.dll", dll=True, tls=True),
    Fixture("x64_dll_tls_data", "c/dll_tls_data.c", "dll_tls_data.dll", dll=True, tls=True),
    Fixture("x64_dll_entry_context", "c/dll_entry_context.c", "dll_entry_context.dll", dll=True),
    Fixture("x64_dll_export", "c/dll_export.c", "dll_export.dll", dll=True),
    Fixture("x86_exe_basic", "c/exe_basic.c", "exe_basic_x86.exe", dll=False, arch="x86"),
    Fixture("x86_exe_tls", "c/exe_tls.c", "exe_tls_x86.exe", dll=False, arch="x86", tls=True),
    Fixture("x86_exe_tls_data", "c/exe_tls_data.c", "exe_tls_data_x86.exe", dll=False, arch="x86", tls=True),
    Fixture("x86_exe_full", "c/exe_full.c", "exe_full_x86.exe", dll=False, arch="x86", tls=True),
    Fixture("x86_exe_data_reloc", "c/exe_data_reloc.c", "exe_data_reloc_x86.exe", dll=False, arch="x86"),
    Fixture("x86_exe_header_scrub", "c/exe_header_scrub.c", "exe_header_scrub_x86.exe", dll=False, arch="x86"),
    Fixture("x86_exe_tls_thread", "c/exe_tls_thread.c", "exe_tls_thread_x86.exe", dll=False, arch="x86", tls=True),
    Fixture("x86_dll_basic", "c/dll_basic.c", "dll_basic_x86.dll", dll=True, arch="x86"),
    Fixture("x86_dll_tls", "c/dll_tls.c", "dll_tls_x86.dll", dll=True, arch="x86", tls=True),
    Fixture("x86_dll_tls_data", "c/dll_tls_data.c", "dll_tls_data_x86.dll", dll=True, arch="x86", tls=True),
    Fixture("x86_dll_entry_context", "c/dll_entry_context.c", "dll_entry_context_x86.dll", dll=True, arch="x86"),
    Fixture("x86_dll_export", "c/dll_export.c", "dll_export_x86.dll", dll=True, arch="x86"),
    Fixture("x64_exe_rust_basic", "rust/exe_rust_basic.rs", "exe_rust_basic.exe",
             dll=False, lang="rust"),
    Fixture("x64_exe_rust_tls_data", "rust/exe_rust_tls_data.rs", "exe_rust_tls_data.exe",
             dll=False, lang="rust", tls=True),
    Fixture("x86_exe_rust_basic", "rust/exe_rust_basic.rs", "exe_rust_basic_x86.exe",
             dll=False, arch="x86", lang="rust"),
    Fixture("x86_exe_rust_tls_data", "rust/exe_rust_tls_data.rs", "exe_rust_tls_data_x86.exe",
             dll=False, arch="x86", lang="rust", tls=True),
]

DLL_EXPORT_EXPECT = (
    "[rdi-test] dll_export attach",
    "[rdi-test] dll_export export user=ABCD",
)

CASES = [
    Case("front_exe_basic", "x64_exe_basic", "front", "x64", ("[rdi-test] exe_basic entry",)),
    Case("post_exe_basic", "x64_exe_basic", "post", "x64", ("[rdi-test] exe_basic entry",)),
    Case("front_dll_basic", "x64_dll_basic", "front", "x64", ("[rdi-test] dll_basic attach",)),
    Case("post_dll_basic", "x64_dll_basic", "post", "x64", ("[rdi-test] dll_basic attach",)),
    Case("front_exe_tls", "x64_exe_tls", "front", "x64",
         ("[rdi-test] exe_tls tls", "[rdi-test] exe_tls entry"), ordered=True),
    Case("post_exe_tls", "x64_exe_tls", "post", "x64",
         ("[rdi-test] exe_tls tls", "[rdi-test] exe_tls entry"), ordered=True),
    Case("front_dll_tls", "x64_dll_tls", "front", "x64",
         ("[rdi-test] dll_tls tls", "[rdi-test] dll_tls attach"), ordered=True),
    Case("post_dll_tls", "x64_dll_tls", "post", "x64",
         ("[rdi-test] dll_tls tls", "[rdi-test] dll_tls attach"), ordered=True),
    Case("front_exe_tls_data", "x64_exe_tls_data", "front", "x64",
         ("[rdi-test] exe_tls_data initial ok",
          "[rdi-test] exe_tls_data write ok"), ordered=True),
    Case("post_exe_tls_data", "x64_exe_tls_data", "post", "x64",
         ("[rdi-test] exe_tls_data initial ok",
          "[rdi-test] exe_tls_data write ok"), ordered=True),
    Case("front_dll_tls_data", "x64_dll_tls_data", "front", "x64",
         ("[rdi-test] dll_tls_data initial ok",
          "[rdi-test] dll_tls_data write ok"), ordered=True),
    Case("post_dll_tls_data", "x64_dll_tls_data", "post", "x64",
         ("[rdi-test] dll_tls_data initial ok",
          "[rdi-test] dll_tls_data write ok"), ordered=True),
    Case("front_dll_export_user", "x64_dll_export", "front", "x64",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_hex="41424344"),
    Case("post_dll_export_user_hex", "x64_dll_export", "post", "x64",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_hex="41424344"),
    Case("post_dll_export_user_file", "x64_dll_export", "post", "x64",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_file="user_abcd.bin"),
    Case("x86_front_exe_basic", "x86_exe_basic", "front", "x86", ("[rdi-test] exe_basic entry",)),
    Case("x86_post_exe_basic", "x86_exe_basic", "post", "x86", ("[rdi-test] exe_basic entry",)),
    Case("x86_front_dll_basic", "x86_dll_basic", "front", "x86", ("[rdi-test] dll_basic attach",)),
    Case("x86_post_dll_basic", "x86_dll_basic", "post", "x86", ("[rdi-test] dll_basic attach",)),
    Case("x86_front_exe_tls", "x86_exe_tls", "front", "x86",
         ("[rdi-test] exe_tls tls", "[rdi-test] exe_tls entry"), ordered=True),
    Case("x86_post_exe_tls", "x86_exe_tls", "post", "x86",
         ("[rdi-test] exe_tls tls", "[rdi-test] exe_tls entry"), ordered=True),
    Case("x86_front_dll_tls", "x86_dll_tls", "front", "x86",
         ("[rdi-test] dll_tls tls", "[rdi-test] dll_tls attach"), ordered=True),
    Case("x86_post_dll_tls", "x86_dll_tls", "post", "x86",
         ("[rdi-test] dll_tls tls", "[rdi-test] dll_tls attach"), ordered=True),
    Case("x86_front_exe_tls_data", "x86_exe_tls_data", "front", "x86",
         ("[rdi-test] exe_tls_data initial ok",
          "[rdi-test] exe_tls_data write ok"), ordered=True),
    Case("x86_post_exe_tls_data", "x86_exe_tls_data", "post", "x86",
         ("[rdi-test] exe_tls_data initial ok",
          "[rdi-test] exe_tls_data write ok"), ordered=True),
    Case("x86_front_dll_tls_data", "x86_dll_tls_data", "front", "x86",
         ("[rdi-test] dll_tls_data initial ok",
          "[rdi-test] dll_tls_data write ok"), ordered=True),
    Case("x86_post_dll_tls_data", "x86_dll_tls_data", "post", "x86",
         ("[rdi-test] dll_tls_data initial ok",
          "[rdi-test] dll_tls_data write ok"), ordered=True),
    Case("x86_front_dll_export_user", "x86_dll_export", "front", "x86",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_hex="41424344"),
    Case("x86_post_dll_export_user_hex", "x86_dll_export", "post", "x86",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_hex="41424344"),
    Case("x86_post_dll_export_user_file", "x86_dll_export", "post", "x86",
         DLL_EXPORT_EXPECT, ordered=True,
         export_name="TestExport", user_file="user_abcd.bin"),
    Case("front_exe_rust_basic", "x64_exe_rust_basic", "front", "x64",
         ("[rdi-test] exe_rust_basic hello world",)),
    Case("post_exe_rust_basic", "x64_exe_rust_basic", "post", "x64",
         ("[rdi-test] exe_rust_basic hello world",)),
    Case("front_exe_rust_tls_data", "x64_exe_rust_tls_data", "front", "x64",
         ("[rdi-test] exe_rust_tls_data initial ok",
          "[rdi-test] exe_rust_tls_data write ok"), ordered=True),
    Case("post_exe_rust_tls_data", "x64_exe_rust_tls_data", "post", "x64",
         ("[rdi-test] exe_rust_tls_data initial ok",
          "[rdi-test] exe_rust_tls_data write ok"), ordered=True),
    Case("x86_front_exe_rust_basic", "x86_exe_rust_basic", "front", "x86",
         ("[rdi-test] exe_rust_basic hello world",)),
    Case("x86_post_exe_rust_basic", "x86_exe_rust_basic", "post", "x86",
         ("[rdi-test] exe_rust_basic hello world",)),
    Case("x86_front_exe_rust_tls_data", "x86_exe_rust_tls_data", "front", "x86",
         ("[rdi-test] exe_rust_tls_data initial ok",
          "[rdi-test] exe_rust_tls_data write ok"), ordered=True),
    Case("x86_post_exe_rust_tls_data", "x86_exe_rust_tls_data", "post", "x86",
         ("[rdi-test] exe_rust_tls_data initial ok",
          "[rdi-test] exe_rust_tls_data write ok"), ordered=True),

    Case("front_exe_full", "x64_exe_full", "front", "x64",
         ("[rdi-test] exe_full tls callback ok",
          "[rdi-test] exe_full tls data initial ok",
          "[rdi-test] exe_full tls data write ok"), ordered=True),
    Case("post_exe_full", "x64_exe_full", "post", "x64",
         ("[rdi-test] exe_full tls callback ok",
          "[rdi-test] exe_full tls data initial ok",
          "[rdi-test] exe_full tls data write ok"), ordered=True),
    Case("x86_front_exe_full", "x86_exe_full", "front", "x86",
         ("[rdi-test] exe_full tls callback ok",
          "[rdi-test] exe_full tls data initial ok",
          "[rdi-test] exe_full tls data write ok"), ordered=True),
    Case("x86_post_exe_full", "x86_exe_full", "post", "x86",
         ("[rdi-test] exe_full tls callback ok",
          "[rdi-test] exe_full tls data initial ok",
          "[rdi-test] exe_full tls data write ok"), ordered=True),

    Case("front_exe_data_reloc", "x64_exe_data_reloc", "front", "x64",
         ("[rdi-test] exe_data_reloc initial ok",
          "[rdi-test] exe_data_reloc write ok"), ordered=True),
    Case("post_exe_data_reloc", "x64_exe_data_reloc", "post", "x64",
         ("[rdi-test] exe_data_reloc initial ok",
          "[rdi-test] exe_data_reloc write ok"), ordered=True),
    Case("x86_front_exe_data_reloc", "x86_exe_data_reloc", "front", "x86",
         ("[rdi-test] exe_data_reloc initial ok",
          "[rdi-test] exe_data_reloc write ok"), ordered=True),
    Case("x86_post_exe_data_reloc", "x86_exe_data_reloc", "post", "x86",
         ("[rdi-test] exe_data_reloc initial ok",
          "[rdi-test] exe_data_reloc write ok"), ordered=True),

    Case("front_exe_header_scrub", "x64_exe_header_scrub", "front", "x64",
         ("[rdi-test] exe_header_scrub ok",)),
    Case("post_exe_header_scrub", "x64_exe_header_scrub", "post", "x64",
         ("[rdi-test] exe_header_scrub ok",)),
    Case("x86_front_exe_header_scrub", "x86_exe_header_scrub", "front", "x86",
         ("[rdi-test] exe_header_scrub ok",)),
    Case("x86_post_exe_header_scrub", "x86_exe_header_scrub", "post", "x86",
         ("[rdi-test] exe_header_scrub ok",)),

    Case("front_exe_tls_thread", "x64_exe_tls_thread", "front", "x64",
         ("[rdi-test] exe_tls_thread current ok",
          "[rdi-test] exe_tls_thread worker initial ok",
          "[rdi-test] exe_tls_thread worker write ok",
          "[rdi-test] exe_tls_thread complete ok"), ordered=True),
    Case("post_exe_tls_thread", "x64_exe_tls_thread", "post", "x64",
         ("[rdi-test] exe_tls_thread current ok",
          "[rdi-test] exe_tls_thread worker initial ok",
          "[rdi-test] exe_tls_thread worker write ok",
          "[rdi-test] exe_tls_thread complete ok"), ordered=True),
    Case("x86_front_exe_tls_thread", "x86_exe_tls_thread", "front", "x86",
         ("[rdi-test] exe_tls_thread current ok",
          "[rdi-test] exe_tls_thread worker initial ok",
          "[rdi-test] exe_tls_thread worker write ok",
          "[rdi-test] exe_tls_thread complete ok"), ordered=True),
    Case("x86_post_exe_tls_thread", "x86_exe_tls_thread", "post", "x86",
         ("[rdi-test] exe_tls_thread current ok",
          "[rdi-test] exe_tls_thread worker initial ok",
          "[rdi-test] exe_tls_thread worker write ok",
          "[rdi-test] exe_tls_thread complete ok"), ordered=True),

    Case("front_dll_entry_context", "x64_dll_entry_context", "front", "x64",
         ("[rdi-test] dll_entry_context ok",)),
    Case("post_dll_entry_context", "x64_dll_entry_context", "post", "x64",
         ("[rdi-test] dll_entry_context ok",)),
    Case("x86_front_dll_entry_context", "x86_dll_entry_context", "front", "x86",
         ("[rdi-test] dll_entry_context ok",)),
    Case("x86_post_dll_entry_context", "x86_dll_entry_context", "post", "x86",
         ("[rdi-test] dll_entry_context ok",)),

    Case("front_exe_unwind_table", "x64_exe_unwind_table", "front", "x64",
         ("[rdi-test] exe_unwind_table ok",)),
    Case("post_exe_unwind_table", "x64_exe_unwind_table", "post", "x64",
         ("[rdi-test] exe_unwind_table ok",)),

    Case("front_dll_export_hash", "x64_dll_export", "front", "x64",
         DLL_EXPORT_EXPECT, ordered=True,
         export_hash=0xCA6A4AB7, user_hex="41424344"),
    Case("post_dll_export_hash", "x64_dll_export", "post", "x64",
         DLL_EXPORT_EXPECT, ordered=True,
         export_hash=0xCA6A4AB7, user_hex="41424344"),
    Case("x86_front_dll_export_hash", "x86_dll_export", "front", "x86",
         DLL_EXPORT_EXPECT, ordered=True,
         export_hash=0xCA6A4AB7, user_hex="41424344"),
    Case("x86_post_dll_export_hash", "x86_dll_export", "post", "x86",
         DLL_EXPORT_EXPECT, ordered=True,
         export_hash=0xCA6A4AB7, user_hex="41424344"),
]


def run(cmd: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        encoding="mbcs",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def must_run(cmd: list[str], *, timeout: int = 30) -> str:
    p = run(cmd, timeout=timeout)
    if p.returncode != 0:
        print("[-] command failed:", " ".join(cmd))
        sys.stdout.buffer.write(p.stdout.encode("utf-8", "replace"))
        if not p.stdout.endswith("\n"):
            sys.stdout.buffer.write(b"\n")
        raise SystemExit(1)
    return p.stdout


def build_public_toolchain() -> None:
    build_script = ROOT / "tools" / "build_convert2shellcode.bat"
    must_run(["cmd", "/c", str(build_script)], timeout=120)

    required = (
        "Convert2Shellcode.exe",
        "shellcode_loader.exe",
        "shellcode_loader_x86.exe",
        "srdi_front_v2_x64.bin",
        "srdi_post_v2_x64.bin",
        "srdi_front_v2_x86.bin",
        "srdi_post_v2_x86.bin",
    )
    missing = [name for name in required if not (BIN / name).is_file()]
    if missing:
        raise SystemExit("[-] public toolchain build did not produce: " + ", ".join(missing))


def find_vcvarsall() -> Path:
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.exists():
        raise SystemExit(f"[-] vswhere.exe not found: {vswhere}")
    p = subprocess.run(
        [str(vswhere), "-latest", "-products", "*",
         "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
         "-property", "installationPath"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    root = p.stdout.strip()
    if p.returncode != 0 or not root:
        raise SystemExit("[-] Visual Studio with VC tools not found")
    vcvars = Path(root) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
    if not vcvars.exists():
        raise SystemExit(f"[-] vcvarsall.bat not found: {vcvars}")
    return vcvars


def must_run_msvc(arch: str, args: list[str], *, timeout: int = 30) -> str:
    if VCVARSALL is None:
        raise RuntimeError("VCVARSALL is not initialized")
    if BUILD_TMP is None:
        raise RuntimeError("BUILD_TMP is not initialized")
    bat = BUILD_TMP / f"msvc_{arch}_{abs(hash(tuple(args))) & 0xffffffff:x}.bat"
    bat.write_text(
        "@echo off\r\n"
        f"call \"{VCVARSALL}\" {arch} >nul\r\n"
        "if errorlevel 1 exit /b %ERRORLEVEL%\r\n"
        + subprocess.list2cmdline(args)
        + "\r\n",
        encoding="mbcs",
    )
    return must_run(["cmd", "/c", str(bat)], timeout=timeout)


def build_rust_fixture(fx: Fixture) -> Path:
    src = FIXTURES / fx.source
    out = OUT / fx.output
    target = RUST_TARGETS.get(fx.arch)
    if not target:
        raise SystemExit(f"[-] unsupported rust arch: {fx.arch}")

    # #[thread_local] requires nightly; a plain std binary works on stable.
    if fx.tls:
        rustup = shutil.which("rustup")
        if not rustup:
            raise SystemExit("[-] rustup not found; nightly is required for Rust TLS fixtures")
        compiler = [rustup, "run", "nightly-x86_64-pc-windows-msvc", "rustc"]
    else:
        rustc = shutil.which("rustc")
        if not rustc:
            raise SystemExit("[-] rustc not found; install the Rust toolchain")
        compiler = [rustc]

    cmd = compiler + [
        "--edition", "2021", "--target", target, "-O", "-C", "panic=abort",
        "-C", "link-arg=/SUBSYSTEM:CONSOLE",
    ]
    if fx.tls:
        # Custom entry (no_main) + keep default CRT libraries for _tls_used.
        cmd += ["-C", "link-arg=/ENTRY:Entry", str(src), "-o", str(out)]
    else:
        # Plain std binary: let rustc provide the default entry point.
        cmd += [str(src), "-o", str(out)]

    print(f"[*] building fixture {fx.name} ({fx.arch}, rust, {'nightly' if fx.tls else 'stable'})")
    must_run(cmd, timeout=60)
    return out


def build_fixture(fx: Fixture) -> Path:
    if fx.lang == "rust":
        return build_rust_fixture(fx)

    if BUILD_TMP is None:
        raise RuntimeError("BUILD_TMP is not initialized")

    src = FIXTURES / fx.source
    out = OUT / fx.output
    obj = BUILD_TMP / f"{fx.name}.obj"
    pdb = BUILD_TMP / f"{fx.name}.pdb"
    implib = BUILD_TMP / f"{fx.name}.lib"
    base = [
        "cl", "/nologo", "/W4", "/O2", "/GS-", "/guard:cf-",
        f"/I{FIXTURES / 'common'}", str(src), f"/Fo{obj}", f"/Fe{out}",
    ]
    dll_entry = "/ENTRY:DllMain" if fx.arch == "x64" else "/ENTRY:DllMain@12"
    if fx.dll:
        cmd = base + [
            "/LD", "/link", dll_entry, "/NODEFAULTLIB", "kernel32.lib",
            f"/IMPLIB:{implib}", f"/PDB:{pdb}",
        ]
    else:
        cmd = base + [
            "/link", "/ENTRY:Entry", "/SUBSYSTEM:CONSOLE", "/NODEFAULTLIB",
            "kernel32.lib", f"/PDB:{pdb}",
        ]

    # TLS callback fixtures need the MSVC TLS support symbol. Keep the entry custom,
    # but allow the linker default libraries to provide _tls_used cleanly.
    if fx.tls:
        if fx.dll:
            cmd = base + [
                "/LD", "/link", dll_entry, "kernel32.lib",
                f"/IMPLIB:{implib}", f"/PDB:{pdb}",
            ]
        else:
            cmd = base + [
                "/link", "/ENTRY:Entry", "/SUBSYSTEM:CONSOLE",
                "kernel32.lib", f"/PDB:{pdb}",
            ]

    print(f"[*] building fixture {fx.name} ({fx.arch})")
    must_run_msvc(fx.arch, cmd)
    return out


def conversion_command(converter: Path, case: Case, fixture_path: Path, output: Path) -> list[str]:
    cmd = [
        str(converter),
        "--arch", case.arch,
        "--type", case.rdi_type,
        "--input", str(fixture_path),
        "--output", str(output),
    ]
    if case.export_name:
        cmd += ["--export-name", case.export_name]
    if case.export_hash is not None:
        cmd += ["--export-hash", f"0x{case.export_hash:08X}"]
    if case.user_hex:
        cmd += ["--user-data-hex", case.user_hex]
    if case.user_file:
        cmd += ["--user-data", str(OUT / case.user_file)]
    return cmd


def convert_case(case: Case, fixture_path: Path) -> Path:
    out = OUT / f"{case.name}.bin"
    cmd = conversion_command(BIN / "Convert2Shellcode.exe", case, fixture_path, out)

    print(f"[*] converting {case.name}")
    must_run(cmd)
    return out


def print_block(title: str, text: str) -> None:
    print(f"  {title}:")
    if not text:
        print("    <empty>")
        return
    for line in text.splitlines():
        print(f"    {line}")


def check_forbidden_output(output: str) -> bool:
    ok = True
    for line in output.splitlines():
        if line.startswith("[rdi-test]") and " fail" in line:
            print(f"  [BAD] forbidden failure marker: {line}")
            ok = False
    return ok


def check_output(case: Case, output: str) -> bool:
    ok = True

    if not check_forbidden_output(output):
        ok = False

    if case.ordered:
        pos = -1
        for idx, marker in enumerate(case.expect, 1):
            nxt = output.find(marker, pos + 1)
            if nxt < 0:
                print(f"  [MISS] marker[{idx}] ordered: {marker}")
                ok = False
                continue
            print(f"  [OK] marker[{idx}] ordered at offset {nxt}: {marker}")
            pos = nxt
        return ok

    for idx, marker in enumerate(case.expect, 1):
        pos = output.find(marker)
        if pos < 0:
            print(f"  [MISS] marker[{idx}]: {marker}")
            ok = False
        else:
            print(f"  [OK] marker[{idx}] at offset {pos}: {marker}")
    return ok


def run_case(case: Case, fixture_path: Path) -> bool:
    shellcode = convert_case(case, fixture_path)
    loader = BIN / ("shellcode_loader_x86.exe" if case.arch == "x86" else "shellcode_loader.exe")
    cmd = [str(loader), str(shellcode), "5000"]
    log_path = LOGS / f"{case.name}.log"

    print()
    print(f"[CASE] {case.name}")
    print(f"  rdi_type:  {case.rdi_type}")
    print(f"  arch:      {case.arch}")
    print(f"  fixture:   {fixture_path} ({fixture_path.stat().st_size} bytes)")
    print(f"  shellcode: {shellcode} ({shellcode.stat().st_size} bytes)")
    print(f"  command:   {' '.join(cmd)}")

    p = run(cmd, timeout=10)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(p.stdout, encoding="utf-8", errors="replace")

    print(f"  exit_code: {p.returncode}")
    print(f"  log_file:  {log_path}")
    print_block("stdout", p.stdout)
    print("  checks:")

    ok = p.returncode == 0 and check_output(case, p.stdout)
    if ok:
        print(f"[PASS] {case.name}")
    else:
        print(f"[FAIL] {case.name}")
    return ok


def run_negative_case(name: str, cmd: list[str]) -> bool:
    log_path = LOGS / f"{name}.log"
    print()
    print(f"[NEGATIVE] {name}")
    print(f"  command: { ' '.join(cmd)}")

    result = run(cmd)
    log_path.write_text(
        f"[exit_code={result.returncode}]\n{result.stdout}",
        encoding="utf-8",
        errors="replace",
    )
    print(f"  exit_code: {result.returncode}")
    print(f"  log_file:  {log_path}")
    print_block("stdout", result.stdout)

    if result.returncode != 0:
        print(f"[PASS] {name}: rejected by converter")
        return True

    print(f"[FAIL] {name}: converter accepted invalid input")
    return False


def run_negative_cases(fixtures: dict[str, Path]) -> list[bool]:
    invalid_dos = OUT / "invalid_dos.bin"
    invalid_dos.write_bytes(b"not-a-pe")

    truncated_pe = OUT / "truncated_pe.bin"
    truncated = bytearray(0x40)
    truncated[:2] = b"MZ"
    struct.pack_into("<I", truncated, 0x3C, 0x80)
    truncated_pe.write_bytes(truncated)

    bad_signature = OUT / "bad_signature.bin"
    bad = bytearray(0x100)
    bad[:2] = b"MZ"
    struct.pack_into("<I", bad, 0x3C, 0x80)
    bad[0x80:0x84] = b"NOPE"
    bad_signature.write_bytes(bad)

    converter = BIN / "Convert2Shellcode.exe"
    cases = [
        ("reject_invalid_dos", invalid_dos, "x64"),
        ("reject_truncated_pe", truncated_pe, "x64"),
        ("reject_bad_nt_signature", bad_signature, "x64"),
        ("reject_arch_mismatch", fixtures["x64_exe_basic"], "x86"),
    ]
    results = []
    for name, source, arch in cases:
        cmd = [
            str(converter), "--arch", arch, "--type", "front",
            "--input", str(source), "--output", str(OUT / f"{name}.bin"),
        ]
        results.append(run_negative_case(name, cmd))
    return results


def main() -> int:
    global BUILD_TMP, VCVARSALL
    OUT.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    (OUT / "user_abcd.bin").write_bytes(b"ABCD")
    BUILD_TMP = Path(tempfile.mkdtemp(prefix="Convert2Shellcode_tests_"))
    VCVARSALL = find_vcvarsall()

    try:
        print("[*] building public RDI toolchain")
        build_public_toolchain()

        fixtures: dict[str, Path] = {}
        for fx in FIXTURE_LIST:
            fixtures[fx.name] = build_fixture(fx)

        results = run_negative_cases(fixtures)
        passed = 0
        for case in CASES:
            if run_case(case, fixtures[case.fixture]):
                passed += 1


        passed += sum(results)
        total = len(CASES) + len(results)
        print()
        print(f"Results: {passed}/{total} passed")
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(BUILD_TMP, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
