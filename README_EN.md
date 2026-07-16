# Convert2Shellcode

Convert2Shellcode is a PE-to-shellcode tool that converts Windows EXE / DLL files into raw shellcode bytes that can be loaded and executed directly.

It supports x64 / x86 and provides two SRDI layouts:

- `front`: RDI loader placed before the PE.
- `post`: RDI loader placed after the PE.

Both modes support EXE entrypoint execution, DLL `DllMain` execution, calling a specified DLL export function, and passing user data.

## Capabilities

- Architectures: x64 / x86
- File types: EXE / DLL
- Modes: front / post
- Import table resolution
- Base relocation
- TLS callback
- TLS data
- Section protection
- Original PE data zeroing
- Mapped PE header scrubbing
- DLL `DllMain`
- EXE entrypoint
- DLL export call by name or hash
- User data passthrough to DLL export
- Rust EXE static TLS data initialization

Not supported:

- .NET assembly

## Go Library

Module path:

```text
github.com/onedays12/Convert2Shellcode
```

`Convert` is a pure-Go API: it takes PE bytes and returns RDI shellcode, with
no cgo, Windows API, or runtime `bin` directory dependency.

```go
package main

import (
    "os"

    convert2shellcode "github.com/onedays12/Convert2Shellcode"
)

func main() {
    pe, _ := os.ReadFile("target.exe")
    shellcode, err := convert2shellcode.Convert(pe, convert2shellcode.Options{
        Arch:       convert2shellcode.ArchX64,
        Layout:     convert2shellcode.LayoutFront,
        ExportName: "TestExport",
        UserData:   []byte("ABCD"),
    })
    if err != nil {
        panic(err)
    }
    _ = os.WriteFile("target.bin", shellcode, 0o666)
}
```

The CLI wrapper lives in `cmd\convert2shellcode`; the build script produces
`bin\Convert2Shellcode.exe`.

## Build

Requirements:

- Windows x64
- Visual Studio 2022 Build Tools or full Visual Studio
- VC x64/x86 tools: `ml64.exe`, `ml.exe`, `cl.exe`
- Python 3
- Go 1.25+

When used as a Go library, only Go and the versioned RDI assets in the repo
are required. Visual Studio, Python, and the `bin` directory are only needed
to re-assemble ASM, build the local CLI, and test loaders.

Build all tools and RDI blobs:

```bat
tools\build_convert2shellcode.bat
```

Specify a default sample PE:

```bat
tools\build_convert2shellcode.bat path\to\target.exe
```

Main outputs:

```text
bin\Convert2Shellcode.exe
bin\shellcode_loader.exe
bin\shellcode_loader_x86.exe
bin\srdi_front_v2_x64.bin
bin\srdi_post_v2_x64.bin
bin\srdi_front_v2_x86.bin
bin\srdi_post_v2_x86.bin
```

Intermediate build files are placed in the system temp directory, so no
`.obj` / `.o` / `.pdb` / `.lib` / `.exp` are left in the project tree.

## Basic Usage

Show help:

```bat
bin\Convert2Shellcode.exe --help
```

Command format:

```bat
bin\Convert2Shellcode.exe --arch x64|x86 --type front|post --input <pe> --output <bin> [options]
```

Options:

```text
--arch x64|x86          Target architecture, default x64
--type front|post       SRDI layout, default front
--input <pe>            Input EXE / DLL
--output <bin>          Output shellcode
--user-data <file>      Read user data from a file and pass it to the DLL export
--user-data-hex <hex>   Read user data from a hex string and pass it to the DLL export
--export-name <name>    Call the specified DLL export; the tool computes the ROR13 hash
--export-hash <value>   Call the specified DLL export by hash, decimal or 0x hex
```

Note: `--arch` must match the input PE architecture. For example, an x86 PE
requires `--arch x86`, and an x64 PE requires `--arch x64`.

`--output` produces raw shellcode bytes, not a PE file. It cannot be
double-clicked; it must be loaded and executed by a shellcode loader.

## EXE to Shellcode

x64 front:

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.exe --output target_x64_front.bin
```

x64 post:

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.exe --output target_x64_post.bin
```

x86 front:

```bat
bin\Convert2Shellcode.exe --arch x86 --type front --input target32.exe --output target_x86_front.bin
```

x86 post:

```bat
bin\Convert2Shellcode.exe --arch x86 --type post --input target32.exe --output target_x86_post.bin
```

## DLL to Shellcode

By default, a DLL will execute:

```c
DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
```

Example:

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output target_dll.bin
```

## Calling a DLL Export

To call a specified DLL export, use:

```bat
--export-name <name>
```

Example:

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output out.bin --export-name TestExport
```

You can also specify the hash directly:

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.dll --output out.bin --export-hash 0x12345678
```

Export calling convention:

```c
Export(image_base, user_ptr, user_len)
```

On x64, arguments are passed in registers; on x86, via the stack. The export
function parses `user_ptr` / `user_len` according to its own convention.

## Passing User Data

From a file:

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output out.bin --export-name TestExport --user-data data.bin
```

From a hex string:

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.dll --output out.bin --export-name TestExport --user-data-hex 41424344
```

`Convert2Shellcode.exe` does not define a multi-argument separator inside the
user data. It only passes the raw bytes to the export:

```text
user_ptr = address of the user data
user_len = length of the user data
```

How multiple arguments are separated is up to the target DLL export. If
arguments may contain `|`, spaces, newlines, or `\0`, a length-prefixed
format is recommended, for example:

```text
argc:u32 + repeated(len:u32 + arg_bytes)
```

## Load Testing

x64 shellcode:

```bat
bin\shellcode_loader.exe target_x64_front.bin 15000
bin\shellcode_loader.exe target_x64_post.bin 15000
```

x86 shellcode:

```bat
bin\shellcode_loader_x86.exe target_x86_front.bin 15000
bin\shellcode_loader_x86.exe target_x86_post.bin 15000
```

The second argument is the number of milliseconds to wait for the shellcode
thread to finish.

## Tests

Run the example validation matrix:

```bat
python example\run_rdi_tests.py
```

Current stable result:

```text
Results: 68/68 passed
```

## FAQ

### The generated shellcode does not run

Check:

- `--arch` matches the input PE architecture.
- x86 shellcode is executed with the x86 loader.
- x64 shellcode is executed with the x64 loader.
- The DLL export name actually exists.
- `--user-data-hex` has an even number of hex characters.

### DLL export does not receive arguments

Make sure both are specified:

```bat
--export-name TestExport
--user-data or --user-data-hex
```

If you only pass `--user-data` without specifying an export, the DLL will
just run `DllMain`.

### How to choose between front and post

Either works.

- `front`: RDI loader placed before the PE.
- `post`: RDI loader placed after the PE.

Both support x64 / x86, EXE / DLL, export calls, and user data. If you have
no special requirement, pick one and stick with it.

