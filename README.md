# Convert2Shellcode

Convert2Shellcode 是一个 PE 转 shellcode 工具，可以把 Windows EXE / DLL 转换成可直接加载执行的 raw shellcode bytes。

当前支持 x64 / x86，并提供两种 SRDI 布局：

- `front`：RDI loader 位于 PE 前方。
- `post`：RDI loader 位于 PE 后方。

两种模式都支持 EXE 入口执行、DLL `DllMain` 执行、调用 DLL 指定导出函数，以及传递用户数据。

## 当前能力

- 支持架构：x64 / x86
- 支持文件：EXE / DLL
- 支持模式：front / post
- 支持导入表解析
- 支持重定位
- 支持 TLS callback
- 支持 TLS data
- 支持 section protection
- 支持清零原始 PE 数据
- 支持隐藏映射后 PE header 特征
- 支持 DLL `DllMain`
- 支持 EXE entrypoint
- 支持按导出函数名或导出 hash 调用 DLL export
- 支持向 DLL export 传递用户数据
- 支持 Rust EXE 的静态 TLS data 初始化

当前不支持：

- .NET assembly

## Go 库

模块路径：

```text
github.com/onedays12/Convert2Shellcode
```

`Convert` 是纯 Go API：输入 PE 字节，输出 RDI shellcode，不依赖 cgo、Windows
API 或运行时 `bin` 目录。

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

命令行版本位于 `cmd\convert2shellcode`；构建脚本会将其生成到
`bin\Convert2Shellcode.exe`。

## 构建

要求：

- Windows x64
- Visual Studio 2022 Build Tools 或完整 Visual Studio
- VC x64/x86 tools：`ml64.exe`、`ml.exe`、`cl.exe`
- Python 3
- Go 1.25+

作为 Go 库使用时，只需要 Go 和仓库中版本化的 RDI assets；不需要 Visual
Studio、Python 或 `bin` 目录。Visual Studio 与 Python 仅用于重新汇编 ASM、
构建本地 CLI 和测试 loader。

构建全部工具和 RDI blob：

```bat
tools\build_convert2shellcode.bat
```

指定默认示例 PE：

```bat
tools\build_convert2shellcode.bat path\to\target.exe
```

主要输出：

```text
bin\Convert2Shellcode.exe
bin\shellcode_loader.exe
bin\shellcode_loader_x86.exe
bin\srdi_front_v2_x64.bin
bin\srdi_post_v2_x64.bin
bin\srdi_front_v2_x86.bin
bin\srdi_post_v2_x86.bin
```

构建中间文件会放在系统临时目录，不会在项目目录留下 `.obj` / `.o` / `.pdb` / `.lib` / `.exp`。

## 基本用法

查看帮助：

```bat
bin\Convert2Shellcode.exe --help
```

命令格式：

```bat
bin\Convert2Shellcode.exe --arch x64|x86 --type front|post --input <pe> --output <bin> [options]
```

参数：

```text
--arch x64|x86          目标架构，默认 x64
--type front|post       SRDI 布局，默认 front
--input <pe>            输入 EXE / DLL
--output <bin>          输出 shellcode
--user-data <file>      从文件读取用户数据并传给 DLL export
--user-data-hex <hex>   从十六进制字符串读取用户数据并传给 DLL export
--export-name <name>    调用 DLL 指定导出函数，工具自动计算 ROR13 hash
--export-hash <value>   调用 DLL 指定导出 hash，支持十进制或 0x 十六进制
```

注意：`--arch` 必须和输入 PE 的架构一致。例如 x86 PE 要使用 `--arch x86`，x64 PE 要使用 `--arch x64`。

`--output` 生成的是 raw shellcode bytes，不是 PE 文件，不能直接双击运行，需要由 shellcode loader 加载执行。

## EXE 转 shellcode

x64 front：

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.exe --output target_x64_front.bin
```

x64 post：

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.exe --output target_x64_post.bin
```

x86 front：

```bat
bin\Convert2Shellcode.exe --arch x86 --type front --input target32.exe --output target_x86_front.bin
```

x86 post：

```bat
bin\Convert2Shellcode.exe --arch x86 --type post --input target32.exe --output target_x86_post.bin
```

## DLL 转 shellcode

默认情况下，DLL 会执行：

```c
DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
```

示例：

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output target_dll.bin
```

## 调用 DLL 导出函数

如果需要调用 DLL 中的指定导出函数，可以使用：

```bat
--export-name <name>
```

例如：

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output out.bin --export-name TestExport
```

也可以直接指定 hash：

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.dll --output out.bin --export-hash 0x12345678
```

导出函数调用约定：

```c
Export(image_base, user_ptr, user_len)
```

x64 下参数通过寄存器传递；x86 下按栈参数传递。导出函数内部按自己的约定解析 `user_ptr` / `user_len`。

## 传递用户数据

从文件传递：

```bat
bin\Convert2Shellcode.exe --arch x64 --type front --input target.dll --output out.bin --export-name TestExport --user-data data.bin
```

从十六进制字符串传递：

```bat
bin\Convert2Shellcode.exe --arch x64 --type post --input target.dll --output out.bin --export-name TestExport --user-data-hex 41424344
```

`Convert2Shellcode.exe` 不定义用户数据里的多参数分隔规则。工具只会把原始字节传给导出函数：

```text
user_ptr = 用户数据首地址
user_len = 用户数据长度
```

多个参数如何分隔，需要由目标 DLL 的导出函数自行约定并解析。如果参数可能包含 `|`、空格、换行或 `\0`，建议使用长度前缀格式，例如：

```text
argc:u32 + repeated(len:u32 + arg_bytes)
```

## 加载测试

x64 shellcode：

```bat
bin\shellcode_loader.exe target_x64_front.bin 15000
bin\shellcode_loader.exe target_x64_post.bin 15000
```

x86 shellcode：

```bat
bin\shellcode_loader_x86.exe target_x86_front.bin 15000
bin\shellcode_loader_x86.exe target_x86_post.bin 15000
```

第二个参数是等待 shellcode 线程结束的毫秒数。

## 测试

运行示例验证矩阵：

```bat
python example\run_rdi_tests.py
```

当前稳定结果：

```text
Results: 68/68 passed
```

## 常见问题

### 生成的 shellcode 没有运行

先确认：

- `--arch` 是否和输入 PE 架构一致。
- x86 shellcode 是否用 x86 loader 执行。
- x64 shellcode 是否用 x64 loader 执行。
- DLL export 名是否真实存在。
- `--user-data-hex` 是否是偶数字符长度。

### DLL export 没有收到参数

确认命令中同时指定了：

```bat
--export-name TestExport
--user-data 或 --user-data-hex
```

如果只传 `--user-data`，但不指定 export，默认只会执行 DLL `DllMain`。

### front 和 post 怎么选

一般都可以使用。

- `front`：RDI loader 位于 PE 前方。
- `post`：RDI loader 位于 PE 后方。

两者都支持 x64 / x86、EXE / DLL、export 调用和 user-data。如果没有特殊需求，任选一种并固定使用即可。

