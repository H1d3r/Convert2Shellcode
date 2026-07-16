# PE/SRDI 验证示例 / PE/SRDI Validation Examples

在仓库根目录运行完整回归矩阵：

Run the complete regression matrix from the repository root:

```bat
py -3 example\run_rdi_tests.py
```

运行器会构建公开 RDI 工具链、构建全部 fixture、将其转换为 `front` 和/或
`post` shellcode、使用匹配的 x64 或 x86 loader 执行，并将生成文件写入
`example\out`。

The runner builds the public RDI toolchain, builds every fixture, converts it
to `front` and/or `post` shellcode, executes it with the matching x64 or x86
loader, and writes generated files below `example\out`.

在 C 到 Go 的迁移阶段，每个正向用例还会由临时 C baseline 生成同一份
shellcode，并与 Go CLI 输出逐字节比较。

During the C-to-Go migration, every positive case is also converted by the
temporary C baseline and compared byte-for-byte with the Go CLI output.

## 目录结构 / Layout

```text
example/
  fixtures/
    c/       C PE fixtures / C PE 测试样本
    rust/    Rust runtime and static-TLS fixtures / Rust 运行时与静态 TLS 样本
    common/  shared fixture helpers / 共享辅助代码
  run_rdi_tests.py
```

## 自动化覆盖 / Automated Coverage

| 范围 / Area | 样本 / Fixtures | 验证内容 / What Is Verified |
|---|---|---|
| EXE OEP 与 DLL 入口 / EXE OEP and DLL entry | `exe_basic`, `dll_basic`, `dll_entry_context` | EXE OEP 路径；`DllMain(image_base, DLL_PROCESS_ATTACH, NULL)`；x86 调用约定 / EXE OEP path; DLL entry arguments; x86 calling convention |
| 导入与节映射 / Imports and section mapping | 全部 C/Rust fixtures / all C/Rust fixtures | `kernel32`/`ntdll` 导入解析、节映射、可写数据访问 / import resolution, mapped sections, writable data access |
| 重定位、`.data`、`.bss` / Relocation, `.data`, `.bss` | `exe_data_reloc` | 绝对数据指针重定位、初始化数据、零填充与写入 / absolute pointer relocation, initialized data, zero-fill, writes |
| TLS callback | `exe_tls`, `dll_tls`, `exe_full` | callback 调度以及 callback 先于入口执行 / callback dispatch and callback-before-entry ordering |
| 静态 TLS 数据 / Static TLS data | `exe_tls_data`, `dll_tls_data`, Rust TLS, `exe_full` | `AddressOfIndex`、TLS raw data 初始化和可写 TLS storage / TLS index, raw-data initialization, writable TLS storage |
| 新线程静态 TLS / Static TLS in new threads | `exe_tls_thread` | 由映射 EXE 创建的新线程中的 TLS 初始化 / TLS initialization in a thread created by the mapped EXE |
| x64 unwind 元数据 / x64 unwind metadata | `exe_unwind_table` | 通过 `RtlLookupFunctionEntry` 验证 `RtlAddFunctionTable` / verifies `RtlAddFunctionTable` through `RtlLookupFunctionEntry` |
| PE header 清理 / Header scrub | `exe_header_scrub` | 调用入口前，映射 PE 的 DOS header 已被清零 / mapped PE DOS header is cleared before entry execution |
| DLL 导出与 user data / DLL exports and user data | `dll_export` | 名称查找、ROR13 hash 查找、内联 hex 与文件 user data / name lookup, ROR13 hash lookup, inline hex and file user data |
| Rust 运行时 / Rust runtime | `exe_rust_basic`, `exe_rust_tls_data` | 标准 Rust 启动路径及 Rust 静态 TLS / normal Rust startup and static TLS |
| 转换器拒绝路径 / Converter rejection | 运行期生成的无效输入 / generated malformed inputs | 无效 DOS、截断 PE、错误 NT 签名和架构不匹配 / invalid DOS, truncated PE, bad NT signature, architecture mismatch |

所有适用的执行样本均在 x64 和 x86 的 `front`、`post` 模式下运行；仅 x64 的
unwind 样本在两种 RDI 模式下运行。当前矩阵共 68 项。

All applicable execution fixtures run in both `front` and `post` modes on
x64 and x86. The x64-only unwind fixture runs in both RDI modes. The current
matrix contains 68 cases.

## 当前覆盖边界 / Current Coverage Boundaries

以下场景未进入自动化通过/失败矩阵，因为它们需要环境相关的地址分配或额外的
PE 后处理：

The following cases are not automatic pass/fail tests because they require
environment-dependent allocation or additional PE post-processing:

- 不可重定位的 `/FIXED` PE，需要按其 `ImageBase` 映射 / non-relocatable `/FIXED` PE images at a required `ImageBase`;
- ordinal、forwarded、delay-load 和 bound import / ordinal, forwarded, delay-load, and bound imports;
- CLR/托管 PE、驱动、加壳 PE，以及依赖完整 CRT 初始化的样本 / managed CLR images, drivers, packed images, and binaries requiring full CRT setup;
- 反射映射前已经存在的线程中的 TLS 初始化 / TLS initialization for threads already alive before reflective mapping.

预期结果 / Expected result:

```text
Results: 68/68 passed
```
