# Chain Finder (指针链查找器)

## 概述 (Overview)
一个C语言程序，用于在目标进程的内存中反向工程和查找指向已知内存地址的指针链。
(A C program to reverse engineer and find pointer chains leading to a known memory address in a target process.)
它通过扫描指定模块的内存区域，尝试不同的偏移组合来定位这些链。
(It works by scanning memory regions of specified modules and trying different offset combinations to locate these chains.)

## 编译 (Compilation)
使用提供的 Makefile 进行编译:
(To compile the program, use the provided Makefile:)
```bash
make
```
这将生成一个名为 `chain_finder` 的可执行文件。
(This will produce an executable named `chain_finder`.)

## 用法 (Usage)
```bash
./chain_finder -p <pid> -a <目标地址> -m <模块名> -d <最大深度> -o <最小偏移> -x <最大偏移> [-h]
```

### 参数 (Arguments):
*   `-p <pid>`: (必需) 目标进程的ID。 (Required: The Process ID of the target application.)
*   `-a <目标地址>`: (必需) 要查找的最终内存地址 (十六进制, 例如 `0x7970437160`)。程序将尝试找到指向此地址的链。 (Required: The final memory address (in hexadecimal, e.g., `0x7970437160`) to find. The program will try to find chains that resolve to this address.)
*   `-m <模块名>`: (必需) 要在其中搜索链起点的模块名称 (例如 `libGameCore.so`, `libunity.so`)。 (Required: The name of a loaded module (e.g., `libGameCore.so`, `libunity.so`) in the target process where the chain search will begin.)
*   `-d <最大深度>`: (必需) 指针链的最大深度 (例如, 1 到 8)。这指的是应用偏移量的次数。深度为1表示 `模块某地址P1 -> read(P1)+偏移0 -> 目标地址`。 (Required: Maximum depth of the pointer chain (e.g., 1 to 8). This refers to the number of offsets applied. A depth of 1 means `AddressInModule (P1) -> read(P1)+offset0 -> target_address`.)
*   `-o <最小偏移>`: (必需) 在每个层级要测试的最小偏移量 (十六进制)。 (Required: Minimum offset in hex to test at each level.)
*   `-x <最大偏移>`: (必需) 在每个层级要测试的最大偏移量 (十六进制)。 (Required: Maximum offset in hex to test at each level.)
*   `-h`: 显示此帮助信息。 (Show this help message.)

### 示例 (Example):
查找进程1234中 `libGameCore.so` 模块内起始，最终指向地址 `0x7970437160`，最大深度为3层，每层偏移尝试范围从 `0x0` 到 `0x200` (步长为指针大小)的指针链:
(To find pointer chains in process 1234, starting in module `libGameCore.so`, leading to address `0x7970437160`, with a maximum depth of 3, and testing offsets from `0x0` to `0x200` (step size is pointer size) at each level:)
```bash
sudo ./chain_finder -p 1234 -a 0x7970437160 -m libGameCore.so -d 3 -o 0 -x 0x200
```

## 权限 (Permissions)
此程序读取其他进程的内存，需要特殊权限。您可能需要以root用户身份运行 (使用 `sudo`) 或授予可执行文件 `CAP_SYS_PTRACE` 权限。
(This program reads memory from another process, which requires special permissions. You will likely need to run it as root (using `sudo`) or grant the executable the `CAP_SYS_PTRACE` capability.)
例如 (e.g.): `sudo setcap cap_sys_ptrace=eip ./chain_finder`

## 输出格式 (Output Format)
程序将输出找到的指针链，格式如下:
(The program will output found pointer chains in the format:)
`<模块名>+<模块内基址偏移>+<偏移0>+<偏移1>...+<偏移N-1> -> <目标地址>`
( `<MODULE_NAME>+<BASE_OFFSET_IN_MODULE>+<OFFSET0>+<OFFSET1>...+<OFFSETN-1> -> <TARGET_ADDRESS>` )

其中:
*   `<模块名>`: 链起点的模块名。 (Module name where the chain starts.)
*   `<模块内基址偏移>`: 链的第一个指针地址相对于其所在模块段基地址的偏移。 (Offset of the first pointer in the chain relative to its module segment's base address.)
*   `<偏移X>`: 在该层级应用的偏移量。 (Offset applied at that level.)
*   `<目标地址>`: 用户提供的目标地址。 (The target address provided by the user.)

如果扫描在中间失败或未找到链，将显示错误或无结果的消息。
(If the scan fails or no chains are found, an error message or a no-results message will be displayed.)

## 注意事项 (Important Notes)
*   **性能 (Performance)**: 扫描指针链可能非常耗时，特别是当模块内存区域很大、偏移范围很宽或最大深度较深时。请谨慎设置扫描参数。 (Pointer chain scanning can be very time-consuming, especially with large module memory regions, wide offset ranges, or deep maximum depths. Set scan parameters carefully.)
*   **偏移步长 (Offset Step)**: 当前版本在递归扫描时，测试偏移量的步长默认为指针大小 (`sizeof(void*)`)。 (The current version tests offsets with a step of pointer size (`sizeof(void*)`) during recursive scanning.)
