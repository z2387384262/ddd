#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // 用于 uintptr_t 和 intptr_t
#include <unistd.h> // 用于 getopt (如果使用) 和 process_vm_readv (虽然头文件是 sys/uio.h)
#include <sys/uio.h> // 用于 process_vm_readv
#include <errno.h>   // 用于 errno
#include <fcntl.h>   // 用于 open (在 find_module_base 中)

// 数据结构定义 (Data structure definitions)
typedef struct {
    char name[256];         // 模块名称 (Module name)
    uintptr_t base_address; // 模块基地址 (Module base address)
} ModuleInfo;

typedef struct {
    int depth;            // 扫描深度 (Scan depth)
    intptr_t offsets[10]; // 偏移量数组, 最多10层 (Offset array, max 10 levels)
} ScanParams;

typedef struct {
    uintptr_t addresses[10]; // 存储链中的解析地址 (Stores resolved addresses in the chain)
    int length;              // 链中地址的数量 (Number of addresses in the chain)
} PointerChain;

// 函数声明 (Function declarations)
int parse_arguments(int argc, char *argv[], int *pid_ptr, uintptr_t *base_address_ptr, ModuleInfo *module_info, ScanParams *scan_params);
int find_module_base(int pid, const char *module_name, uintptr_t *module_base);
int read_process_memory(int pid, uintptr_t address, void *buffer, size_t size);
void scan_pointer_chain(int pid, uintptr_t base_for_current_offset, int current_level_idx, const ScanParams *params, PointerChain *chain_output);
void print_pointer_chain(const PointerChain *chain, const ModuleInfo *module_info, uintptr_t initial_explicit_base, const ScanParams *params);

// 主函数 (Main function)
int main(int argc, char *argv[]) {
    int pid = -1; // 进程ID (Process ID)
    uintptr_t base_address = 0; // 用户提供的基地址 (User-provided base address)
    ModuleInfo module_info;     // 模块信息 (Module information)
    ScanParams scan_params;     // 扫描参数 (Scan parameters)
    PointerChain chain;         // 指针链结果 (Pointer chain result)

    // 初始化结构体 (Initialize structs)
    memset(&module_info, 0, sizeof(ModuleInfo));
    scan_params.depth = -1; // 初始深度设为-1, 表示未设置 (Initial depth set to -1, indicating not set)
    memset(scan_params.offsets, 0, sizeof(scan_params.offsets));
    memset(&chain, 0, sizeof(PointerChain));

    // 1. 解析命令行参数 (Parse command-line arguments)
    if (parse_arguments(argc, argv, &pid, &base_address, &module_info, &scan_params) != 0) {
        // parse_arguments 内部已打印错误信息和用法 (parse_arguments already prints error messages and usage)
        return 1;
    }

    uintptr_t initial_scan_address = base_address; // 用于扫描的初始地址 (Initial address for scanning)

    // 2. 如果提供了模块名, 查找模块基地址 (If module name provided, find module base address)
    if (strlen(module_info.name) > 0) {
        if (find_module_base(pid, module_info.name, &module_info.base_address) != 0) {
            fprintf(stderr, "错误: 无法找到模块 %s 在进程 %d 中的基地址。\n", module_info.name, pid);
            // 如果没有通过 -b 提供显式基地址, 则此错误是致命的 (If no explicit base address via -b, this is fatal)
            if (base_address == 0) return 1;
        } else {
            printf("信息: 模块 %s 的基地址: 0x%lx\n", module_info.name, (unsigned long)module_info.base_address);
            // 如果用户没有通过 -b 指定基地址, 则使用模块基地址 (If user didn't specify base_address via -b, use module base)
            if (base_address == 0) {
                initial_scan_address = module_info.base_address;
            } else {
                // 用户同时提供了模块名和显式基地址 (-b)
                // initial_scan_address 已经设置为 -b 的值
                // 打印提示信息 (Print a note)
                printf("注意: 同时提供了模块名和显式基地址 (-b)。将使用显式基地址 0x%lx 进行扫描的初始偏移计算。\n", (unsigned long)base_address);
            }
        }
    }

    // 再次检查 initial_scan_address 是否有效 (Re-check if initial_scan_address is valid)
    if (initial_scan_address == 0 && scan_params.depth > 0) {
        fprintf(stderr, "错误: 当扫描深度大于0时, 需要一个有效的基地址 (通过 -m 或 -b)。\n");
        return 1;
    }

    // 如果扫描深度为0, 不执行扫描 (If scan depth is 0, do not scan)
    if (scan_params.depth == 0) {
        printf("信息: 扫描深度为0, 不执行指针链扫描。\n");
        if (initial_scan_address != 0) {
             printf("信息: 初始基地址为: 0x%lx\n", (unsigned long)initial_scan_address);
        }
        printf("指针扫描器结束。\n");
        return 0;
    }

    printf("信息: 开始扫描进程 %d, 初始扫描地址 0x%lx, 深度 %d\n", pid, (unsigned long)initial_scan_address, scan_params.depth);

    // 3. 扫描指针链 (Scan for pointer chain)
    chain.length = 0; // 重置链长度 (Reset chain length)
    scan_pointer_chain(pid, initial_scan_address, 0, &scan_params, &chain);

    // 4. 打印找到的指针链 (Print the found pointer chain)
    // 即使链长度为0 (扫描失败), print_pointer_chain 也会处理 (Even if chain length is 0 (scan failed), print_pointer_chain will handle it)
    print_pointer_chain(&chain, &module_info, base_address, &scan_params);
    // base_address 传递的是用户通过 -b 指定的原始地址, 用于打印逻辑判断
    // module_info.base_address 包含的是解析后的模块基地址

    printf("指针扫描器结束。\n");
    return 0;
}

// 函数实现 (Function implementations)

// 解析命令行参数 (Parse command-line arguments)
int parse_arguments(int argc, char *argv[], int *pid_ptr, uintptr_t *base_address_ptr, ModuleInfo *module_info, ScanParams *scan_params) {
    *pid_ptr = -1; // 默认无效PID (Default invalid PID)
    scan_params->depth = -1; // -1 表示深度未由-d显式设置 (Indicates depth not explicitly set by -d)
    int offsets_count = 0;     // 解析到的偏移量数量 (Number of offsets parsed)
    int depth_explicitly_set = 0; // 标记深度是否由-d设置 (Flag if depth was set by -d)

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0) { // PID
            if (++i < argc) {
                *pid_ptr = atoi(argv[i]);
                if (*pid_ptr <= 0) {
                    fprintf(stderr, "错误: PID (-p) 必须是一个正整数。\n");
                    return 1;
                }
            } else { fprintf(stderr, "错误: -p 需要一个参数 (PID)。\n"); return 1; }
        } else if (strcmp(argv[i], "-m") == 0) { // 模块名 (Module name)
            if (++i < argc) {
                strncpy(module_info->name, argv[i], sizeof(module_info->name) - 1);
                module_info->name[sizeof(module_info->name) - 1] = '\0'; // 确保以null结尾 (Ensure null termination)
            } else { fprintf(stderr, "错误: -m 需要一个参数 (模块名)。\n"); return 1; }
        } else if (strcmp(argv[i], "-b") == 0) { // 基地址 (Base address)
            if (++i < argc) {
                *base_address_ptr = strtoull(argv[i], NULL, 16);
            } else { fprintf(stderr, "错误: -b 需要一个参数 (十六进制基地址)。\n"); return 1; }
        } else if (strcmp(argv[i], "-d") == 0) { // 扫描深度 (Scan depth)
            if (++i < argc) {
                scan_params->depth = atoi(argv[i]);
                depth_explicitly_set = 1;
                if (scan_params->depth < 0 || scan_params->depth > 10) { // 深度0是允许的 (Depth 0 is allowed)
                    fprintf(stderr, "错误: 扫描深度 (-d) 必须在 0 到 10 之间。\n");
                    return 1;
                }
            } else { fprintf(stderr, "错误: -d 需要一个参数 (扫描深度)。\n"); return 1; }
        } else if (strcmp(argv[i], "-o") == 0) { // 偏移量 (Offsets)
            if (++i < argc) {
                char *offsets_str_copy = strdup(argv[i]); // 复制字符串以供strtok使用 (Copy string for strtok)
                if (!offsets_str_copy) {
                    fprintf(stderr, "错误: 内存分配失败 (偏移量字符串)。\n");
                    return 1;
                }
                char *token;
                char *temp_str_ptr = offsets_str_copy;
                offsets_count = 0; // 重置当前-o参数的偏移量计数 (Reset offset count for current -o)
                while ((token = strtok(temp_str_ptr, ",")) != NULL && offsets_count < 10) {
                    scan_params->offsets[offsets_count++] = strtol(token, NULL, 16);
                    temp_str_ptr = NULL; // strtok后续调用需要NULL (Subsequent strtok calls need NULL)
                }
                free(offsets_str_copy); // 释放副本 (Free the copy)
            } else {
                fprintf(stderr, "错误: -o 需要一个参数 (偏移量列表, 例如: 0x10,0x20)。\n");
                return 1;
            }
        } else {
            fprintf(stderr, "错误: 未知选项: %s\n", argv[i]);
            fprintf(stderr, "用法: %s -p <pid> [-m <module_name> | -b <base_address_hex>] [-d <depth>] -o <offset1_hex[,offset2_hex,...]>\n", argv[0]);
            return 1;
        }
    }

    // 参数解析后的校验 (Validation after all arguments are parsed)
    if (*pid_ptr == -1) {
        fprintf(stderr, "错误: PID (-p) 是必需参数。\n"); return 1;
    }
    if (strlen(module_info->name) == 0 && *base_address_ptr == 0) {
        fprintf(stderr, "错误: 必须提供模块名 (-m) 或基地址 (-b)。\n"); return 1;
    }

    if (depth_explicitly_set) { // 如果用户用-d指定了深度 (If user specified depth with -d)
        if (scan_params->depth > 0 && offsets_count < scan_params->depth) {
            fprintf(stderr, "错误: 提供的偏移量数量 (%d) 少于指定的扫描深度 (%d)。\n", offsets_count, scan_params->depth);
            return 1;
        }
        if (scan_params->depth == 0 && offsets_count > 0) {
            // 警告: 深度为0但提供了偏移量, 偏移量将被忽略 (Warning: depth is 0 but offsets provided, offsets will be ignored)
            // 主函数中会处理这种情况 (Main function handles this)
            printf("警告: 扫描深度为0, 但提供了%d个偏移量。这些偏移量将被忽略。\n", offsets_count);
        }
    } else { // 如果用户没有用-d指定深度, 则从偏移量数量推断 (If user didn't specify depth, infer from offset count)
        scan_params->depth = offsets_count;
        if (scan_params->depth > 10) {
            fprintf(stderr, "错误: 偏移量数量 (%d) 超过了最大允许深度 (10)。\n", scan_params->depth);
            return 1;
        }
    }

    if (scan_params->depth < 0) { // 如果深度最终为负 (例如, 没有-d也没有-o)
        scan_params->depth = 0; // 默认为0 (Default to 0)
    }

    if (scan_params->depth > 0 && offsets_count == 0) {
        fprintf(stderr, "错误: 扫描深度为 %d 但没有提供偏移量 (-o)。\n", scan_params->depth);
        return 1;
    }


    return 0; // 成功 (Success)
}

// 查找模块基地址 (Find module base address) - Linux specific
int find_module_base(int pid, const char *module_name, uintptr_t *module_base) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid); // 构建maps文件路径 (Construct maps file path)

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("错误: 打开maps文件失败"); // (Error opening maps file)
        return -1;
    }

    char line_buffer[512];
    int found = 0;
    while (fgets(line_buffer, sizeof(line_buffer), maps_file)) {
        if (strstr(line_buffer, module_name)) { // 检查行中是否包含模块名 (Check if line contains module name)
            // 解析起始地址 (Parse start address)
            // 格式: address-range perms offset dev inode pathname
            // 例如: 7f7c8d400000-7f7c8d500000 r-xp ...
            if (sscanf(line_buffer, "%lx-%*lx", module_base) == 1) {
                found = 1;
                break; // 找到并解析成功 (Found and parsed successfully)
            }
        }
    }
    fclose(maps_file);

    if (!found) {
        fprintf(stderr, "错误: 未在进程 %d 的maps文件中找到模块 %s。\n", pid, module_name);
        return -1;
    }
    return 0; // 成功 (Success)
}

// 读取进程内存 (Read process memory) - Linux specific
// 注意: 此函数需要相应权限 (例如root或CAP_SYS_PTRACE) (Note: Requires permissions like root or CAP_SYS_PTRACE)
int read_process_memory(int pid, uintptr_t address, void *buffer, size_t size) {
    if (buffer == NULL || size == 0) {
        fprintf(stderr, "错误(read_process_memory): 无效的缓冲区或大小。\n");
        return -1;
    }

    struct iovec local_iov = { .iov_base = buffer, .iov_len = size };
    struct iovec remote_iov = { .iov_base = (void *)address, .iov_len = size };

    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

    if (bytes_read == -1) {
        //perror("错误(read_process_memory): process_vm_readv失败");
        fprintf(stderr, "错误(read_process_memory): process_vm_readv失败 读取地址 0x%lx 失败, PID %d: %s (errno %d)\n", (unsigned long)address, pid, strerror(errno), errno);
        return -1;
    }
    if ((size_t)bytes_read < size) {
        fprintf(stderr, "错误(read_process_memory): 读取不完整, 期望 %zu 字节, 实际读取 %zd 字节, 地址 0x%lx, PID %d\n",
                size, bytes_read, (unsigned long)address, pid);
        return -1; // 视为错误 (Considered an error)
    }
    return 0; // 成功 (Success)
}

// 递归扫描指针链 (Recursively scan pointer chain)
void scan_pointer_chain(int pid, uintptr_t base_for_current_offset, int current_level_idx, const ScanParams *params, PointerChain *chain_output) {
    // base_for_current_offset: 对于level 0, 这是模块基地址或用户指定的初始地址。对于后续level, 这是上一步读取到的指针值。
    // (For level 0, this is module base or user-specified initial addr. For subsequent levels, it's the pointer value read previously.)
    // current_level_idx: 当前偏移量在 params->offsets[] 中的索引, 从0到params->depth-1。
    // (Current index in params->offsets[], from 0 to params->depth-1.)

    if (chain_output->length >= 10) { // 防止超出数组界限 (Prevent exceeding array bounds)
        fprintf(stderr, "警告: 指针链达到最大存储长度(10), 停止扫描。\n");
        return;
    }

    // 1. 计算当前层级的目标地址 (Calculate target address for the current level)
    uintptr_t current_target_address = base_for_current_offset + params->offsets[current_level_idx];
    //printf("调试: 层级 %d, 基址 0x%lx, 偏移 0x%lx, 目标地址 0x%lx\n", current_level_idx, base_for_current_offset, params->offsets[current_level_idx], current_target_address);


    // 2. 将目标地址存入链中 (Store target address in the chain)
    chain_output->addresses[chain_output->length] = current_target_address;
    chain_output->length++;

    // 3. 递归基本情况: 如果这是最后一个偏移量, 链已形成 (Base case: if this is the last offset, chain is formed)
    if (current_level_idx == params->depth - 1) {
        //printf("调试: 达到最大深度 %d, 链构建完成。\n", params->depth);
        return;
    }

    // 4. 读取下一个指针值 (Read the next pointer value from current_target_address)
    uintptr_t next_base_for_offset; // 这个值将作为下一层计算偏移量的基址 (This value will be the base for next level's offset calculation)
    if (read_process_memory(pid, current_target_address, &next_base_for_offset, sizeof(next_base_for_offset)) != 0) {
        fprintf(stderr, "错误: 在扫描链的层级 %d 时, 读取地址 0x%lx 失败。\n", current_level_idx, (unsigned long)current_target_address);
        chain_output->length = 0; // 标记链无效 (Mark chain as invalid)
        return;
    }
    //printf("调试: 层级 %d, 从 0x%lx 读取到值: 0x%lx\n", current_level_idx, current_target_address, next_base_for_offset);


    // 5. 递归调用下一层 (Recursive call for the next level)
    scan_pointer_chain(pid, next_base_for_offset, current_level_idx + 1, params, chain_output);
}

// 打印指针链 (Print pointer chain)
void print_pointer_chain(const PointerChain *chain, const ModuleInfo *module_info, uintptr_t initial_user_base, const ScanParams *params) {
    // initial_user_base 是用户通过 -b 提供的原始基地址。如果为0, 表示用户没有使用-b。
    // (initial_user_base is the raw base address provided by user via -b. If 0, user didn't use -b.)
    // module_info->base_address 是解析后的模块基地址 (module_info->base_address is the resolved module base address)
    // params->offsets[0] 是第一个应用的偏移量 (params->offsets[0] is the first applied offset)

    if (chain->length == 0) {
        printf("结果: 未找到有效的指针链或扫描失败。\n"); // (Result: No valid pointer chain found or scan failed.)
        return;
    }

    if (chain->length != params->depth) {
        printf("结果: 指针链不完整 (期望深度 %d, 实际解析 %d 层)。链可能在中间断开。\n", params->depth, chain->length);
         // 仍然打印部分链 (Still print the partial chain)
    } else {
        printf("结果: 成功找到指针链！\n"); // (Result: Pointer chain found successfully!)
    }

    // 确定起始部分的显示: 模块名还是十六进制地址
    // (Determine display for the starting part: module name or hex address)
    int use_module_name = 0;
    if (strlen(module_info->name) > 0) {
        // 如果 initial_user_base 为0 (用户未指定-b), 或者 initial_user_base 与模块基地址相同,
        // 并且第一个偏移量是应用于这个模块基地址的, 那么使用模块名。
        // (If initial_user_base is 0 (user didn't specify -b), OR initial_user_base is same as module base,
        //  AND the first offset was applied to this module base, then use module name.)

        // 简化逻辑: 如果模块名存在, 并且用户没有通过 -b 提供一个 *不同* 的地址作为最优先的起始点, 则使用模块名。
        // (Simplified logic: if module name exists, and user didn't provide a *different* address via -b as the primary start, use module name)
        if (initial_user_base == 0 || initial_user_base == module_info->base_address) {
             use_module_name = 1;
        }
    }


    if (use_module_name) {
        printf("%s", module_info->name);
    } else {
        // 如果使用-b指定了地址, 或者无法确定模块名, 则打印第一个偏移量所基于的地址
        // (If -b was used, or module name cannot be determined, print the address first offset was based on)
        // 这个地址是 scan_pointer_chain 的 initial_scan_address, 也就是 main 函数中的 initial_scan_address
        // 它等于 initial_user_base (如果-b) 或 module_info->base_address (如果-m且无-b)
        uintptr_t display_base;
        if (initial_user_base != 0) {
            display_base = initial_user_base; // 用户通过-b提供的地址
        } else {
            display_base = module_info->base_address; // 模块基地址
        }
        printf("0x%lx", (unsigned long)display_base);
    }

    // 打印所有实际构成链的偏移量和最终地址 (Print all offsets that formed the chain and the final address)
    for (int i = 0; i < chain->length; ++i) {
        // params->offsets[i] 是用来计算 chain->addresses[i] 的那个偏移量
        // (params->offsets[i] is the offset used to calculate chain->addresses[i])
        printf("+0x%lx", (unsigned long)params->offsets[i]);
    }

    if (chain->length > 0) {
        printf(" = 0x%lx\n", (unsigned long)chain->addresses[chain->length - 1]);
    } else {
        printf("\n"); // 如果链长度为0, 仅换行 (If chain length is 0, just newline)
    }
}
