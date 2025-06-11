#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>    // For getopt and process_vm_readv
#include <sys/uio.h>   // For process_vm_readv
#include <errno.h>     // For errno
#include <fcntl.h>     // For open
#include <ctype.h>     // For isspace, isxdigit

// --- 基本配置参数 ---
// (Basic Configuration Parameters)
#define MAX_CHAIN_DEPTH 8      // 允许的最大指针链深度 (Max allowed pointer chain depth)
#define MAX_MODULES_TO_SCAN 10 // 最多扫描的模块数量 (Max number of modules to scan)
#define MAX_RANGES_PER_MODULE 5 // 每个模块可能包含的内存段数量 (Max memory segments per module)

// --- 数据结构定义 ---
// (Data structure definitions)

// 目标信息 (Target Information)
typedef struct {
    int pid;                     // 目标进程ID (Target Process ID)
    uintptr_t target_address;    // 要查找的最终地址 (The final address to find)
} TargetInfo;

// 搜索空间定义 (Search Space Definition)
typedef struct {
    char module_name[256];      // 模块名 (Module name) - Should store base_module_name
    uintptr_t start_addr;       // 搜索区域的起始地址 (Start address of a search region)
    uintptr_t end_addr;         // 搜索区域的结束地址 (End address of a search region)
} SearchRegion;

typedef struct {
    SearchRegion regions[MAX_MODULES_TO_SCAN * MAX_RANGES_PER_MODULE]; // 搜索区域列表 (List of search regions)
    int count;                                                         // 区域数量 (Number of regions)
} SearchSpace;

// 扫描约束 (Scan Constraints)
typedef struct {
    int max_depth;               // 当前扫描允许的最大深度 (Max depth for the current scan)
    intptr_t min_offset;         // 要测试的最小偏移量 (Min offset value to test)
    intptr_t max_offset;         // 要测试的最大偏移量 (Max offset value to test)
} ScanConstraints;

// 找到的指针链信息 (Found Pointer Chain Information)
typedef struct {
    SearchRegion initial_base_region;
    uintptr_t base_address_in_region;
    intptr_t offsets[MAX_CHAIN_DEPTH];
    uintptr_t chain_links[MAX_CHAIN_DEPTH + 1];
    int depth;
} FoundChain;

// 存储找到的所有链 (To store all found chains)
typedef struct {
    FoundChain *chains;
    int count;
    int capacity;
} FoundChainList;

// --- 函数声明 ---
// (Function declarations)
void init_found_chain_list(FoundChainList *list, int initial_capacity);
void add_to_found_chain_list(FoundChainList *list, const FoundChain *chain);
void free_found_chain_list(FoundChainList *list);
int get_module_memory_ranges(int pid, const char *module_name_specifier, SearchSpace *search_space);
int read_memory_value_at(int pid, uintptr_t address, uintptr_t *value_read);
int is_valid_pointer_candidate(uintptr_t address_value, int pid);
void find_chains_recursive(const TargetInfo *target, const ScanConstraints *constraints, uintptr_t value_from_prev_deref, int current_depth_idx, FoundChain *current_chain_progress, FoundChainList *results);
void scan_memory_for_chain_starts(const TargetInfo *target, const SearchSpace *space, const ScanConstraints *constraints, FoundChainList *results);
void print_chain_final(const FoundChain *chain);
void print_usage(const char *prog_name);


// --- FoundChainList 辅助函数实现 ---
// (FoundChainList helper function implementations)
void init_found_chain_list(FoundChainList *list, int initial_capacity) {
    if (list == NULL) {
        fprintf(stderr, "错误: init_found_chain_list 收到空列表指针。\n");
        return;
    }
    if (initial_capacity <= 0) initial_capacity = 10;
    list->chains = (FoundChain *)malloc(initial_capacity * sizeof(FoundChain));
    if (list->chains == NULL) {
        perror("错误: 为 FoundChainList 分配内存失败");
        list->count = 0;
        list->capacity = 0;
        return;
    }
    list->count = 0;
    list->capacity = initial_capacity;
}

void add_to_found_chain_list(FoundChainList *list, const FoundChain *chain) {
    if (list == NULL || chain == NULL) {
        fprintf(stderr, "错误: add_to_found_chain_list 收到空指针。\n");
        return;
    }
    if (list->chains == NULL || list->capacity == 0) {
        init_found_chain_list(list, 10);
        if (list->chains == NULL || list->capacity == 0) {
            fprintf(stderr, "错误: FoundChainList 重新初始化失败。无法添加链。\n");
            return;
        }
    }
    if (list->count == list->capacity) {
        int new_capacity = list->capacity * 2;
        FoundChain *new_chains = (FoundChain *)realloc(list->chains, new_capacity * sizeof(FoundChain));
        if (new_chains == NULL) {
            perror("错误: 为 FoundChainList 扩展内存失败");
            return;
        }
        list->chains = new_chains;
        list->capacity = new_capacity;
    }
    list->chains[list->count++] = *chain;
}

void free_found_chain_list(FoundChainList *list) {
    if (list == NULL) return;
    if (list->chains != NULL) {
        free(list->chains);
        list->chains = NULL;
    }
    list->count = 0;
    list->capacity = 0;
}

// --- 核心功能函数实现 ---
// (Core function implementations)

// 获取模块的内存区域 (Get module memory ranges)
int get_module_memory_ranges(int pid, const char *module_name_specifier, SearchSpace *search_space) {
    char base_module_name_buffer[256];
    const char *name_to_search_in_maps;

    search_space->count = 0;

    printf("DEBUG_GMMR: Entered get_module_memory_ranges with pid=%d, module_name_specifier='%s'\n", pid, module_name_specifier);

    if (pid <= 0 || module_name_specifier == NULL || module_name_specifier[0] == '\0' || search_space == NULL) {
        fprintf(stderr, "错误(get_module_memory_ranges): 无效的参数 pid=%d, specifier=%p, space=%p。\n", pid, (void*)module_name_specifier, (void*)search_space);
        return -1;
    }

    const char *colon_ptr = strchr(module_name_specifier, ':');
    if (colon_ptr != NULL) {
        size_t length = colon_ptr - module_name_specifier;
        if (length < sizeof(base_module_name_buffer)) {
            strncpy(base_module_name_buffer, module_name_specifier, length);
            base_module_name_buffer[length] = '\0';
        } else {
            strncpy(base_module_name_buffer, module_name_specifier, sizeof(base_module_name_buffer) - 1);
            base_module_name_buffer[sizeof(base_module_name_buffer) - 1] = '\0';
            fprintf(stderr, "警告(get_module_memory_ranges): 基础模块名 '%s' 过长, 已截断为 '%s'\n", module_name_specifier, base_module_name_buffer);
        }
        name_to_search_in_maps = base_module_name_buffer;
    } else {
        strncpy(base_module_name_buffer, module_name_specifier, sizeof(base_module_name_buffer) - 1);
        base_module_name_buffer[sizeof(base_module_name_buffer) - 1] = '\0';
        name_to_search_in_maps = base_module_name_buffer;
    }
    printf("DEBUG_GMMR: Extracted name_to_search_in_maps='%s'\n", name_to_search_in_maps);

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("错误(get_module_memory_ranges): 打开maps文件失败");
        fprintf(stderr, "错误(get_module_memory_ranges): 无法打开 %s。PID %d 可能不存在或权限不足。\n", maps_path, pid);
        return -1;
    }

    char line_buffer[1024];
    unsigned long temp_start, temp_end;
    char perms[5];
    char path_from_maps[512];

    while (fgets(line_buffer, sizeof(line_buffer), maps_file)) {
        // Preliminary check on the raw line_buffer
        if (strstr(line_buffer, name_to_search_in_maps) != NULL) {
            printf("DEBUG_GMMR_MAPS_LINE: Candidate line: %s", line_buffer);

            path_from_maps[0] = '\0';
            perms[0] = '\0';
            temp_start = 0;
            temp_end = 0;

            int items_parsed = sscanf(line_buffer, "%lx-%lx %4s %*x %*s:%*s %*d %511[^\n]",
                                     &temp_start, &temp_end, perms, path_from_maps);

            if (items_parsed < 3) {
                char addr_str[64], perm_str_local[5], offset_str[64], dev_str[64], inode_str[64];
                path_from_maps[0] = '\0';
                int fallback_items_parsed = sscanf(line_buffer, "%s %4s %s %s %s %511[^\n]",
                                      addr_str, perm_str_local, offset_str, dev_str, inode_str, path_from_maps);
                if (fallback_items_parsed >= 2) {
                     sscanf(addr_str, "%lx-%lx", &temp_start, &temp_end);
                     strncpy(perms, perm_str_local, 4);
                     perms[4] = '\0';
                } else {
                    printf("DEBUG_GMMR_PARSE: Failed to parse addresses/perms from line (items_parsed=%d for primary, %d for fallback): %s", items_parsed, fallback_items_parsed, line_buffer);
                    continue;
                }
            }

            printf("DEBUG_GMMR_PARSE: Parsed: start=0x%lx, end=0x%lx, perms=%s, path_from_maps='%s'\n", temp_start, temp_end, perms, path_from_maps);

            if (strchr(perms, 'r') != NULL) {
                char *match_ptr = NULL;
                if (path_from_maps[0] != '\0') {
                    match_ptr = strstr(path_from_maps, name_to_search_in_maps);
                }

                if (match_ptr != NULL) {
                    size_t name_len = strlen(name_to_search_in_maps);
                    int is_standalone_match = 1;

                    if (match_ptr > path_from_maps) {
                        char char_before = *(match_ptr - 1);
                        if (char_before != '/' && char_before != ' ' && char_before != '-') {
                            is_standalone_match = 0;
                        }
                    }
                    if (is_standalone_match && *(match_ptr + name_len) != '\0' && *(match_ptr + name_len) != ' ' && *(match_ptr + name_len) != '.' && *(match_ptr + name_len) != ':') {
                         is_standalone_match = 0;
                    }

                    if (is_standalone_match) {
                        if (search_space->count < (MAX_MODULES_TO_SCAN * MAX_RANGES_PER_MODULE)) {
                            SearchRegion *region = &search_space->regions[search_space->count];
                            region->start_addr = (uintptr_t)temp_start;
                            region->end_addr = (uintptr_t)temp_end;
                            strncpy(region->module_name, name_to_search_in_maps, sizeof(region->module_name) - 1);
                            region->module_name[sizeof(region->module_name) - 1] = '\0';

                            printf("DEBUG_GMMR: ADDED region for '%s': start=0x%lx, end=0x%lx, perms=%s, full_path_from_maps='%s'\n",
                                   name_to_search_in_maps, (unsigned long)region->start_addr, (unsigned long)region->end_addr, perms, path_from_maps);
                            search_space->count++;
                        } else {
                            fprintf(stderr, "警告(get_module_memory_ranges): SearchSpace区域已满 (%d)，无法添加更多模块区域。\n", search_space->count);
                        }
                    } else {
                        printf("DEBUG_GMMR_STRSTR_FAIL_POST_PARSE: Parsed path '%s' contained '%s' but failed standalone validation.\n", path_from_maps, name_to_search_in_maps);
                    }
                } else {
                    printf("DEBUG_GMMR_STRSTR_FAIL_POST_PARSE: Parsed path '%s' did not contain '%s' or path was empty after parse.\n", path_from_maps, name_to_search_in_maps);
                }
            } else {
                printf("DEBUG_GMMR_NOT_READABLE: Region from candidate line not readable (perms: %s).\n", perms);
            }
        }
    } // End of while loop
    fclose(maps_file);

    if (search_space->count == 0) {
        printf("DEBUG_GMMR: Loop finished, no regions added for '%s' (specifier '%s'). search_space->count = %d\n",
               name_to_search_in_maps, module_name_specifier, search_space->count);
    }
    return 0;
}

// 读取进程内存中的一个指针大小的值 (Read a pointer-sized value from process memory)
int read_memory_value_at(int pid, uintptr_t address, uintptr_t *value_read) {
    if (value_read == NULL) {
        fprintf(stderr, "错误(read_memory_value_at): value_read 指针为空。\n");
        return -1;
    }

    struct iovec local_iov = { .iov_base = value_read, .iov_len = sizeof(uintptr_t) };
    struct iovec remote_iov = { .iov_base = (void *)address, .iov_len = sizeof(uintptr_t) };
    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

    if (bytes_read == -1) {
        fprintf(stderr, "错误(read_memory_value_at): process_vm_readv 读取地址 0x%lx (PID %d) 失败: %s (errno %d)\n",
                (unsigned long)address, pid, strerror(errno), errno);
        return -1;
    }
    if ((size_t)bytes_read < sizeof(uintptr_t)) {
        fprintf(stderr, "错误(read_memory_value_at): 读取不完整, 期望 %zu 字节, 实际读取 %zd 字节, 地址 0x%lx, PID %d\n",
                sizeof(uintptr_t), bytes_read, (unsigned long)address, pid);
        return -1;
    }
    return 0;
}

// 检查读取到的值是否可能是一个有效的用户空间指针
// (Checks if a read value is potentially a valid user-space pointer)
int is_valid_pointer_candidate(uintptr_t address_value, int pid __attribute__((unused)) ) {
    if (address_value == 0) return 0;
    if (address_value % sizeof(void*) != 0) return 0;
    if (address_value < 0x10000) return 0;
    if (address_value >= (uintptr_t)0x0000800000000000) return 0;
    return 1;
}

// --- 递归扫描函数 ---
// (Recursive scanning functions)
void find_chains_recursive(const TargetInfo *target, const ScanConstraints *constraints, uintptr_t value_from_prev_deref, int current_depth_idx, FoundChain *current_chain_progress, FoundChainList *results);

void scan_memory_for_chain_starts(const TargetInfo *target, const SearchSpace *space, const ScanConstraints *constraints, FoundChainList *results) {
    if (!target || !space || !constraints || !results) {
        fprintf(stderr, "错误(scan_memory_for_chain_starts): 无效的参数指针。\n");
        return;
    }
    printf("开始扫描内存区域以查找链起点 (%d 个区域)...\n", space->count);
    for (int i = 0; i < space->count; ++i) {
        const SearchRegion *region = &space->regions[i];
        printf("  正在扫描区域 %d/%d: %s (0x%lx - 0x%lx)\n",
               i + 1, space->count, region->module_name,
               (unsigned long)region->start_addr, (unsigned long)region->end_addr);

        for (uintptr_t current_addr = region->start_addr;
             current_addr <= region->end_addr - sizeof(uintptr_t) && current_addr < region->end_addr;
             current_addr += sizeof(uintptr_t)) {

            printf("DEBUG: scan_memory_for_chain_starts: Attempting to read initial pointer at address 0x%lx (Module: %s, Region Start: 0x%lx, Region End: 0x%lx)\n", (unsigned long)current_addr, region->module_name, (unsigned long)region->start_addr, (unsigned long)region->end_addr);

            uintptr_t pointer_candidate_value;
            if (read_memory_value_at(target->pid, current_addr, &pointer_candidate_value) != 0) {
                fprintf(stderr, "DEBUG: scan_memory_for_chain_starts: read_memory_value_at FAILED for initial pointer at 0x%lx.\n", (unsigned long)current_addr);
                continue;
            }

            printf("DEBUG: scan_memory_for_chain_starts: Read initial value 0x%lx from 0x%lx. Validating...\n", (unsigned long)pointer_candidate_value, (unsigned long)current_addr);
            if (!is_valid_pointer_candidate(pointer_candidate_value, target->pid)) {
                printf("DEBUG: scan_memory_for_chain_starts: Initial value 0x%lx from 0x%lx IS NOT a valid pointer candidate.\n", (unsigned long)pointer_candidate_value, (unsigned long)current_addr);
                continue;
            }

            FoundChain chain_prototype;
            memset(&chain_prototype, 0, sizeof(FoundChain));
            chain_prototype.initial_base_region = *region;
            chain_prototype.base_address_in_region = current_addr;
            chain_prototype.chain_links[0] = current_addr;

            printf("DEBUG: scan_memory_for_chain_starts: Calling find_chains_recursive with base_P1_addr=0x%lx, val_P1=0x%lx, depth_idx=0\n", (unsigned long)chain_prototype.chain_links[0], (unsigned long)pointer_candidate_value);
            find_chains_recursive(target, constraints, pointer_candidate_value, 0, &chain_prototype, results);
        }
    }
    printf("内存区域扫描完成。\n");
}

void find_chains_recursive(
    const TargetInfo *target,
    const ScanConstraints *constraints,
    uintptr_t value_from_prev_deref,
    int current_depth_idx,
    FoundChain *current_chain_progress,
    FoundChainList *results) {

    printf("DEBUG: find_chains_recursive: depth_idx=%d, value_from_prev_deref=0x%lx, current_chain_base_P1_addr=0x%lx\n", current_depth_idx, (unsigned long)value_from_prev_deref, (unsigned long)current_chain_progress->base_address_in_region);

    if (current_depth_idx >= constraints->max_depth) {
        return;
    }

    for (intptr_t offset_try = constraints->min_offset; offset_try <= constraints->max_offset; offset_try += sizeof(void*)) {
        printf("DEBUG: find_chains_recursive: depth_idx=%d, Trying offset 0x%lx (current range %ld to %ld)\n", current_depth_idx, (unsigned long)offset_try, (long)constraints->min_offset, (long)constraints->max_offset);

        uintptr_t next_address_to_read = value_from_prev_deref + offset_try;
        printf("DEBUG: find_chains_recursive: depth_idx=%d, Calculated next_address_to_read = 0x%lx (val_prev=0x%lx + off=0x%lx)\n", current_depth_idx, (unsigned long)next_address_to_read, (unsigned long)value_from_prev_deref, (unsigned long)offset_try);

        current_chain_progress->offsets[current_depth_idx] = offset_try;
        current_chain_progress->chain_links[current_depth_idx + 1] = next_address_to_read;

        if (next_address_to_read == target->target_address) {
            current_chain_progress->depth = current_depth_idx + 1;
            printf("DEBUG: find_chains_recursive: Target MATCH! next_address_to_read (0x%lx) == target_address (0x%lx)\n", (unsigned long)next_address_to_read, (unsigned long)target->target_address);
            add_to_found_chain_list(results, current_chain_progress);
        }

        if (current_depth_idx + 1 < constraints->max_depth) {
            if (!is_valid_pointer_candidate(next_address_to_read, target->pid)) {
                 continue;
            }
            uintptr_t value_at_next_address;
            if (read_memory_value_at(target->pid, next_address_to_read, &value_at_next_address) == 0) {
                if (is_valid_pointer_candidate(value_at_next_address, target->pid)) {
                    printf("DEBUG: find_chains_recursive: Preparing for RECURSIVE call. next_depth_idx=%d, next_value_from_deref=0x%lx (read from 0x%lx)\n", current_depth_idx + 1, (unsigned long)value_at_next_address, (unsigned long)next_address_to_read);
                    find_chains_recursive(target, constraints, value_at_next_address, current_depth_idx + 1, current_chain_progress, results);
                }
            } else {
                 fprintf(stderr, "DEBUG: find_chains_recursive: read_memory_value_at FAILED for next level pointer at 0x%lx. depth_idx=%d\n", (unsigned long)next_address_to_read, current_depth_idx);
            }
        }
    }
}

// --- 打印和用法函数 ---
// (Printing and Usage functions)
void print_chain_final(const FoundChain *chain) {
    if (chain == NULL || chain->depth <= 0 || chain->depth > MAX_CHAIN_DEPTH) {
        fprintf(stderr, "提示(print_chain_final): 无效的链或深度不符合预期(1-%d)。\n", MAX_CHAIN_DEPTH);
        return;
    }
    uintptr_t base_offset_in_module = chain->base_address_in_region - chain->initial_base_region.start_addr;
    printf("%s+0x%lx", chain->initial_base_region.module_name, (unsigned long)base_offset_in_module);
    for (int i = 0; i < chain->depth; ++i) {
        printf("+0x%lx", (unsigned long)chain->offsets[i]);
    }
    printf(" -> 0x%lx\n", (unsigned long)chain->chain_links[chain->depth]);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "用法: %s -p <pid> -a <目标十六进制地址> -m <模块名> -d <最大深度> -o <最小偏移hex> -x <最大偏移hex>\n", prog_name);
    fprintf(stderr, "  -p PID          目标进程的ID (Target process ID)\n");
    fprintf(stderr, "  -a TARGET_ADDR  要查找的最终十六进制地址 (Final hex address to find)\n");
    fprintf(stderr, "  -m MODULE_NAME  要在其中搜索链起点的模块名 (e.g., libname.so or libname.so:bss)\n");
    fprintf(stderr, "  -d MAX_DEPTH    指针链的最大深度 (Max depth of the pointer chain, e.g., 1 to %d)\n", MAX_CHAIN_DEPTH);
    fprintf(stderr, "  -o MIN_OFFSET   十六进制的最小偏移量 (Min offset in hex to test at each level)\n");
    fprintf(stderr, "  -x MAX_OFFSET   十六进制的最大偏移量 (Max offset in hex to test at each level)\n");
    fprintf(stderr, "  -h              显示此帮助信息 (Show this help message)\n");
    fprintf(stderr, "示例: %s -p 1234 -a 0x7970437160 -m libGameCore.so -d 3 -o 0 -x 0x200\n", prog_name);
}

// --- 主函数 ---
// (Main function)
int main(int argc, char *argv[]) {
    TargetInfo target;
    ScanConstraints constraints;
    char *module_arg = NULL;
    int opt;

    target.pid = -1;
    target.target_address = 0;
    int target_address_was_set = 0;
    constraints.max_depth = -1;
    constraints.min_offset = 0;
    constraints.max_offset = 0x1000;

    while ((opt = getopt(argc, argv, "p:a:m:d:o:x:h")) != -1) {
        switch (opt) {
            case 'p': target.pid = atoi(optarg); break;
            case 'a': target.target_address = strtoull(optarg, NULL, 16); target_address_was_set = 1; break;
            case 'm': module_arg = optarg; break;
            case 'd': constraints.max_depth = atoi(optarg); break;
            case 'o': constraints.min_offset = strtoll(optarg, NULL, 16); break;
            case 'x': constraints.max_offset = strtoll(optarg, NULL, 16); break;
            case 'h': print_usage(argv[0]); return EXIT_SUCCESS;
            default: print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (target.pid == -1) { fprintf(stderr, "错误: 必须提供PID (-p)。\n"); print_usage(argv[0]); return EXIT_FAILURE; }
    if (!target_address_was_set) { fprintf(stderr, "错误: 必须提供目标地址 (-a)。\n"); print_usage(argv[0]); return EXIT_FAILURE; }
    if (module_arg == NULL) { fprintf(stderr, "错误: 必须提供模块名 (-m)。\n"); print_usage(argv[0]); return EXIT_FAILURE; }
    if (constraints.max_depth == -1) { fprintf(stderr, "错误: 必须提供最大深度 (-d)。\n"); print_usage(argv[0]); return EXIT_FAILURE; }

    if (target.pid <= 0) { fprintf(stderr, "错误: 无效的PID: %d\n", target.pid); return EXIT_FAILURE; }
    if (constraints.max_depth <= 0 || constraints.max_depth > MAX_CHAIN_DEPTH) {
        fprintf(stderr, "错误: 最大深度必须在 1 到 %d 之间。提供的是: %d\n", MAX_CHAIN_DEPTH, constraints.max_depth); return EXIT_FAILURE;
    }
    if (constraints.min_offset > constraints.max_offset) {
        fprintf(stderr, "错误: 最小偏移量 (0x%lx) 不能大于最大偏移量 (0x%lx)。\n", (unsigned long)constraints.min_offset, (unsigned long)constraints.max_offset); return EXIT_FAILURE;
    }
    if (optind < argc) {
        fprintf(stderr, "错误: 发现额外的非选项参数: ");
        while (optind < argc) fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n"); print_usage(argv[0]); return EXIT_FAILURE;
    }

    printf("--- 配置信息 ---\n");
    printf("目标 PID: %d\n", target.pid);
    printf("目标地址: 0x%lx\n", (unsigned long)target.target_address);
    printf("扫描模块: %s\n", module_arg);
    printf("最大深度: %d\n", constraints.max_depth);
    printf("偏移范围: 0x%lx 到 0x%lx\n", (unsigned long)constraints.min_offset, (unsigned long)constraints.max_offset);
    printf("--- 开始初始化 ---\n");

    SearchSpace space;
    memset(&space, 0, sizeof(SearchSpace));

    FoundChainList results;
    init_found_chain_list(&results, 10);

    printf("正在获取模块 '%s' 的内存区域...\n", module_arg);
    if (get_module_memory_ranges(target.pid, module_arg, &space) != 0) {
        fprintf(stderr, "未能成功处理模块 '%s' 的内存区域信息。\n", module_arg);
    }

    if (space.count == 0) {
        fprintf(stderr, "错误: 未能找到模块 '%s' 的任何可读内存区域进行扫描。\n", module_arg);
        free_found_chain_list(&results);
        return EXIT_FAILURE;
    }
    printf("获取到 %d 个内存区域用于扫描。\n", space.count);
    for(int i=0; i<space.count; ++i) {
        printf("  区域 %d: %s (0x%lx - 0x%lx)\n", i, space.regions[i].module_name, (unsigned long)space.regions[i].start_addr, (unsigned long)space.regions[i].end_addr);
    }

    printf("--- 开始扫描指针链 (这可能需要很长时间!) ---\n");
    scan_memory_for_chain_starts(&target, &space, &constraints, &results);

    printf("--- 扫描完成 ---\n");
    printf("发现 %d 条可能的指针链:\n", results.count);
    if (results.count == 0) {
        printf("  未找到符合条件的指针链。\n");
    } else {
        for (int i = 0; i < results.count; ++i) {
            printf("链 %d: ", i + 1);
            print_chain_final(&results.chains[i]);
        }
    }

    free_found_chain_list(&results);
    printf("程序执行完毕。\n");
    return EXIT_SUCCESS;
}
