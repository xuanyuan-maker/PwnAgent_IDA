# PWN 分析报告

- 任务ID：`quick-20260322-104432-ac3a`
- 二进制：`Z:\home\xuanyuan\Ws\ccb\work\pwn2\catchme`
- IDB：`Z:\home\xuanyuan\Ws\ccb\work\pwn2\catchme.i64`
- 模型：`deepseek-r1:14b`

## 最可疑位置
在 `engrave` 函数中，调用了 `read(0, (void *)(v2 + 8), 0x18uLL)`，其中 `v2` 是从内存地址 `qword_202060[v1]` 获取的值。这个调用直接将用户输入写入到内存地址 `v2 + 8` 的位置，而没有对输入长度进行任何限制或检查。

## 疑似漏洞类型
堆溢出漏洞

## 漏洞函数
- engrave

## 漏洞位置
- `engrave` @ `0xf4f`（伪代码）：__int64 engrave() { unsigned int v1; // [rsp+4h] [rbp-1Ch] __int64 v2; // [rsp+8h] [rbp-18h] char nptr[8]; // [rsp+10h] [rbp-10h] BYREF unsigned __int64 v4; // [rsp+18h] [rbp-8h] v4 = __readfsqword(0x28u); if ( dword_202 ...

## 根因定位
函数 `engrave` 在调用 `read` 时，直接将用户输入写入到内存地址 `v2 + 8` 的位置。虽然 `read` 调用指定了读取长度为 `0x18uLL`，但没有检查目标内存块的大小是否足够容纳这个数据量。如果 `v2` 对应的内存块（例如通过 `malloc` 分配）小于 `0x18` 字节，则会导致堆溢出。

## 触发条件
当用户选择一个较小的生物类型（如选项 3，分配了 `0x48uLL` 的内存块），并在调用 `engrave` 时输入超过 `0x18` 字节的数据时，将触发该漏洞。

## 调用树分析顺序
- sub_A81
- add
- dele
- inspect
- engrave
- purge
- main

## 函数级分析摘要
- （无）

## 语义化改名建议
- （无）

## 关键证据
- `engrave` 函数中调用了 `read(0, (void *)(v2 + 8), 0x18uLL)`。
- `add` 函数为不同生物类型分配了不同的内存块大小：`malloc(0x430uLL)`、`malloc(0x440uLL)` 和 `calloc(1uLL, 0x48uLL)`。

## 影响评估
攻击者可以利用此漏洞通过提供超长输入数据来破坏堆内存，导致程序崩溃或执行任意代码。

## 误报风险
中

## 修复建议
在调用 `read` 前，检查目标内存块的剩余空间是否足够容纳要写入的数据，并添加相应的边界检查。

## 最小修复方案
在 `engrave` 函数中，添加对目标内存块大小的检查：

```c
if (qword_202060[v1] + 8 + 0x18 > allocated_size) {
    puts("invalid operation");
    return 0xFFFFFFFFLL;
}
```

## 人工复核清单
- 检查 `engrave` 函数中所有内存分配的大小。
- 确保在调用 `read` 前，目标内存块有足够的空间容纳写入的数据。

## 多模型一致性
- 漏洞类型一致：`True`
- 风险评级一致：`True`
