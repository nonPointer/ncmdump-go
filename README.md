# ncmdump (Go) — 单二进制 / 跨平台 / 并行 / 硬件加速

把目录下所有 `.ncm` 文件并行解密还原为 `.mp3` / `.flac`,纯 Go 标准库实现,**无任何外部依赖**,编译出来是一个静态单文件。

## 为什么是 Go

在 M1 Pro 上对同一首 22.4 MB 音频做解密循环基准:

| 实现 | 吞吐 | 相对 vanilla Python |
|------|------|------|
| vanilla Python(逐字节) | 9 MB/s | 1× |
| numpy(pad+向量化) | 2610 MB/s | 288× |
| Go(pad+字 XOR) | 1814 MB/s | 200× |
| Rust(pad+字 XOR) | 1885 MB/s | 208× |

关键结论:**加速来自算法(预计算 256 字节周期 keystream)+ 向量化 XOR,而非语言**。单文件已快到 ~20ms,真正瓶颈在 I/O 与"多文件",所以选了跨文件并行 + 易分发单二进制的 Go。

## 硬件加速点

- keystream 周期为 256,启动时一次性预计算成 `pad[256]`;
- 解密用 `uint64` 宽字 XOR(`decryptChunk`),编译器自动向量化(M1 上走 NEON);
- 跨文件用 goroutine 工作池并行(默认 = CPU 核数)。

## 构建

```bash
go build -ldflags="-s -w" -o ncmdump .     # 当前平台
bash build.sh                              # 交叉编译到 dist/ 全平台
```

## 使用

```bash
./ncmdump -dir /path/to/music          # 解密该目录(含子目录)所有 .ncm
./ncmdump /path/to/music               # 位置参数等价写法
```

常用 flag:

| flag | 默认 | 说明 |
|------|------|------|
| `-dir` | `.` | 扫描目录(递归) |
| `-workers` | CPU 核数 | 并行 worker 数 |
| `-log` | `<dir>/ncmdump.log` | 日志文件路径 |
| `-delete-src` | false | 解密成功后删除源 `.ncm` |
| `-delete-lq` | false | 已存在低音质版本时删除并重新解密 |
| `-dedup-apply` | false | 实际删除重复文件(默认仅在日志里报告) |

## 行为说明

- **日志**:每个文件的结果(ok/skip/err、耗时、吞吐)同时打到 stdout 和日志文件。
- **重复比较**:
  - 解密前若已存在同名 `.mp3`/`.flac`,按 `输出体积 / ncm 体积` 比值判断:`< 0.8` 视为低音质(可配合 `-delete-lq` 覆盖),否则视为已有等质量输出并跳过;
  - 解密后扫描 `曲名 (N).flac|mp3` 形式的副本,与原曲体积一致则判为重复(`-dedup-apply` 时删除,否则仅报告)。
- **破坏性操作默认关闭**:`-delete-src` / `-delete-lq` / `-dedup-apply` 都需显式开启(与原 `ncmdump.py` 默认删源的行为不同)。

## 致谢

本实现(算法分析、并行架构、跨平台构建与全套测试)由 **Anthropic Claude Opus 4.8** 协助完成。
