# 生态扫描：DSH 插件体检快照

> 由 **dsh-sentinel** 对公开插件仓库做只读静态扫描。命中表示需要人工复核，
> 不是恶意软件判定，也不构成对项目安全性的保证。

## 方法

- 语料是 6 个固定 commit 的完整浅克隆，不再使用旧版 CDN 零散文件快照。
- 克隆过程禁用子模块和 Git LFS 下载，不执行 `npm install`、生命周期脚本、构建、模块导入或插件代码。
- 每个仓库先验证 `package.json` 和真实源码，再进入扫描；HTML/CDN 错误正文会被拒绝。
- 测试与开发工具中的命中完整展示，但各自最多贡献 20 风险分；运行入口可达的测试文件仍按 source 全额计分。
- 复现：`node scripts/fetch-corpus.mjs && node scripts/scan-corpus.mjs && node scripts/write-corpus-manifest.mjs`

固定 commit 与仓库计数见 [`benchmarks/public-corpus-manifest.json`](benchmarks/public-corpus-manifest.json)。

## 结果一览

以下结果来自 2026-08-21 的本地复现，6/6 扫描均为 `scanComplete=true`。

| 插件 | 裁决 | 分 | 命中 | source / test / dev |
| --- | --- | ---: | ---: | ---: |
| `@anionex/dsh-vision-toolkit` | dangerous | 100 | 80 | 59 / 21 / 0 |
| `dsh-remote` | dangerous | 100 | 62 | 54 / 3 / 5 |
| `@anionex/dsh-turn-rewind` | risky | 76 | 15 | 7 / 8 / 0 |
| `@liustack/modlens` | risky | 70 | 48 | 5 / 35 / 8 |
| `@anysearch/anysearch-dsh` | risky | 59 | 10 | 3 / 4 / 3 |
| `ax-feishu-bridge` | risky | 51 | 7 | 6 / 1 / 0 |

高分插件中可见运行时安装、更新、命令执行、动态解码执行、任意路径读写或凭据处理等能力面，必须结合具体代码和产品用途人工审阅。`modlens` 等测试较多的仓库不会再因测试夹具无限累加到 100，但其 source 与开发工具证据仍保留在报告中。

## 已知边界

- TypeScript 当前采用保守降级：模块图恢复静态 import/export/require，节点标记为 `parser: unparsed` 并给出 warning，不因 Acorn 无法解析类型语法而把扫描判为 incomplete。
- 辅助层（依赖图、SBOM、provenance、能力图）失败会报告 warning；核心文件遍历、读取、模块图路径逃逸与跨文件分析失败仍会影响完整性。
- 风险分用于排序人工复核优先级，不能替代沙箱、签名、来源验证、动态行为分析或人工代码审计。
