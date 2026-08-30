# 架构 / Architecture

dsh-sentinel 是 **DeepSeek Harness 插件供应链 + Agent Tool 静态安全审计器**。
本文描述 v2 轮升级后的代码结构与核心不变式。

## 0. 定位与红线

- 只读静态分析:绝不 `require/import/eval/spawn` 被扫描代码,绝不执行
  preinstall/install/postinstall/prepare 等生命周期脚本
- 安装前审计:下载 tarball → 隔离 quarantine → 安全解包 → 静态扫描 → 删除,
  全程不执行 `npm install`
- 新联网能力默认关闭(`--advisories` 才查询 OSV,仅上传包名+版本)
- 不把源码上传任何第三方;git push 只到自有仓库
- SARIF / GitHub Action / HTML 只是"结果标准化 / 自动化 / 展示",
  不是检测能力本身

## 1. 目录结构

```text
bin/sentinel.mjs           CLI:配置合并(CLI > config)、输出(json/sarif/html/text)、
                           退出码(0/1/2/3)、--fail-on、--redact-paths
engine/
  index.js                 public API:scan() / scanProfile() / audit*() / computeRuntimeEntries()
  scanner.js               文件遍历、collectFiles、applyRule(行去重+exclude+comment)、
                           FindingCollector(评分统计)、FindingBuffer(优先级有界缓冲)、
                           hardSkipped metadata、binary audit 编排
  rules.js                 规则目录(唯一 severity 权重来源 SEVERITY_WEIGHT)
  report.js                buildReport:schema v2、评分(基于 allStats)、裁决、
                           overlap suppression、secret 脱敏、ignored/hardSkipped
  manifest.js              DSH bundle 清单检查(patch/main/exports/入口契约)
  path-safety.js           词法 containment + realpath containment + symlink 防护
  redact.js                secret 脱敏(永远开启)
  config.js                sentinel.config.json 加载与 CLI 覆盖
  semantic/
    ast.js                 acorn 解析(含 vendored 回退)+ callee/别名/常量拼接
    taint.js               AST 污点流:source → propagation → sink,跨函数 MVP
    harness.js             defineTool 识别、SSRF 细化、prompt 投毒分级、能力不匹配证据
    module-graph.js        有界 JS/TS 模块图、扩展名回退、containment 与 warning/failure
    cross-file-taint.js    基于模块图的有界跨文件 source → sink 分析与攻击链
    capability-graph.js    从 finding 归一化工具能力与策略不匹配
    index.js               语义入口 + 正则兜底
  package/
    audit.js               安装前审计 API(auditPackageBeforeInstall)
    acquire.js             npm 元数据获取(参数数组 spawn,无 shell 拼接)
    tarball.js             tarball 下载 + integrity + 隔离解包
    tar.js                 自包含安全 tar 解析(traversal/symlink/bomb 防护)
    diff.js                源码 ↔ 发布包漂移(SEN-SUPPLY-003)
  binary/
    inspect.js             magic/kind/可疑字符串
    strings.js             printable strings 提取
    entropy.js             Shannon entropy
  supplychain/
    lockfile.js            lockfile 识别与依赖统计
    dependency-graph.js    package-lock 标准化依赖节点/边;其他格式显式降级
    sbom.js                CycloneDX 1.6 / SPDX 2.3 确定性序列化
    provenance.js          metadata-only provenance 证据校验
    osv.js                 OSV 查询(默认关闭)
  output/
    sarif.js               SARIF 2.1.0(相对路径、稳定指纹)
    html.js                单文件 HTML 报告
  report/fingerprint.js    稳定指纹 + baseline 对比
plugin/index.js            DSH 插件入口:sentinel_scan / sentinel_scan_profile /
                           sentinel_audit_package
scripts/                   benchmark(rule/finding/flow 三级)、规则文档生成、demo
action.yml                 根 GitHub Action(composite;vendored acorn 在
                           .github/actions/dsh-sentinel/vendor/)
```

## 2. 扫描流水线

```text
目标路径
  ↓
collectFiles(模式感知跳过 / ignore glob / 大文件 / 二进制 / hardMax 分类)
  ↓
逐文件:
  regex fast pass(applyRule:行去重 → excludes → comment → total++)
  semantic deep pass(AST 污点 + Harness 专属,失败时正则兜底)
  → FindingCollector:全量统计(allStats)+ 优先级有界缓冲(展示)
  → finalizeFile:同源重叠抑制标记(suppressedForScore)+ 精确 rawScore
  ↓
可执行二进制 metadata audit(SEN-BIN-*/SEN-WASM-*)
  ↓
hardSkipped(>20MB)metadata:path/size/sha256/extension/分类/采样信号 → scanComplete=false
  ↓
manifest 检查(inspectBundle:patch/main/exports/入口契约,全部路径走 containment)
  ↓
buildReport:score 基于全部有效命中(allStats)、裁决、排序截断、脱敏、fingerprint
```

## 3. 评分与展示解耦(P0-1)

```text
recordFinding(f):
  allStats.bySeverity/category/context/findingCount  ← 全量
  rawScore                                           ← 全部有效命中(降权后)加权和
  FindingBuffer.add(f)                               ← 最多 maxFindings 条,按
                                                        critical>high>medium>low>info
                                                        优先级淘汰,永不丢 critical/high
```

- `summary.findingsTotal` = 全部有效命中数(与评分一致)
- `summary.findingsReturned` = 报告实际条数
- `summary.scoreBasedOnAllFindings` = true
- minified/bundle 只打 `bundleFile` evidence 标记,绝不自动降 severity;
  置信度由检测方式决定(regex-only → medium,AST/taint → high)

## 4. 完整性契约

任何截断必须可见且影响裁决:

| 情况 | 处理 |
| --- | --- |
| maxFiles 截断 | scanComplete=false + INCOMPLETE 标记 + 裁决 ≥ review |
| > hardMaxBytesPerFile | 记录 metadata + scanComplete=false |
| 可执行二进制超审计上限 | binarySkippedFiles > 0 → scanComplete=false |
| maxPlugins 截断 | pluginsSkipped{reason:maxPlugins-limit} + scanComplete=false |
| trusted-scope / self / not-a-dsh-plugin | policySkips(策略性跳过,默认不算 incomplete) |
| ignore glob | 进入 report.ignored[{pattern,count}],绝不静默忽略 |

## 5. Profile 插件发现(§11)

```text
profile package.json direct dependencies
  + dsh.profile manifest bundles
  + cordis.patch 引用的包
  + 回退:node_modules 中声明 dsh.bundle 的候选
  ↓
依赖图(深度受限)划分角色:
  direct-plugin / direct-dependency   → 全量扫描 + manifest 规则(仅插件)
  transitive-dependency               → metadata audit(仅 install/supplychain 规则,
                                         不产生 SEN-MAN-002 等误报)
```

## 6. 语义能力边界

支持(confidence high,AST):
- `defineTool` `execute(args)` 内 `args.* → shell/fs/network`
- 别名(`const {exec: run} = require('child_process')`)、多步变量传播、跨函数 MVP
- 计算属性(`cp['ex'+'ec']`、`process.env['OPEN'+'AI_API_KEY']`)、optional chaining
- env 凭据 → 网络(SEN-TAINT-001,受信端点豁免)
- 文件读取/记忆 → 网络(SEN-TAINT-002)、解码 → 执行(SEN-TAINT-003)
- SSRF 目标细化:云元数据端点 → critical
- 有界跨文件污点流:ESM 与可静态证明的 CommonJS `require` / `require.resolve` 图上的参数传递与攻击链聚合
- CommonJS 解构导入(`const {run} = require('./runner')`)到 `exports.run` / `module.exports.run` 的函数或箭头函数跨文件 source → sink 追踪
- TypeScript `.js` specifier → `.ts/.tsx/.mts/.cts` 源文件回退;声明文件与开发入口降级为 warning

不支持(已知限制):
- 运行时才能确定目标的动态 import/require、复杂回调/闭包捕获/原型链的完整跨文件传播;动态目标会显式记录 warning,不会猜测边
- 完整 TypeScript 类型语法 AST;超出 Acorn 能力时使用静态 import/export/require 降级
- 非 JS 语言的语义(走正则)

## 7. 供应链审计

- tarball 安全解包:拒绝 `../`、绝对路径、盘符、symlink/hardlink 条目;
  限制条目数 20000 / 解压总量 300MB / 单文件 50MB / 路径 1024 / 深度 32
- integrity:sha512 base64 与实际 tarball 比对;不匹配 → SEN-SUPPLY-004 + 至少 REVIEW
- 解包被阻止 → SEN-SUPPLY-005 + BLOCK-RECOMMENDED + scanComplete=false
- quarantine 目录在任何 success/failure/exception 路径都 finally cleanup
- lockfile 识别(package-lock/shrinkwrap/pnpm/yarn/bun)+ 依赖统计; npm 与 pnpm v9 使用规范化图,
  pnpm v9 解析 `importers/packages/snapshots`、workspace containment、peer-suffixed 实例和
  `requiresBuild` 证据路径; malformed/escape/unresolved/unsupported/oversized 输入显式降级,
  不猜测 direct/transitive 数量; yarn/bun 当前仅识别并报告 unsupported/degraded

## 8. 报告 schema v2

```json
{
  "schemaVersion": 2,
  "summary": { "verdict", "score", "scanComplete", "filesDiscovered",
               "filesAnalyzed", "findingsTotal", "findingsReturned",
               "findingsTruncated", "scoreBasedOnAllFindings" },
  "scanCoverage": { "sourceFiles", "buildFiles", "binaryFiles", "largeFiles",
                    "parseFailures", "hardSkippedFiles", "binarySkippedFiles" },
  "findings": [], "attackChains": [], "supplyChain": {},
  "ignored": [], "hardSkipped": [], "policySkips": [], "coverageSkips": []
}
```
