# Changelog

## Unreleased

### Added

- 独立 CodeQL 工作流覆盖自扫描必须排除的规则引擎源码。
- Dependabot、CODEOWNERS、贡献指南、行为准则，以及结构化 Issue / Pull Request 模板。
- 静态 CommonJS `require` / `require.resolve` 模块图边，以及 CommonJS 解构导入到导出函数/箭头函数的跨文件污点链。
- pnpm v9 `importers` / `packages` / `snapshots` 规范化依赖图、workspace containment、peer 实例保留、`requiresBuild` 证据链和 CycloneDX / SPDX 组件引用。

### Changed

- CI 改为执行 `package.json` 中的完整测试契约，并升级到 Node 24 运行时的官方 Actions。
- 仓库递归自扫描显式报告 `engine/**`、`test/**`、`scripts/**` 排除范围；核心引擎改由 CodeQL 独立覆盖。
- 动态模块目标现在作为结构化 warning 报告，不再静默忽略或猜测依赖边；TypeScript fallback 可恢复字面量 CommonJS 引用。
- pnpm v9 direct/transitive 依赖统计改为读取规范化图；图失败时返回零计数和显式不完整原因，不再使用缩进正则猜测。

### Fixed

- 避免将能力说明中的 `exfiltration endpoints` 名词短语误判为提示注入。
- 支持带安全 options 参数的 `spawn` / `execFile` 调用，但 `shell` 选项仍保持告警。
- 仅对明确的开发/语料脚本降权；未知 `scripts/**` 文件继续按运行时源码计分。
- ignore 报告区分匹配条目和被剪枝目录，不再把未遍历目录误称为已统计文件。
- 本地 `.worktrees/` 作为 Git 工作树元数据目录跳过，避免把并行检出重复当作目标源码。
- CodeQL 明确覆盖 `engine` / `plugin` / `bin` 发布面；测试语料不再混入核心代码告警。
- 重写不受信源码的 child-process 别名提取、patch 行解析和开发 runner 识别，消除多项 polynomial ReDoS 路径；动态别名进入正则前执行完整元字符转义。
- malformed pnpm YAML、workspace importer 路径逃逸、oversized lockfile 和未知 pnpm 版本均保留明确 dependency-layer failure；`requiresBuild` 不再被误称为已知安装脚本。

## 0.4.4 (2026-08-23) — Professional Scanner Release

### Added

- 有界 JS/TS 模块图、跨文件污点分析与攻击链聚合。
- 标准化 npm 依赖图、CycloneDX 1.6 / SPDX 2.3 SBOM、能力图与 provenance 报告层。
- 真实 DSH corpus 固定 commit 浅克隆验证,不安装依赖、不执行第三方代码。

### Changed

- SBOM 默认工具版本改为统一 `VERSION` 来源,不再错误输出未来版本 `0.5.0`。
- README 改为完整英文优先、完整中文随后;同步 SECURITY、architecture、roadmap 与示例报告。
- 测试扩展至 200 项;保留 32 项 rule/finding/flow benchmark。

### Fixed

- TypeScript/TSX/MTS/CTS 模块图使用静态 import/export 降级，不再因 Acorn 的 TS 能力边界把完整扫描误判为 incomplete；补齐 `.js` 到 TS 源文件的解析回退。
- 非 JS/TS 文件不再进入模块图；声明文件、测试与显式开发 runner 的缺失构建产物改为 warning，路径逃逸和核心读取失败仍保持 incomplete。
- 依赖图、SBOM、provenance、能力图失败作为辅助层 warning，不再覆盖核心扫描完整性。
- 支持默认导出的 Cordis service class 与 `export async function apply` 入口契约。
- finding 指纹加入稳定代码锚点和重复序号，避免同文件同规则独立调用点碰撞；SARIF 复用报告指纹。
- 测试与开发上下文分别封顶 20 风险分，低置信度证据再降一级计分；安装脚本和运行入口可达文件仍全额计分。
- 注释不再触发 `SEN-EXFIL-002`，特殊用途/私有 IPv4 不再误报为公网硬编码地址。
- 真实语料改为固定 commit 的完整浅克隆并拒绝 CDN/HTML 错误正文，不安装依赖、不执行第三方代码。
- CI 路径与 tar 测试改为跨平台；仓库自扫描使用 PR 当前 Action，并显式忽略规则目录和恶意测试夹具。

### Verification

- 200 项测试全绿；32 项 benchmark：rule F1 0.976、finding F1 0.957、flow F1 1.000。
- 6 个固定 commit 的真实 DSH 插件仓库全部 `scanComplete=true`。

## 0.4.3 (2026-08) — 文档同步

- README / roadmap / submission-awesome 同步至 v0.4.2 状态:151 项测试、32 项 benchmark 语料(edge 16 项)、standalone 文案(移除 zero-dependency)
- docs/example-report.json 按当前引擎重新生成
- 无代码/规则变更;版本 bump 仅为让 npm 包内 README 与仓库一致

## 0.4.2 (2026-08) — Final 3 Blockers Fix

按 `dsh-sentinel-v0.4-final-3-blockers-fix.md` 完成最后 3 个发布阻塞项修复:

### Fixed
- **Action 依赖安装边界(P0-1)**:npm ci 定向 `--prefix ${{ github.action_path }}` 并强制
  `--ignore-scripts`;新增 Action 字符串级测试(lockfile 检查路径 / --prefix / --ignore-scripts /
  无 curl.exe / CLI 路径)
- **traversal 完整度(P0-2)**:traversalFailures 并入 `coverageSkips`(report 可见);新增
  `scanCoverage.binarySampleFailures`(binary-sample 阶段失败独立计数);walk/stat 失败测试
- **tarball 资源所有权(P0-3)**:`extractTarball()` 接管 tarball 生命周期——成功 cleanup /
  TarSafetyError / 任意解包异常都删除 quarantine + 传入 tgz;cleanup 幂等

### Changed
- 版本 0.4.2(package.json / package-lock / version.js 一致)
- Final Test 151/151 全绿;Final Benchmark 32 项(edge 16 项 1.000);verify:release EXIT=0

## 0.4.1 (2026-08) — Release Engineering Final Fix

按 `dsh-sentinel-v0.4-release-engineering-final-fix.md` 完成发布工程闭环(0.4.0 为 RC,0.4.1 为最终 Release):

### Fixed
- **GitHub Action 依赖安装隔离**:npm ci 定向 `--prefix ${{ github.action_path }}`(绝不在被扫描项目执行),
  强制 `--ignore-scripts`(最小执行面);vendored acorn 兜底,安装失败/离线仍可扫描
- **engines 精确对齐**:`^22.18.0 || >=24.11.0`(与 parser runtime 一致),lockfile 重建
- CI matrix:Node 22.18 / 24.11 × 3 OS

### Added
- benchmark corpus 扩至 32 项:新增 edge-ipv6-ssrf / edge-credential-specific /
  edge-multiple-taints / edge-local-bare-exec;hardening edge 组 16 项 precision/recall/F1 = 1.000
- `action.yml` 进入 npm 包(files)
- Release Gate 全部核验(§48)

## 0.4.0 (2026-08) — Final Release Hardening

按 `dsh-sentinel-v0.4-final-release-hardening.md` 完成发布前加固:正确性 / 完整性 / 资源安全 / 打包 / CI 集成,并形成可复现的最终测试证据(137 项测试全绿,benchmark rule F1 0.943 / finding 0.914 / flow 1.000)。

### Added
- 完整度:read/hash/analysis/traversal 失败显式化(`coverageSkips` + `scanComplete=false`,失败不计入 `filesAnalyzed`)
- 资源限制:metadata 5MB / tarball 512MB 下载上限(`--max-filesize`),失败路径 partial 清理;`--noproxy` 直连
- 下载层严格 DNS 校验(默认关,防 SSRF;DNS TOCTOU 限制已文档化)
- IPv6 / IPv4-mapped / `[brackets]` SSRF 目标识别(`::1`、`fc00::/7`、`fe80::/10`、`::ffff:169.254.169.254`)
- 凭据专属受信端点:secret 名匹配 + 官方端点才豁免(大厂 host 不再直接豁免)
- 同一参数 multiple taints:一个 arg → 多个独立 flow;去重键含 source+sink
- bare sink 绑定校验:`exec/spawn/readFile/writeFile` 必须绑定 import(`eval/Function/fetch` 免绑定)
- report 保留 semantic evidence(`flowSteps`/`functionName`/`toolName`/`startColumn`/`endLine`/`endColumn`/`ssrfTarget`)
- fingerprint 报告层闭环(`attachFingerprints`);SARIF `dshFingerprint` 取代 `primaryLocationLineHash`
- FindingBuffer 优先级淘汰修正(critical 永不因 cap 丢失;同优先级保留先出现)

### Fixed
- maxFindings 反向淘汰(P0-1)
- read/hash failure 虚假 complete(P0-2)
- patch/main/bin/exports 逃逸读取(P0-3)
- tarball/quarantine 全生命周期 cleanup(P0-6)
- 下载 full-body 资源限制(P0-7)
- registry 地址可覆盖(模块缓存不再固化)

### Changed
- Node 运行时基线 `>=22.18.0`(现代基线,CI matrix 22.18/24)
- 版本统一 0.4.0(package.json / package-lock / version.js)
- 文案:`zero-dependency` → `self-contained`(运行时依赖 acorn)

## 0.3.1 (2026-08) — 第二轮一次性修复(v2)

按 `dsh-sentinel-professional-v2-full-fix.md` 完成 22 项必改,把底层正确性债务一次性清掉,
并把 SARIF / GitHub Action / 安装前审计集成准备到位。优先级:正确性 > 完整性 > 防绕过 >
输出一致性 > CI 集成 > 生态功能。

### P0 正确性

- **评分与展示彻底解耦(P0-1)**:新增 `scoreBasedOnAllFindings`;扫描器维护全量
  `allStats`(bySeverity/byCategory/byContext/rawScore),评分基于全部有效命中;
  报告展示使用**优先级有界缓冲**(critical > high > medium > low > info),
  critical/high 即使出现在 maxFindings 之后也永不丢失——攻击者无法用淹没式低危命中稀释风险分
- **profile 大文件假分析修复(P0-2)**:删除 `scanTreeSync()`,profile 统一 `await scanTree`,
  大文件真正走 large-file-lite(此前只统计语言不扫描,却报告 filesAnalyzed)
- **findingsTotal 虚高修复(P0-3)**:`applyRule` 顺序改为去重 → excludes → comment → 计数,
  注释行与 known-safe idiom 不再计入 findingsTotal
- **minified/bundle 全局降级取消(P0-4)**:压缩产物只作为 evidence(`bundleFile` 标记),
  绝不自动降 severity;置信度由检测方式决定(regex → medium,AST/taint → high)
- **path containment 强化(P0-5)**:词法 containment + realpath containment +
  symlink/junction 防护 + 平台感知大小写(仅 Windows 不敏感)

### 完整性(防 silent skip)

- **hardMax 文件(P0-6)**:超过硬上限的文件记录 metadata(path/size/sha256/extension/
  文本-二进制分类/URL/exec 关键字/熵估计),并强制 `scanComplete=false`
- **maxPlugins 截断(P0-7)**:pluginsSkipped 结构化为 `{name, reason}`
  (trusted-scope/self/maxPlugins-limit/not-installed/not-a-dsh-plugin),
  limit 类截断 → `scanComplete=false`;报告新增 policySkips / coverageSkips 分类
- **二进制最低限度审计**:新增 `engine/binary/{inspect,strings,entropy}.js`,
  `.wasm/.exe/.dll/.so/.node` 等做 magic/size/sha256/entropy/printable strings 审计,
  规则 SEN-BIN-001/002/003、SEN-WASM-001

### 扫描目标模型

- **profile 插件发现重构**:direct deps → dsh.profile manifest → cordis patch →
  bundle 声明(回退);依赖图划分 direct-plugin / direct-dependency / transitive-dependency,
  传递依赖只做 metadata 审计(install/supplychain 规则),不再产生 SEN-MAN-002 误报
- **custom trustedScopes 生效**:`@my-company/foo` 等自定义 scope 正确跳过(trusted-scope)
- **test 文件降权升级**:被 main/exports/bin/patch 运行入口可达的 test 文件不再降权
  (reachability 预留);`computeRuntimeEntries()` 计算运行期入口集合

### 配置与输出一致性

- **sentinel.config.json 全部生效**:maxBytesPerFile / maxFindings / maxPlugins /
  ignore(glob,进入 report.ignored)/ includeBuildArtifacts / redactPaths / failOn(CLI 优先)/
  advisories;redactSecrets 永远开启(config false 被忽略并警告)
- **规则文档权重动态化**:generate-rules-doc.mjs 不再硬编码 critical(45),全部取自
  `SEVERITY_WEIGHT`(唯一来源)
- **audit JSON 输出修复**:CLI `--json` 输出 `{...report, audit}`(与 Harness Tool 一致),
  audit 元数据(verdict/sha256/integrity/dependencyCount/installScripts)不再丢失
- **report schema v2 补全**:scoreBasedOnAllFindings / ignored / hardSkipped /
  policySkips / coverageSkips / attackChains / supplyChain
- **CLI**:新增 `--fail-on-incomplete`(exit 3)、`--strict-exit-codes`、
  `--redact-paths`、`--max-bytes`;config 优先从目标目录检测

### 语义引擎审计

- taint source 名传播(flow 可解释:`args.command → exec`、`Buffer.from → eval`)
- 解码判定精确化:`Buffer.from` 仅 base64/hex 编码参数视为解码
- computed env(`process.env['OPEN'+'AI_API_KEY']`)、optional chaining(`cp?.exec?.`)
- SSRF 细化:云元数据端点 169.254.169.254 → critical
- prompt 投毒 confidence 分级(low 文档 / medium description / high description+隐藏副作用)
- capability mismatch 输出 evidence(declaredCapabilities / observedCapabilities)
- 新增 `net.connect` / `dgram.createSocket` 网络 sink

### 供应链安全

- **自包含安全 tar 解析**(engine/package/tar.js):拒绝 `../`、绝对路径、盘符、
  symlink/hardlink 条目;限制条目数 20000 / 解压 300MB / 单文件 50MB / 路径 1024 / 深度 32
- **integrity 不匹配** → SEN-SUPPLY-004 + 至少 REVIEW;解包被阻止 → SEN-SUPPLY-005 +
  BLOCK-RECOMMENDED + scanComplete=false;quarantine 任何路径 finally cleanup
- **lockfile 识别与统计**(package-lock/shrinkwrap/pnpm/yarn/bun)→ supplyChain 字段
- secret 形态扩展:github_pat_ / npm_ / AIza / Anthropic sk-ant- / PEM 私钥块脱敏
- 敏感文件扩展:.pypirc / .yarnrc / .env.local / .env.production / gcloud / Azure / kubeconfig
- persistence 最低限度:SEN-PERSIST-001(持久化机制)/ SEN-PERSIST-002(写 shell profile,high)

### CI 与生态

- **GitHub Action**:`.github/actions/dsh-sentinel/` 自包含 composite action
  (path/mode/fail-on/fail-on-incomplete/max-files/sarif-file 输入,exit-code/sarif-path 输出),
  acorn 已 vendored;示例 workflow `.github/workflows/sentinel.yml`(SARIF → Code Scanning)
- **SARIF 审计**:相对路径(不写盘符绝对路径)、稳定指纹、severity 映射、GitHub 兼容
- **benchmark 升级**:rule / finding(±2 行)/ flow(source→sink)三级指标
- **DSH pre-install 集成**:确认无官方 hook(不伪造),提供 `auditPackageBeforeInstall` API
  + CLI wrapper + 集成设计文档

### 测试与文档

- 测试 63 → 94 项(新增供应链安全 12 项 + v2 正确性 19 项)
- 新增 fixtures:bench 扩至 16 项(跨函数/SSRF/optional-chain/computed-env 等)
- 文档:新增 architecture.md / integration-github-action.md / integration-dsh-preinstall.md;
  更新 README / SECURITY / roadmap / rules.md / example-report.json

### Benchmark(16 项带标注语料)

```text
rule-level   precision 0.962 · recall 1.000 · F1 0.981
finding-level precision 0.941 · recall 1.000 · F1 0.970
flow-level   precision 1.000 · recall 1.000 · F1 1.000
```

## 0.2.0 (2026-08-19) — 专业版 Phase-1

- 扫描完整性:maxFindings 只限报告条数;scanComplete/filesDiscovered/filesAnalyzed 如实上报
- 三种扫描模式 source/package/profile;大文件 large-file-lite;路径 containment;入口契约严格化
- secret 脱敏;VERSION 单一来源;41 项测试

## 0.1.0 (2026-08-18)

- 首个 npm 发布:零依赖静态启发式扫描(执行/凭据/外传/混淆/安装脚本/文件系统/网络/manifest/hygiene)
- 双形态:DSH 工具插件 + 独立 CLI;测试上下文降权;43 仓库生态体检
