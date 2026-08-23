# Roadmap / 发布清单

## 🧭 版本规划(按任务书 §53 调整)

### v0.2 ✅(2026-08-19,Phase-1)
- [x] 扫描完整性:maxFindings 不再提前停扫,findingsTotal/findingsReturned/scanComplete 如实上报;不完整扫描强制 review + INCOMPLETE 标记
- [x] 三种扫描模式 source/package/profile;package/profile 模式必扫 dist/build/lib/out;profile 扫描自动排除扫描器自身
- [x] 大文件策略:512KB–20MB 走 large-file-lite;路径 containment(SEN-MAN-009);入口契约严格化;secret 脱敏;VERSION 单一来源
- [x] SECURITY.md、41 项测试

### v0.3 ✅(2026-08-19,Phase 2–8)
- [x] sentinel.config.json、profile 依赖图、内置包信任策略
- [x] 安装前扫描:npm tarball 隔离获取/完整性校验;audit-install / npm:<pkg> / sentinel_audit_package
- [x] AST(acorn)+ 污点流(SEN-TAINT-001/002/003)+ 跨函数传播 + 受信端点豁免
- [x] Harness 专属:SEN-AGENT-005/006;SSRF 目标细化;containment 提示;记忆/对话外传
- [x] CI:稳定 fingerprint、SARIF 2.1.0、baseline、--fail-on
- [x] 生态:OSV(默认关)、provenance、源码↔发布包 diff、HTML、benchmark

### v0.3.1 ✅(2026-08,第二轮一次性修复)
- [x] **正确性**:评分-展示彻底解耦(scoreBasedOnAllFindings,优先级有界缓冲,critical 永不因 cap 丢失);applyRule 顺序修复(comment/exclude 不虚高 findingsTotal);删除 profile scanTreeSync(统一 await scanTree,大文件真正走 lite)
- [x] **防绕过**:minified/bundle 取消全局降 severity(改为 confidence 模型);path containment 三层化(平台大小写/realpath/symlink 防护);hardMax 文件 metadata 记录 + scanComplete=false;maxPlugins 截断 → incomplete + skip 分类
- [x] **完整性**:可执行二进制 metadata 审计(SEN-BIN-001/002/003、SEN-WASM-001);profile 插件发现重构(direct deps/manifest/patch/bundle 声明,transitive 只做 metadata 审计);custom trustedScopes 生效;test 文件降权升级(运行入口可达不降权)
- [x] **输出一致性**:config 全字段进入主调用链(ignore/redactPaths/failOn/maxBytes/maxFindings);规则文档权重动态化(SEVERITY_WEIGHT);audit JSON 携带 audit 元数据;report schema v2 补全(ignored/hardSkipped/policySkips/coverageSkips/attackChains)
- [x] **供应链**:自包含安全 tar 解析(traversal/symlink/hardlink/tar bomb);integrity 不匹配 → SEN-SUPPLY-004 + 至少 REVIEW;解包阻止 → SEN-SUPPLY-005 + BLOCK;lockfile 识别统计;secret 形态扩展(github_pat_/npm_/AIza/Anthropic/PEM);persistence 最低限度规则
- [x] **CI**:GitHub Action(自包含 composite + vendored acorn)+ 示例 workflow + 文档;--fail-on-incomplete(exit 3)/--strict-exit-codes
- [x] **DSH 集成**:确认无官方 pre-install hook(不伪造),提供 auditPackageBeforeInstall API + 集成设计文档
- [x] **基准**:三级 benchmark(rule/finding±2 行/flow source→sink);199 项测试

### v0.4 ✅(2026-08,Final Release Hardening + Professional Upgrade,0.4.0→0.4.4)
- [x] 完整度:read/hash/binary-sample/analysis/traversal 失败显式化(coverageSkips + scanComplete=false);filesAnalyzed 真实计数
- [x] 资源安全:metadata 5MB / tarball 512MB 上限;tarball/quarantine 全生命周期 cleanup(幂等);下载层严格 DNS(默认关)
- [x] 语义:凭据专属受信端点、multiple taints、bare sink import 绑定、IPv6/mapped SSRF、TypeScript 标注、解构污点
- [x] 报告:semantic evidence 保留、fingerprint 报告层闭环、SARIF dshFingerprint
- [x] 发布工程:Action 依赖安装隔离(--prefix/--ignore-scripts)、engines ^22.18.0 || >=24.11.0、CI 3 OS × 2 Node、verify:release
- [x] 专业分析层:模块图、有界跨文件污点、攻击链、依赖图、能力图、SBOM、provenance
- [x] TypeScript 模块图降级与 `.js → .ts` 回退;辅助层失败不再误判核心扫描不完整
- [x] 证据:199 项测试全绿;benchmark 32 项(edge 16 项全 1.000);npm 0.4.4 发布

### v0.5
- [ ] pnpm/yarn/bun lockfile 标准化与 install-script 依赖链标注
- [ ] 动态 import/require、复杂回调/闭包的跨文件 reachability
- [ ] 原生 TypeScript parser,减少静态 import/export 降级
- [ ] GitHub Action 拆独立仓库 + 徽章服务
- [ ] DSH 官方 pre-install hook 对接(若官方提供)
- [ ] 公开威胁情报(默认关闭,仅上传包名/版本/hash)

### v1.0
- [ ] 稳定语义引擎与基准(目标:rule precision ≥ 0.90 / recall ≥ 0.85)
- [ ] 专业 CI 集成(Code Scanning 全流程)
- [ ] 文档化限制清单

## 🚀 发布 Checklist

### 1. GitHub 仓库 ✅
- [x] 仓库已建并推送:github.com/Eligahyu/dsh-sentinel-scanner
- [x] Topics:dsh-plugin、deepseek-harness、security、scanner、supply-chain-security、static-analysis
- [x] SECURITY.md 已补全(supported versions / reporting / scanner self-security / tar 解析 / 路径逃逸 / secret 泄露 / 响应承诺)

### 2. 上架插件目录
- [x] 自动入队:awesome-dsh-plugin 每日工作流自动抓取
- [x] 自荐提交包:docs/submission-awesome.md
- [ ] 自荐展示位:star > 10 后执行
- [x] dsh-market:目录即 awesome-dsh-plugin 注册表,自动跟随

### 3. npm 发布
- [x] 包名 `deepseek-harness-sentinel`;v0.1.0 已发布
- [x] 全局安装 + CLI 冒烟测试通过
- [x] 发布 v0.3.1(第二轮修复)
- [x] 发布 v0.4.0–v0.4.4(发布加固 + 专业分析升级,Node ^22.18.0 || >=24.11.0)
- [ ] 配置 Trusted Publishing(OIDC)

### 4. 中文社区传播
- [x] 生态体检素材:docs/ecosystem-scan.md
- [ ] 掘金/知乎/公众号文章

## 🎯 定位红线(决定不做的事)

- ❌ 不做"自动判定恶意"的一票否决——只做证据与建议,决策权留给用户
- ❌ 不联网收集被扫描代码(隐私),离线纯本地
- ❌ 不执行被扫描代码(动态沙箱是另一个项目的事)
- ❌ 不为通过测试删除检测规则 / 不偷删恶意 fixture / 不无差别降级
