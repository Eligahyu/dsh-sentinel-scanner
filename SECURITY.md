# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.4.x | ✅ 当前版本 |
| 0.3.x | ⚠️ 仅关键安全修复 |
| ≤ 0.2.x | ❌ 不再支持 |

## Reporting a Vulnerability

dsh-sentinel 是一个安全扫描工具,自身的安全同样重要。请通过以下渠道报告:

- **GitHub Private Vulnerability Reporting**:在本仓库的 **Security → Report a vulnerability** 提交
- 或邮件至仓库维护者(见 GitHub 主页)

**请勿**在公开 Issue / 讨论 / 社交媒体中披露未修复的漏洞细节(包括 0-day)。

## Response Timeline

- 48 小时内确认收到报告
- 7 天内给出修复计划
- 修复后发布安全版本,并在 CHANGELOG 中记录(CVE 编号如有)

## Scope: What We Care About

### 扫描器自身被恶意构造的插件/路径攻破

- 路径逃逸(`../`、绝对路径、盘符、UNC、symlink/junction escape)——由
  `engine/path-safety.js` 三层校验(词法 + realpath + symlink)防护
- zip-slip / tar traversal / tar bomb——由 `engine/package/tar.js` 防护
  (拒绝 traversal/链接条目;条目数 20000 / 解压 300MB / 单文件 50MB / 路径 1024 / 深度 32)
- 拒绝服务:超大文件只做 metadata 记录,绝不整读入内存(流式 sha256)

### 报告二次泄露

- secret 脱敏绕过:`engine/redact.js` 永远开启,报告零完整 secret,只保留指纹
- 绝对路径泄露:`--redact-paths` 将本机路径匿名化为 `<workspace>/...`
  (JSON / SARIF / HTML 均可分享)

### 误执行被扫描代码(红线)

- 任何情况下都不 `require/import/eval/spawn` 被扫描代码
- 安装前审计只做:tarball 下载 → 隔离解包 → 静态扫描 → 删除,
  绝不执行 `npm install` / preinstall / install / postinstall / prepare
- 报告此类的漏洞将被优先处理

### Phase A 动态分析的延后执行边界

- Phase A 是实验性、显式 opt-in 的动态分析基础设施；生产 resolver 故意返回 unavailable，
  不能通过 CLI 或普通 API 获得真实 backend
- Phase A 绝不执行插件代码、绝不启动容器、绝不调用 Docker/Podman、绝不执行 host fallback；
  测试中唯一可运行的 adapter 是显式注入的 fake backend
- 静态完整性与动态完整性独立记录。请求动态扫描得到 unavailable/refused/incomplete 时，
  只有 `--fail-on-incomplete` 或 `--strict-exit-codes` 才以 exit 3 阻断 CI
- 动态 policy 的 timeout 默认 15000ms，并强制限制在 1000–30000ms；事件和 evidence 也有
  不可变数量、字节与深度上限
- 动态 evidence 在写入报告前必须复制、验证、规范化、脱敏和摘要；hostile/malformed evidence
  或不确定 cleanup 只能形成安全的 incomplete 状态，不能泄露 backend 错误或 secret
- Docker/Podman 的实际实现只会在 Phase B、并经过独立安全审计后开始；该审计是发布门禁。

### 默认行为意外联网

- 所有联网能力默认关闭(`--advisories` 才查询 OSV,仅上传包名+版本;
  `audit-install` 的 registry 获取由用户显式触发)
- 发现任何"未显式触发就联网"的路径,请立即报告

## Security-relevant design guarantees

- 扫描器只读:绝不执行被扫描代码,不跟随目录符号链接
- 所有 manifest 派生路径(patch/main/exports/bin/入口名)经过 containment,
  逃逸即报 `SEN-MAN-009`(critical)
- 评分基于全部有效命中(与展示解耦);critical/high 不会因 maxFindings 丢失
- minified/bundle 只作为 evidence,绝不自动降 severity
- 任何 ignore / skip / 截断都进入报告(ignored / hardSkipped / policySkips /
  coverageSkips / scanComplete),不完整扫描绝不显示 clean
- 默认不上传任何源码;未来的联网能力只会上传包名/版本/hash
- **不保证检测所有恶意插件**:静态启发式扫描存在天然漏报(跨文件污点分析是有界的;
  复杂回调/闭包/原型链、非 JS 语言语义和运行时混淆仍是能力边界),扫描通过 ≠ 插件安全
- **SSRF 下载层有显式目标限制**:`--strict-dns`(或 `SENTINEL_STRICT_DNS=1`)在下载前
  解析 hostname 并拒绝私有/保留地址;注意 DNS rebinding 无法完全消除(TOCTOU),
  严格校验降低风险而非绝对防护

## Response expectations

- 漏洞报告会获得修复版本与 CHANGELOG 记录
- 涉及扫描器自身代码执行/路径逃逸/二次泄露的漏洞享有最高优先级
