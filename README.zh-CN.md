# dsh-sentinel（中文说明）

[English README](README.md) 是主文档，也是最完整、最先维护的说明。本中文文件是辅助翻译；
如有歧义，以英文文档和发布版本的行为为准。

## 定位

dsh-sentinel 是 DeepSeek Harness（DSH）插件的只读安全、供应链和健康扫描器。它对源码树、
npm 发布包、DSH profile 和 CI 进行静态审计，输出风险分、裁决、可审阅证据和覆盖率信息。
扫描器不会 `require`、`import`、`eval` 或执行被扫描的插件代码。

## Phase A：实验性、显式选择的动态分析基础设施

Phase A 只提供动态分析的契约、状态机、策略限制、证据脱敏和测试用注入 fake backend。它不是
生产动态执行功能，默认也不会启用。即使使用 `--dynamic`，生产 resolver 仍会明确返回
`backend-not-implemented-phase-a` / `unavailable`。

因此，Phase A 有以下不可协商的边界：

- 不执行插件代码；
- 不启动容器，也不调用 Docker 或 Podman；
- 不运行生产 backend，不发起进程或网络执行；
- **永远没有 host-execution fallback（主机执行回退）**；
- Docker/Podman 的实现只会在 Phase B、并通过独立安全审计门禁后才会开始。

静态完整性和动态完整性是两个独立状态。静态结果继续通过
`summary.scanComplete` 表示；请求动态扫描时，结果单独写在
`analysisLayers.dynamic`，不会覆盖、淡化或伪造静态裁决。

## 动态分析 CLI 选项

| 选项 | Phase A 行为 |
| --- | --- |
| `--dynamic` | 请求实验性深度分析；生产结果为 `unavailable`。 |
| `--dynamic-backend <auto\|docker\|podman>` | 声明未来容器 backend 偏好；Phase A 不调用 Docker/Podman。 |
| `--dynamic-profile observe` | 选择唯一支持的观测 profile。 |
| `--dynamic-timeout <ms>` | 请求有界超时；默认 `15000` ms，强制限制在 `1000`–`30000` ms。 |

当请求的深度扫描为 `unavailable`、`refused` 或 `incomplete` 时，只有在使用
`--fail-on-incomplete` 或 `--strict-exit-codes` 的情况下才退出 `3`。不使用这些严格
选项时，该状态仍会出现在报告中，但不会单独导致 CI 失败。这个规则与静态扫描完整性分开。

## 安全与隐私保证

- 被扫描代码从不执行；安装前审计也不会执行 npm 生命周期脚本。
- 所有动态层证据都在固定的脱敏边界内规范化、限长和摘要化；原始 secret 不会写入报告。
- 路径、清单入口和隔离解包继续经过 containment 与资源限制检查。
- 所有跳过、截断和不完整状态都显式报告；“干净”不等于插件安全。
- 默认不会上传源码。`--advisories` 是显式联网功能，只发送包名和版本。

更多静态扫描功能、报告格式、CI 集成和安全政策，请参阅 [English README](README.md)、
[架构文档](docs/architecture.md) 与 [安全策略](SECURITY.md)。
