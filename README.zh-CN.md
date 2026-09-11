# dsh-sentinel（中文说明）

[English README](README.md) 是主文档，也是最完整、最先维护的说明。本中文文件是辅助说明；
如有歧义，以英文文档、当前发布版本和报告契约为准。

## 定位

dsh-sentinel 是 DeepSeek Harness（DSH）插件的只读安全、供应链和健康扫描器。它对源码树、
npm 发布包、DSH profile 和 CI 进行静态审计，输出风险分、裁决、可审阅证据和覆盖率信息。
静态扫描不会 `require`、`import`、`eval` 或执行被扫描的插件代码。

## Phase B 动态分析：显式选择、网络隔离

动态分析不是默认行为。只有明确传入 `--dynamic` 才会在静态结果之后请求独立的动态层；没有
这个选项就不会探测 Docker/Podman，也不会启动 runner。静态裁决和动态状态始终分开。

Phase B 只接受本地 Docker 或 rootless Podman，以及由扫描器发布、预先加载、使用完整
`sha256` digest 固定的可信镜像。当前 npm 包没有编译/部署内置的 scanner-owned 镜像，因此
生产 resolver 在没有该镜像时报告 `unavailable`（通常原因为 `trusted-image-unavailable`）。
它不会 pull、build、在主机执行插件，也没有主机执行回退路径。

静态 preflight 会在高风险 native 可执行文件或 native Node 模块、容器控制/逃逸信号、超出
硬限制、入口点无法解析、核心遍历不完整或隔离 backend 不可用时拒绝动态执行。拒绝是可报告
状态，不会删除或覆盖静态 findings。

动态状态包括 `not-requested`、`unavailable`、`refused`、`complete` 和 `incomplete`：

- `not-requested`：没有请求动态层；
- `unavailable`：可信 immutable 镜像或本地隔离前提不存在，插件没有运行；
- `refused`：静态 preflight 认为目标超出 Phase B 的威胁边界；
- `complete`：固定阶段、有界证据和精确 cleanup 都完成，但不等于插件安全；
- `incomplete`：阶段、解析、超时、取消、资源限制或 cleanup 存在不确定性。

使用 `--fail-on-incomplete` 或 `--strict-exit-codes` 时，请求的
`unavailable`/`refused`/`incomplete` 会以退出码 `3` 告知 CI；否则状态仍在报告中可见，
但不会单独改变静态退出策略。

## Phase B runner 边界

Linux release gate 只运行在受保护、由管理员维护的 self-hosted runner，标签为
`self-hosted`、`linux`、`dsh-sentinel-phase-b`，environment 为
`dynamic-analysis-protected`。它要求本地 Docker/Podman、预加载的扫描器可信镜像和受保护
的 immutable digest；不接受 remote endpoint/context。runner 每个阶段都是新的短生命周期
容器，并固定使用：

- `--network=none`，不允许 public 或 private egress；Phase C 的 gateway/probe 不在其中；
- `--pull=never`，不拉取镜像；不在扫描中 build 镜像；如果本地没有 exact image，则明确
  报告 `unavailable` 并跳过；
- private PID/IPC namespace、read-only root、read-only staging、non-root 用户、dropped
  capabilities 和 `no-new-privileges`；
- 有界的 CPU、内存、PID、临时空间、输出和 wall-clock 资源；
- 没有 host workspace mount、engine socket、host namespace、host credential 或真实凭据；
- 不执行 package manager，也不执行 `preinstall`、`install`、`postinstall`、`prepare` 生命周期。

staging lifecycle 会先做 root containment，再把允许的 regular files 复制到扫描器拥有的临时
snapshot；symlink、hardlink、socket、device、VCS metadata、worktree 和逃逸路径都会被排除。
只读挂载 snapshot，运行结束后只清理当前 run 所有的资源；cleanup 不确定时状态为
`incomplete`。证据会限长、结构化、脱敏和摘要化，报告不会写入 secret 原文、完整请求体、
主机绝对路径或未过滤的 engine diagnostics。

runner 的 endpoint 与 executable binding 由扫描器固定，调用者不能替换镜像、endpoint、
entrypoint、mount 或 namespace 策略。可信镜像由 scanner release 负责；staged package
始终是不可信输入。

## Phase C 限定

Phase B 故意只做 network-denied runner。CI gate 使用固定两分钟 job timeout 和 90 秒 host
command timeout。DNS/HTTP/TCP/UDP gateway、Node preload probe、
canary correlation 和任何 allowlisted replay network 都是 Phase C 工作；Phase B 的
`complete` 不暗示这些能力，也不暗示公共网络访问。

## 动态分析 CLI 选项

| 选项 | Phase B 行为 |
| --- | --- |
| `--dynamic` | 显式请求 Phase B；默认不启用。 |
| `--dynamic-backend <auto\|docker\|podman>` | 选择本地 engine，但不能绕过 immutable image 或网络隔离。 |
| `--dynamic-profile observe` | 选择有界 Phase B profile；不包含 Phase C gateway/probe。 |
| `--dynamic-timeout <ms>` | 请求有界超时；默认 `15000` ms，强制限制在 `1000`–`30000` ms。 |

## 安全与隐私保证

- 被扫描代码从不执行；安装前审计也不会执行 npm 生命周期脚本。
- 所有动态层证据都在固定的脱敏边界内规范化、限长和摘要化；原始 secret 不会写入报告。
- 路径、清单入口和隔离解包继续经过 containment 与资源限制检查。
- 所有跳过、截断和不完整状态都显式报告；“干净”不等于插件安全。
- 默认不会上传源码。OSV advisory 等联网功能需要显式开启。

更多静态扫描功能、报告格式、CI 集成和安全政策，请参阅 [English README](README.md)、
[架构文档](docs/architecture.md) 与 [安全策略](SECURITY.md)。
