# 规则目录 / Rule Catalog

共 51 条启发式规则。启发式 ≠ 判决:命中只表示"需要人工复核",不代表插件一定恶意。

| ID | 严重度(权重) | 类别 | 规则 | 说明 |
| --- | --- | --- | --- | --- |
| `SEN-EXEC-001` | 🔴 critical(50 分) | execution | **remote-code-download** | 发现从网络获取内容后直接交给执行器(exec/spawn/eval/Function/shell)的模式。这是供应链攻击最典型的形状。 |
| `SEN-EXEC-002` | 🟡 medium(8 分) | execution | **shell-execution** | 插件调用系统命令。部分 DSH 插件(终端、构建类)确有正当需求,但这是插件越权的最高频入口,必须逐处审查。 |
| `SEN-EXEC-003` | 🟠 high(20 分) | execution | **dynamic-code-eval** | eval、new Function、vm.runIn*、Module._compile、process.binding 等动态执行机制。配合网络或解码即高危。 |
| `SEN-EXEC-004` | 🟠 high(20 分) | execution | **eval-of-decoded** | 先 base64/URI 解码再执行,是绕过静态检测的经典混淆手段。shell 的 base64 -d | sh 与 eval "$(base64 …)" 同样算。 |
| `SEN-CRED-001` | 🔴 critical(50 分) | credentials | **credential-file-read** | 代码读取 ~/.ssh、~/.aws/credentials、.npmrc、.netrc、kubeconfig、docker config、.git-credentials 等敏感文件。 |
| `SEN-CRED-002` | 🟠 high(20 分) | credentials | **env-credential-access** | 代码访问 process.env 中以 _ 分段的凭据名(API_KEY/ACCESS_KEY/TOKEN/SECRET/PASSWORD/CREDENTIAL/PRIVATE_KEY/AUTH)。AUTHOR、GITHUB_SHA、AWS_REGION 这类非凭据名不算。 |
| `SEN-CRED-003` | 🟠 high(20 分) | credentials | **hardcoded-secret** | 代码中出现形似真实 API key / token 的字符串(sk-…、AKIA…、ghp_…、JWT 等)。 |
| `SEN-CRED-004` | 🟡 medium(8 分) | credentials | **dotenv-loading** | 插件读取 .env 或环境文件。本机开发场景常见,但需确认 .env 内容不会离开本机。 |
| `SEN-CRED-005` | 🟡 medium(8 分) | credentials | **credential-file-write** | 代码向 .ssh/.aws/.npmrc 等敏感路径写入内容(注入密钥或篡改配置)。 |
| `SEN-EXFIL-001` | 🔴 critical(50 分) | exfiltration | **suspicious-endpoint** | 代码向已知的"接收任意数据"类服务发起请求:webhook.site、requestbin、pastebin、Discord webhook（/api/webhooks）、Telegram bot、ngrok/serveo 隧道、oast/interactsh 等。普通 Discord API（/api/v10）和仅出现 discord 字样不算。 |
| `SEN-EXFIL-002` | 🟠 high(20 分) | exfiltration | **network-with-secrets** | 网络请求的参数/头/体中拼接了 process.env 或密钥变量,存在把凭据外传的风险。 |
| `SEN-EXFIL-003` | 🟡 medium(8 分) | exfiltration | **encoded-env-in-network** | 请求前对 env/密钥做 base64 或编码处理,通常用于规避 URL 字符限制或检测。 |
| `SEN-OBF-001` | 🟠 high(20 分) | obfuscation | **encoded-payload** | 源码中出现超过 200 字符的 base64、连续 40+ 个 \x 十六进制转义或 80+ 字符的纯字母数字长串。纯十六进制摘要(如 sha512 的 128 位十六进制)和 sha256/384/512- integrity 不算载荷。注:\uXXXX unicode 转义不算——那是转译器/压缩器对非 ASCII 文本(i18n 文案等)的常规处理,在中文生态里普遍存在。 |
| `SEN-OBF-002` | 🟡 medium(8 分) | obfuscation | **minified-single-line** | 单个代码行超过 30KB。合法插件也可能打包产物,但超长单行是隐藏恶意逻辑的常用手法,需人工解压审阅。 |
| `SEN-OBF-003` | 🟢 low(3 分) | obfuscation | **decode-then-exec** | decodeURIComponent/unescape/fromCharCode 与 eval/Function 出现在同一文件。 |
| `SEN-INST-001` | 🟡 medium(8 分) | install | **install-script-present** | npm 安装时会自动执行这些脚本,运行在用户完整权限下、不在任何沙箱之内。注:DSH 官方对 git 安装的 TS bundle 也要求 prepare 构建脚本,因此仅"存在"本身不是恶意——需要人工确认脚本内容。 |
| `SEN-INST-002` | 🔴 critical(50 分) | install | **install-script-network** | 安装脚本中包含 curl/wget/base64/chmod、管道到 shell,或非 echo/printf 的网络地址。典型形状是 curl … | bash。仅在 echo/printf 里出现的文档链接不算。 |
| `SEN-FS-001` | 🔴 critical(50 分) | filesystem | **destructive-command** | 删除命令的目标是 ~、/、C:、/home、/root、/etc、/usr、/Users 等关键路径。相对路径(./dist)、临时目录(/tmp)和工作区清理不算。 |
| `SEN-FS-002` | 🟡 medium(8 分) | filesystem | **write-outside-workspace** | 代码向 /etc、C:、用户主目录等绝对路径写入文件。 |
| `SEN-FS-003` | 🟡 medium(8 分) | filesystem | **permission-mutation** | 代码把文件设为宽松权限(777 / a+rwx / 递归 -R 置宽)或提权执行。严格权限(0o600/0o700/0o644/0o755 等)是良好实践,不在此列。 |
| `SEN-FS-004` | 🟢 low(3 分) | filesystem | **tempfile-in-exec** | shell 命令写入 /tmp 或 %TEMP%——配合下载执行是常见攻击链。 |
| `SEN-NET-001` | 🟡 medium(8 分) | network | **network-call** | 插件存在出网能力。相对路径的同源调用(fetch('/plugin-api/...'))是客户端插件与自家宿主的本地通道,不算外发;只有绝对 URL(http/https/ws)、协议相对(//host)或变量目标的调用才命中。 |
| `SEN-NET-002` | 🟢 low(3 分) | network | **hardcoded-ip** | 源码中直接出现公网 IPv4 字面量(排除 127.x / 10.x / 192.168.x / 172.16-31.x / 0.x / 255.x)。 |
| `SEN-MAN-001` | 🟡 medium(8 分) | manifest | **missing-package-manifest** | 扫描目标不是 npm 包结构,无法作为 DSH bundle 安装。 |
| `SEN-MAN-002` | 🟠 high(20 分) | manifest | **not-a-dsh-bundle** | package.json 中没有 dsh.bundle,`dsh plugin add` 不会激活其任何层。 |
| `SEN-MAN-003` | 🟠 high(20 分) | manifest | **patch-file-missing** | dsh.bundle.patch 指向的文件在包内缺失,安装后插件层不会生效(或安装失败)。 |
| `SEN-MAN-004` | 🟡 medium(8 分) | manifest | **patch-row-invalid** | cordis.patch.yml 的行解析失败,loader 可能拒绝该层。 |
| `SEN-MAN-005` | 🟡 medium(8 分) | manifest | **patch-entry-unresolvable** | patch 行 name 指向的子路径在包内不存在(或未在 exports 中声明)。 |
| `SEN-MAN-006` | 🟠 high(20 分) | manifest | **plugin-entry-invalid** | 入口模块未导出 Cordis 插件协议要求的 name/apply,加载会失败或静默无行为。 |
| `SEN-MAN-007` | 🟢 low(3 分) | hygiene | **license-missing** | package.json 未声明 license,安装与再分发存在法律风险。 |
| `SEN-MAN-008` | 🟢 low(3 分) | hygiene | **description-missing** | package.json 未声明 description。 |
| `SEN-MAN-009` | 🔴 critical(50 分) | manifest | **manifest-path-escape** | package.json 的 dsh.bundle.patch、main、exports 或 cordis.patch.yml 的入口名指向扫描根目录之外(如 ../../Users/xxx/.ssh)。攻击者可借此让扫描器读取目标目录之外的文件。 |
| `SEN-SUPPLY-001` | 🟠 high(20 分) | supplychain | **remote-dependency-source** | package.json 依赖指向非标准来源:git+http(明文)、http:// tarball、file: 本地路径或 workspace: 引用。供应链攻击常通过劫持这类来源投放。 |
| `SEN-SUPPLY-002` | 🟡 medium(8 分) | supplychain | **dependency-install-script** | 依赖元数据显示依赖包含 preinstall/install/postinstall 脚本。安装时以用户完整权限执行,是供应链攻击的主要载体。 |
| `SEN-SUPPLY-004` | 🟠 high(20 分) | supplychain | **integrity-mismatch** | 下载的 tarball 的 sha512 与 registry 返回的 integrity 字段不匹配——可能是传输篡改、镜像污染或注册表被入侵。 |
| `SEN-SUPPLY-005` | 🔴 critical(50 分) | supplychain | **tar-path-traversal** | 包内条目试图写入解包目录之外(../../)、绝对路径或通过 symlink/hardlink 逃逸隔离目录。 |
| `SEN-AGENT-001` | 🔴 critical(50 分) | agent | **model-controlled-shell** | defineTool 的 execute(args) 中,模型可控参数(args.*)直接或经变量传播进入 shell 执行器。 |
| `SEN-AGENT-002` | 🟠 high(20 分) | agent | **model-controlled-file-read** | 模型可控参数进入文件读取调用,若无 workspace containment 则模型可读任意文件。 |
| `SEN-AGENT-003` | 🟠 high(20 分) | agent | **model-controlled-file-write** | 模型可控参数进入文件写入调用,可写 HOME / 系统目录 / DSH profile / 其他插件目录。 |
| `SEN-AGENT-004` | 🟠 high(20 分) | agent | **model-controlled-network-target** | 模型可控参数成为网络请求 URL,即 SSRF / 任意出网能力面。 |
| `SEN-TAINT-001` | 🔴 critical(50 分) | taint | **secret-to-network** | process.env 中的凭据(API key/token/secret)直接或经变量传播进入网络请求,包括 fetch/axios 和已导入的 dns.lookup/dns.resolve。Promise.resolve 不算网络出口。 |
| `SEN-TAINT-002` | 🟠 high(20 分) | taint | **workspace-to-network** | readFile 等读取的结果(可能是工作区源码/配置)进入网络请求体。 |
| `SEN-TAINT-003` | 🔴 critical(50 分) | taint | **decode-to-exec-flow** | base64/hex/URI 解码(Buffer.from/atob/fromCharCode 等)的结果进入 eval/Function/exec。别名(const run = eval、Function.prototype.constructor、const decode = atob)和 new vm.Script(decoded) 同样算。 |
| `SEN-AGENT-005` | 🟡 medium(8 分) | agent | **tool-prompt-poisoning** | defineTool 描述或指令文本含 "ignore previous instructions" / "do not tell the user" 等短语。注意:防御性说明也可能出现同类文字,需结合上下文。 |
| `SEN-AGENT-006` | 🟡 medium(8 分) | agent | **capability-mismatch** | 工具描述看似普通(天气/问候/换算等),但代码含 exec/fetch/文件读写等敏感能力。 |
| `SEN-BIN-001` | ⚪ info(0 分) | binary | **native-binary-present** | 插件包内含可执行原生代码(.exe/.dll/.so/.node 等)。可能完全正当(构建工具/平台库),但原生代码无法逐行静态审阅,需人工确认来源。 |
| `SEN-BIN-002` | 🟡 medium(8 分) | binary | **suspicious-binary-strings** | 原生二进制的可打印字符串含 webhook/discord/ngrok、AWS_/API_KEY、curl/powershell、.ssh 等标记。注意:仅凭字符串不能判恶意,但必须人工复核。 |
| `SEN-BIN-003` | 🟡 medium(8 分) | binary | **high-entropy-binary** | 采样熵值过高,通常表示压缩/加密/加壳。不直接判恶意,但意味着无法静态核验内容。 |
| `SEN-WASM-001` | ⚪ info(0 分) | binary | **wasm-module-present** | 包内含 .wasm 模块。WASM 常用于合法性能敏感代码,也可能用于隐藏逻辑。 |
| `SEN-PERSIST-001` | 🟡 medium(8 分) | persistence | **persistence-mechanism** | 代码注册自启动/定时任务:可让代码在用户不知情时反复执行。部分监控/提醒类工具有正当需求,但必须人工确认。 |
| `SEN-PERSIST-002` | 🟠 high(20 分) | persistence | **shell-profile-persist** | 代码向 .bashrc/.zshrc/.profile 或 PowerShell $PROFILE 写入内容。正常插件没有任何理由修改用户的 shell 启动文件。 |

权重:critical=50 · high=20 · medium=8 · low=3 · info=0,总分封顶 100。

裁决:0-19 ✅ safe · 20-49 👀 review · 50-79 ⚠️ risky · 80-100 🚨 dangerous

> 评分与展示分离:分数基于全部有效命中(allStats),报告最多展示 maxFindings 条;
> critical/high 命中即使出现在截断之后也不会丢失计分。minified/bundle 只作为 evidence,不自动降级。
