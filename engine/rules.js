/**
 * dsh-sentinel rule catalog.
 *
 * Every rule is a heuristic: a finding means "a human should look at this",
 * never "this plugin is malicious". Severities weight the final 0-100 score —
 * a single critical finding (50) already lands in `risky`, two in `dangerous`:
 *
 *   critical 50 · high 20 · medium 8 · low 3 · info 0
 *
 * Line patterns are tested per line; content patterns are tested once against
 * the whole file. `filePattern` restricts a rule to matching relative paths.
 * Findings inside test files are tagged `testFile` and scored one level lower
 * UNLESS reachable from a runtime entry (see engine/report.js + engine/index.js).
 * minified/bundle 内容只作为 evidence(bundleFile 标记),绝不自动降 severity:
 * 置信度由检测方式决定(regex-only → medium,AST/taint → high)。
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_WEIGHT = Object.freeze({
  critical: 50,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
})

export const CATEGORIES = Object.freeze([
  'execution',
  'credentials',
  'exfiltration',
  'obfuscation',
  'install',
  'filesystem',
  'network',
  'manifest',
  'hygiene',
  // 专业版新增类别
  'agent',        // Harness Tool / 模型可控输入
  'taint',        // 污点传播
  'supplychain',  // 供应链
  'binary',       // 二进制
  'persistence',  // 持久化
])

/** Shared fragment: any JS-adjacent code file. */
export const CODE_EXT = /\.(?:[cm]?js|jsx|ts|tsx|mts|cts|py|rb|php|pl|sh|bash|zsh|ps1|go|rs|java|kt|m|mm|swift|vue|svelte)$/i
const CODE = CODE_EXT

/** Hardcoded-secret detector used by SEN-CRED-003 (kept private, exported below). */
const SECRET_PATTERNS = [
  { name: 'OpenAI/DeepSeek-style API key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub personal access token', re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'JWT-style token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'PEM private key header', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/ },
]

export const RULES = Object.freeze([
  // ─────────────────────────── execution ───────────────────────────
  {
    id: 'SEN-EXEC-001',
    name: 'remote-code-download',
    severity: 'critical',
    category: 'execution',
    message: '下载远程代码并执行(remote code download & execute)',
    description: '发现从网络获取内容后直接交给执行器(exec/spawn/eval/Function/shell)的模式。这是供应链攻击最典型的形状。',
    recommendation: '拒绝安装,除非你能逐行审查网络载荷并信任其来源。任何"下载即执行"的插件都不应进入你的 profile。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:child_process|cp|exec|execSync|execFile|spawn|spawnSync|system|popen|run)\s*\(\s*["'`]?(?:[^"'`)]{0,120}?)(?:curl|wget|powershell\s+-c|cmd\s+\/c|bash\s+-c|sh\s+-c)[^"'`)]{0,120}?["'`]?\s*\)/i,
        note: 'exec 类调用里出现 curl/wget/远程管道',
      },
      {
        // 执行器参数中出现 URL 或 fetch 调用。
        // 注意:大小写敏感——`Function` 仅匹配构造器 new Function,
        // 不能因 ignoreCase 匹配任意 function 关键字(见 .then 链误报修复)。
        re: /(?:exec|execSync|spawn|spawnSync|eval|new\s+Function)\s*\([^)]{0,400}(?:https?:\/\/|fetch\s*\()/s,
        note: '执行器参数中出现 URL 或 fetch 调用',
      },
      {
        // 先请求后执行的链式调用:exec/eval 必须出现在 .then 同一作用层内
        // ([^}] 阻止跨大括号吞掉无关代码);大小写敏感避免 function 关键字误报
        re: /(?:fetch|axios|https?\.request)\s*\([^)]*\)\s*\.then\s*\([^}]{0,240}?(?:eval|exec|new\s+Function)\s*\(/s,
        note: '先请求后执行的链式调用',
      },
      {
        re: /(?:require|import)\s*\(\s*["'`](?:https?:|data:)/i,
        note: '从 URL 动态加载模块',
      },
    ],
  },
  {
    id: 'SEN-EXEC-002',
    name: 'shell-execution',
    severity: 'medium',
    category: 'execution',
    message: '使用 shell 执行(child_process / system 调用)',
    description: '插件调用系统命令。部分 DSH 插件(终端、构建类)确有正当需求,但这是插件越权的最高频入口,必须逐处审查。',
    recommendation: '确认每个执行点都是功能必需、命令与参数均为静态常量(不含拼接的用户输入/环境变量),且沙箱外执行需用户知情。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      { re: /(?:child_process|cp)\s*\.\s*(?:exec|execSync|execFile|spawn|spawnSync|fork)\s*\(/ },
      // 裸 spawn(/exec( 只在文件确实引入 child_process 时才告警——否则可能是
      // 业务函数名(如游戏插件的 spawn(state)),见 needsImport 处理。
      { re: /(?<![.\w$])(?:exec|execSync|spawn|spawnSync)\s*\(/, needsImport: 'child_process' },
      { re: /\b(?:system|popen|shell_exec|os\.system|subprocess\.(?:run|Popen|call))\s*\(/ },
    ],
    // 命令与参数均为静态常量且以参数数组形态调用时豁免(规则推荐语明示的安全形态):
    //   spawn('git', ['status']) / execFile('git', ['log'])
    // 单字符串常量(spawn('ls') / exec('npm --version'))仍标记——exec/spawn 默认走 shell,
    // 常量命令也要逐处审查;仅"字符串命令 + 数组参数"视为参数化安全形态。
    excludes: [
      /(?:execFile|execFileSync|spawn|spawnSync)\s*\(\s*['"][^'"]*['"]\s*,\s*\[[^\]]*\]\s*(?:,\s*\{(?![^}]*\bshell\s*:)[^}]*\})?\s*\)/,
    ],
  },
  {
    id: 'SEN-EXEC-003',
    name: 'dynamic-code-eval',
    severity: 'high',
    category: 'execution',
    message: '动态代码执行(eval / Function / vm / 编译钩子)',
    description: 'eval、new Function、vm.runIn*、Module._compile、process.binding 等动态执行机制。配合网络或解码即高危。',
    recommendation: '审查动态执行的内容来源;任何来自网络、环境变量或解码字符串的动态执行都应视为危险。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      { re: /(?<![.\w$])(?:eval|Function)\s*\(/ },
      { re: /\bvm\s*\.\s*(?:runIn|compileFunction|createScript)/ },
      { re: /\bprocess\s*\.\s*binding\s*\(/ },
      { re: /\bModule\s*\.\s*_compile\s*\(/ },
      { re: /(?<![.\w$])(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64|decodeURIComponent|unescape)/i },
    ],
    // Known-safe idioms on the same line suppress the finding: the classic
    // `new Function("return this")()` / `new Function("")()` globalThis
    // detection pattern used by bundled code.
    excludes: [
      /new\s+Function\s*\(\s*["']\s*["']\s*\)/,
      /new\s+Function\s*\(\s*["']return\s+(?:this|globalThis)["']\s*\)/,
    ],
  },
  {
    id: 'SEN-EXEC-004',
    name: 'eval-of-decoded',
    severity: 'high',
    category: 'execution',
    message: '对解码内容执行(eval(atob(...)) 等)',
    description: '先 base64/URI 解码再执行,是绕过静态检测的经典混淆手段。',
    recommendation: '视为恶意特征:正常插件不需要对解码后的字符串执行代码。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:eval|Function|exec|runInNewContext)\s*\(\s*(?:atob|Buffer\.from|base64decode|decodeURIComponent|unescape|fromCharCode)\s*\(/i,
      },
    ],
  },

  // ─────────────────────────── credentials ───────────────────────────
  {
    id: 'SEN-CRED-001',
    name: 'credential-file-read',
    severity: 'critical',
    category: 'credentials',
    message: '读取凭据文件(SSH 私钥 / AWS / npmrc / kubeconfig 等)',
    description: '代码读取 ~/.ssh、~/.aws/credentials、.npmrc、.netrc、kubeconfig、docker config、.git-credentials 等敏感文件。',
    recommendation: '拒绝安装。DSH 插件没有读取用户私钥的任何正当理由。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /(?:readFile|readFileSync|createReadStream|openSync|require\s*\(\s*["'`])[^;\n]{0,160}?(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]|credentials|\.npmrc|\.netrc|\.kube[\\\/]|\.docker[\\\/]config|\.git-credentials|\.pypirc|\.yarnrc|\.env\.local|\.env\.production|application_default_credentials\.json|\.azure[\\\/]|kubeconfig)/i,
      },
      {
        re: /(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]credentials|\.npmrc|\.netrc|\.kube[\\\/]|\.git-credentials|\.pypirc|\.yarnrc|\.env\.local|\.env\.production|application_default_credentials\.json|kubeconfig)[^;\n]{0,120}?(?:readFile|cat|type\s+)/i,
      },
    ],
  },
  {
    id: 'SEN-CRED-002',
    name: 'env-credential-access',
    severity: 'high',
    category: 'credentials',
    message: '读取环境变量中的凭据(API key / token / secret)',
    description: '代码访问 process.env 中名称含 API_KEY/TOKEN/SECRET/PASSWORD 或知名厂商前缀(DeepSeek/OpenAI/Anthropic/GitHub/AWS)的变量。',
    recommendation: '确认凭据读取是否功能必需(如官方 API 客户端),以及凭据是否仅用于本机调用、绝不出网。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /process\s*\.\s*env\s*\.?\s*\[?["'`]?[A-Za-z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|AUTH)[A-Za-z_]*["'`]?\]?/i,
      },
      {
        re: /process\s*\.\s*env\s*\.?\s*\[?["'`]?(?:DEEPSEEK|OPENAI|ANTHROPIC|GITHUB|AWS|AZURE|GOOGLE|HF_|HUGGING)[A-Za-z_]*["'`]?\]?/i,
      },
    ],
  },
  {
    id: 'SEN-CRED-003',
    name: 'hardcoded-secret',
    severity: 'high',
    category: 'credentials',
    message: '疑似硬编码密钥',
    description: '代码中出现形似真实 API key / token 的字符串(sk-…、AKIA…、ghp_…、JWT 等)。',
    recommendation: '从仓库中移除并轮换该密钥。若为文档示例,应使用明显占位符(如 sk-xxx…)。',
    filePattern: CODE,
    linePatterns: SECRET_PATTERNS.map((p) => ({ re: p.re, note: p.name })),
  },
  {
    id: 'SEN-CRED-004',
    name: 'dotenv-loading',
    severity: 'medium',
    category: 'credentials',
    message: '加载 .env / dotenv',
    description: '插件读取 .env 或环境文件。本机开发场景常见,但需确认 .env 内容不会离开本机。',
    recommendation: '确认加载 .env 后仅在本机进程内使用,不随网络请求或日志外传。',
    filePattern: CODE,
    linePatterns: [
      { re: /\b(?:dotenv|loadEnvFile)\s*\(/ },
      { re: /(?:readFileSync|readFile|parse)[^;\n]{0,60}?["'`]\.env["'`]/i },
      { re: /\brequire\s*\(\s*["']dotenv["']\s*\)/ },
    ],
  },
  {
    id: 'SEN-CRED-005',
    name: 'credential-file-write',
    severity: 'medium',
    category: 'credentials',
    message: '写入凭据文件',
    description: '代码向 .ssh/.aws/.npmrc 等敏感路径写入内容(注入密钥或篡改配置)。',
    recommendation: '确认写入目标与用途;向用户凭据目录写入任何内容都应视为高风险行为。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:writeFile|writeFileSync|appendFile|createWriteStream|chmod)\s*\([^)]{0,160}?(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]|\.npmrc|\.netrc|\.git-credentials)/i,
      },
    ],
  },

  // ─────────────────────────── exfiltration ───────────────────────────
  {
    id: 'SEN-EXFIL-001',
    name: 'suspicious-endpoint',
    severity: 'critical',
    category: 'exfiltration',
    message: '可疑数据外传端点(webhook / pastebin / 隧道 / 监听服务)',
    description: '代码向已知的"接收任意数据"类服务发起请求:webhook.site、requestbin、pastebin、Discord webhook、Telegram bot、ngrok/serveo 隧道、oast/interactsh 等。',
    recommendation: '拒绝安装。正常插件不会把数据发往这些端点。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /https?:\/\/[^"'`\s)]{0,120}?(?:webhook\.site|requestbin\.com|pastebin\.com|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|ngrok\.(?:io|app)|serveo\.net|localtunnel\.me|smee\.io|oast\.(?:me|online|fun|pro)|interact\.sh|webhook\.cc|pipedream\.net|requestcatcher\.com)/i,
      },
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|http\.request|https\.request)\s*\([^)]{0,200}?(?:webhook\.site|requestbin|pastebin|discord|api\.telegram|ngrok|serveo|oast\.|interact\.sh)/i,
      },
    ],
  },
  {
    id: 'SEN-EXFIL-002',
    name: 'network-with-secrets',
    severity: 'high',
    category: 'exfiltration',
    message: '网络调用携带凭据或环境变量',
    description: '网络请求的参数/头/体中拼接了 process.env 或密钥变量,存在把凭据外传的风险。',
    recommendation: '确认请求目标完全可信,且凭据绝不出本机。任何将 env 拼进 URL 查询参数的行为都应视为危险。',
    filePattern: CODE,
    ignoreComments: true,
    contentPatterns: [
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|http\.request|https\.request)[^;]{0,300}process\s*\.\s*env[^;]{0,200}/is,
      },
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|https?\.request)\s*\([^)]{0,120}?["'`][^"'`]{0,120}?=[^"'`]{0,60}(?:api[_-]?key|token|secret|password|authorization)/is,
      },
    ],
    // 受信 API 端点的凭据携带是正常客户端行为(与语义引擎 TRUSTED_HOSTS 一致)。
    excludes: [
      /(?:api|platform)\.(?:deepseek\.com|openai\.com|anthropic\.com)|(?:api\.)?github\.com|googleapis\.com|azure\.com|aws\.com|api\.x\.com/i,
    ],
  },
  {
    id: 'SEN-EXFIL-003',
    name: 'encoded-env-in-network',
    severity: 'medium',
    category: 'exfiltration',
    message: '网络调用中编码(加密/base64)处理凭据',
    description: '请求前对 env/密钥做 base64 或编码处理,通常用于规避 URL 字符限制或检测。',
    recommendation: '确认编码目的;若为"让凭据不那么显眼"而编码,按外传处理。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:atob|btoa|Buffer\.from\s*\(\s*[^)]{0,80}base64|encodeURIComponent)[^;]{0,200}?process\s*\.\s*env[^;]{0,120}/is,
      },
    ],
  },

  // ─────────────────────────── obfuscation ───────────────────────────
  {
    id: 'SEN-OBF-001',
    name: 'encoded-payload',
    severity: 'high',
    category: 'obfuscation',
    message: '代码中存在大段编码载荷(base64 / 十六进制转义)',
    description: '源码中出现超过 200 字符的 base64、连续 40+ 个 \\x 十六进制转义或 80+ 字符的纯字母数字长串。注:\\uXXXX unicode 转义不算——那是转译器/压缩器对非 ASCII 文本(i18n 文案等)的常规处理,在中文生态里普遍存在。',
    recommendation: '先解码再判断:若解码结果是可读代码或数据且无文档说明,按恶意处理。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      { re: /[A-Za-z0-9+/]{200,}={0,2}/ },
      { re: /(?:\\x[0-9a-fA-F]{2}){40,}/ },
      { re: /(?:\b[A-Za-z0-9+/]{80,}\b)/ },
    ],
    // 内嵌资源(data:image/font 的 base64 URI)是客户端插件的常规做法,不算载荷。
    excludes: [
      /data:image\/(?:png|jpe?g|gif|webp|svg\+xml|ico|avif);base64,/i,
      /data:font\/(?:woff2?|ttf|otf);base64,/i,
    ],
  },
  {
    id: 'SEN-OBF-002',
    name: 'minified-single-line',
    severity: 'medium',
    category: 'obfuscation',
    message: '超长单行代码(疑似压缩混淆)',
    description: '单个代码行超过 30KB。合法插件也可能打包产物,但超长单行是隐藏恶意逻辑的常用手法,需人工解压审阅。',
    recommendation: '格式化后审阅;若为构建产物,对比其与源码仓库的对应关系。',
    filePattern: CODE,
    linePatterns: [{ re: /^.{30000,}$/ }],
  },
  {
    id: 'SEN-OBF-003',
    name: 'decode-then-exec',
    severity: 'low',
    category: 'obfuscation',
    message: '解码函数与动态执行混用',
    description: 'decodeURIComponent/unescape/fromCharCode 与 eval/Function 出现在同一文件。',
    recommendation: '确认用途;此类组合常见于混淆载荷。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:decodeURIComponent|unescape|String\.fromCharCode)[^;]{0,300}?(?:eval|Function|exec)\s*\(/is,
      },
    ],
  },

  // ─────────────────────────── install scripts ───────────────────────────
  {
    id: 'SEN-INST-001',
    name: 'install-script-present',
    severity: 'medium',
    category: 'install',
    message: '存在安装生命周期脚本(preinstall / install / postinstall / prepare)',
    description: 'npm 安装时会自动执行这些脚本,运行在用户完整权限下、不在任何沙箱之内。注:DSH 官方对 git 安装的 TS bundle 也要求 prepare 构建脚本,因此仅"存在"本身不是恶意——需要人工确认脚本内容。',
    recommendation: '逐行审阅脚本内容。纯构建类(prepare: npm run build / tsc / tsdown)可接受;含网络下载、base64、chmod 等请按 SEN-INST-002 处理。',
    filePattern: /package\.json$/i,
    contentPatterns: [
      {
        re: /"(?:preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]{1,400}"/i,
      },
    ],
  },
  {
    id: 'SEN-INST-002',
    name: 'install-script-network',
    severity: 'critical',
    category: 'install',
    message: '安装脚本下载并执行远程内容',
    description: '安装脚本中包含 curl/wget/网络地址/base64/chmod 等,典型形状是 curl … | bash。',
    recommendation: '拒绝安装。安装即执行远程代码的插件不可信。',
    filePattern: /package\.json$/i,
    contentPatterns: [
      {
        re: /"(?:preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]{0,400}?(?:curl|wget|https?:|base64|chmod\s+\+x|eval)[^"]{0,200}"/i,
      },
    ],
  },

  // ─────────────────────────── filesystem ───────────────────────────
  {
    id: 'SEN-FS-001',
    name: 'destructive-command',
    severity: 'critical',
    category: 'filesystem',
    message: '危险删除命令(rm -rf 指向主目录 / 根目录等)',
    description: '删除命令的目标是 ~、/、C:\、/home、/root、/etc 等关键路径。',
    recommendation: '拒绝安装。任何指向用户主目录或系统目录的递归删除都是恶意特征。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /(?:rm|del)\s+(?:-rf|-fr|-\s*r\s*f|[-/]s\s+[-/]q)[^;&|]{0,80}?(?:~|\/home\/|\/root|\/etc\/|\/usr\/|C:\\|%USERPROFILE%|%HOMEDRIVE%|\$HOME|\\$home)/i,
      },
      {
        re: /(?:rm|del)\s+(?:-rf|-fr)[^;&|]{0,80}?["'`]?\s*(?:\/|\.\s*;|[A-Za-z]:[\\/])\s*["'`]?/i,
      },
    ],
  },
  {
    id: 'SEN-FS-002',
    name: 'write-outside-workspace',
    severity: 'medium',
    category: 'filesystem',
    message: '写入工作区之外的绝对路径',
    description: '代码向 /etc、C:\、用户主目录等绝对路径写入文件。',
    recommendation: '确认写入目标;插件默认应只写自己的数据目录。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:writeFile|writeFileSync|appendFile|createWriteStream|mkdir|mkdirSync)\s*\([^)]{0,120}?(?:["'`]\/etc\/|["'`]\/usr\/|["'`]\/var\/|["'`]\/home\/|["'`]C:\\|["'`][A-Za-z]:\\|process\.env\.HOME|os\.homedir\s*\(\s*\)\s*\+)/i,
      },
    ],
  },
  {
    id: 'SEN-FS-003',
    name: 'permission-mutation',
    severity: 'medium',
    category: 'filesystem',
    message: '宽松权限修改 / 提权(chmod 777 / sudo / setuid 等)',
    description: '代码把文件设为宽松权限(777 / a+rwx / 递归 -R 置宽)或提权执行。严格权限(0o600/0o700/0o644/0o755 等)是良好实践,不在此列。',
    recommendation: '确认宽松权限与提权操作的必要性;插件代码中出现 sudo/777 应视为高度可疑。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      { re: /\bchmod\s*\([^)]{0,60}?(?:0o?777|777|0o?666|666|a\+rwx)\b/i },
      { re: /\bchmod\s+(?:-R\s+)?(?:777|666|a\+rwx)\b/i },
      { re: /\b(?:chown|sudo|setuid|setgid|chflags)\s*\(|["'`](?:sudo|chmod\s+777|chown)[ "'`]/i },
    ],
  },
  {
    id: 'SEN-FS-004',
    name: 'tempfile-in-exec',
    severity: 'low',
    category: 'filesystem',
    message: '执行命令中使用临时目录(/tmp 等)',
    description: 'shell 命令写入 /tmp 或 %TEMP%——配合下载执行是常见攻击链。',
    recommendation: '确认临时文件用途与清理逻辑。',
    filePattern: CODE,
    linePatterns: [
      { re: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\([^)]{0,160}?(?:\/tmp\/|%TEMP%|os\.tmpdir|mkdtemp)/i },
    ],
  },

  // ─────────────────────────── network ───────────────────────────
  {
    id: 'SEN-NET-001',
    name: 'network-call',
    severity: 'medium',
    category: 'network',
    message: '发起外发网络请求(fetch 绝对 URL / WebSocket / 套接字)',
    description: '插件存在出网能力。相对路径的同源调用(fetch(\'/plugin-api/...\'))是客户端插件与自家宿主的本地通道,不算外发;只有绝对 URL(http/https/ws)、协议相对(//host)或变量目标的调用才命中。',
    recommendation: '列出所有请求端点;确认无凭据、无工作区内容外传。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|WebSocket|EventSource)\s*\(\s*(?:["'`])(?:https?:|wss?:|\/\/)/i,
        note: '绝对 URL / 协议相对',
      },
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon)\s*\(\s*[A-Za-z_$][\w$.]*\s*[,)]/,
        note: '变量目标',
      },
      { re: /\b(?:http|https)\.(?:request|get)\s*\(/ },
      { re: /\b(?:net|dgram)\.(?:connect|createConnection|createSocket)\s*\(/ },
    ],
  },
  {
    id: 'SEN-NET-002',
    name: 'hardcoded-ip',
    severity: 'low',
    category: 'network',
    message: '代码中出现非本机的硬编码 IP 地址',
    description: '源码中直接出现公网 IPv4 字面量(排除 127.x / 10.x / 192.168.x / 172.16-31.x / 0.x / 255.x)。',
    recommendation: '确认该地址的用途与归属。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /["'`](?!0\.|10\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.(?:0\.0\.|0\.2\.|88\.99\.|168\.)|198\.(?:1[89]\.|51\.100\.)|203\.0\.113\.|(?:22[4-9]|23\d|24\d|25[0-5])\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\.)["'`]/,
      },
    ],
  },

  // ─────────────────────────── manifest / DSH bundle compliance ───────────────────────────
  {
    id: 'SEN-MAN-001',
    name: 'missing-package-manifest',
    severity: 'medium',
    category: 'manifest',
    message: '未找到 package.json',
    description: '扫描目标不是 npm 包结构,无法作为 DSH bundle 安装。',
    recommendation: '确认扫描的是插件仓库根目录。',
  },
  {
    id: 'SEN-MAN-002',
    name: 'not-a-dsh-bundle',
    severity: 'high',
    category: 'manifest',
    message: '不是 DSH bundle(缺少 dsh.bundle 声明)',
    description: 'package.json 中没有 dsh.bundle,`dsh plugin add` 不会激活其任何层。',
    recommendation: '若目标是 DSH 插件,补上 dsh.bundle.patch 声明;否则此仓库无法以插件形式安装。',
  },
  {
    id: 'SEN-MAN-003',
    name: 'patch-file-missing',
    severity: 'high',
    category: 'manifest',
    message: '声明的 patch 文件不存在',
    description: 'dsh.bundle.patch 指向的文件在包内缺失,安装后插件层不会生效(或安装失败)。',
    recommendation: '核对 files 列表与 patch 路径。',
  },
  {
    id: 'SEN-MAN-004',
    name: 'patch-row-invalid',
    severity: 'medium',
    category: 'manifest',
    message: 'patch 中存在缺少 id 或 name 的行',
    description: 'cordis.patch.yml 的行解析失败,loader 可能拒绝该层。',
    recommendation: '检查 patch 的 YAML 结构(id + name 必填)。',
  },
  {
    id: 'SEN-MAN-005',
    name: 'patch-entry-unresolvable',
    severity: 'medium',
    category: 'manifest',
    message: 'patch 引用的插件模块无法解析',
    description: 'patch 行 name 指向的子路径在包内不存在(或未在 exports 中声明)。',
    recommendation: '核对 name 子路径与 exports 映射。',
  },
  {
    id: 'SEN-MAN-006',
    name: 'plugin-entry-invalid',
    severity: 'high',
    category: 'manifest',
    message: '插件入口无效(缺少 name 或 apply 导出)',
    description: '入口模块未导出 Cordis 插件协议要求的 name/apply,加载会失败或静默无行为。',
    recommendation: '补上 export const name 与 export function apply(ctx)。',
  },
  {
    id: 'SEN-MAN-007',
    name: 'license-missing',
    severity: 'low',
    category: 'hygiene',
    message: '缺少许可证(license 字段)',
    description: 'package.json 未声明 license,安装与再分发存在法律风险。',
    recommendation: '补上 license 字段(如 MIT)。',
  },
  {
    id: 'SEN-MAN-008',
    name: 'description-missing',
    severity: 'low',
    category: 'hygiene',
    message: '缺少描述(description 字段)',
    description: 'package.json 未声明 description。',
    recommendation: '补上简短描述。',
  },
  {
    id: 'SEN-MAN-009',
    name: 'manifest-path-escape',
    severity: 'critical',
    category: 'manifest',
    message: 'manifest 路径逃逸扫描根目录(patch / main / exports / 入口名)',
    description: 'package.json 的 dsh.bundle.patch、main、exports 或 cordis.patch.yml 的入口名指向扫描根目录之外(如 ../../Users/xxx/.ssh)。攻击者可借此让扫描器读取目标目录之外的文件。',
    recommendation: '拒绝该包或修复 manifest 路径;所有路径必须解析在包根目录之内。',
  },
  {
    id: 'SEN-SUPPLY-001',
    name: 'remote-dependency-source',
    severity: 'high',
    category: 'supplychain',
    message: '依赖来源危险(git+http / http tarball / 本地文件 / workspace 逃逸)',
    description: 'package.json 依赖指向非标准来源:git+http(明文)、http:// tarball、file: 本地路径或 workspace: 引用。供应链攻击常通过劫持这类来源投放。',
    recommendation: '依赖应来自受信 registry(https);git 依赖应锁定 commit 并使用 https。',
    filePattern: /package\.json$/i,
    linePatterns: [
      { re: /["'][A-Za-z0-9@/._-]+["']\s*:\s*["'](?:git\+http:\/\/|http:\/\/[^"'#]+\.(?:tgz|tar\.gz)|file:|workspace:|\.\.\/)/i },
    ],
    // patch/main/exports/files 等键的路径由 SEN-MAN-009 containment 负责,不算依赖来源问题。
    excludes: [
      /^\s*"(?:patch|main|exports|files|bin)"\s*:/,
    ],
  },
  {
    id: 'SEN-SUPPLY-002',
    name: 'dependency-install-script',
    severity: 'medium',
    category: 'supplychain',
    message: '依赖包携带安装生命周期脚本(需审计依赖链)',
    description: '依赖元数据显示依赖包含 preinstall/install/postinstall 脚本。安装时以用户完整权限执行,是供应链攻击的主要载体。',
    recommendation: '审查依赖链中所有 install 脚本内容;尽量选择无生命周期脚本的依赖。',
  },
  {
    id: 'SEN-SUPPLY-004',
    name: 'integrity-mismatch',
    severity: 'high',
    category: 'supplychain',
    message: 'tarball integrity 与 registry 声明不一致',
    description: '下载的 tarball 的 sha512 与 registry 返回的 integrity 字段不匹配——可能是传输篡改、镜像污染或注册表被入侵。',
    recommendation: '拒绝安装;从可信渠道重新获取并复核来源。',
  },
  {
    id: 'SEN-SUPPLY-005',
    name: 'tar-path-traversal',
    severity: 'critical',
    category: 'supplychain',
    message: 'tarball 解包路径逃逸 / 符号链接 / 硬链接(zip-slip 类攻击)',
    description: '包内条目试图写入解包目录之外(../../)、绝对路径或通过 symlink/hardlink 逃逸隔离目录。',
    recommendation: '拒绝安装;这是恶意打包的典型特征。',
  },

  // ─────────────────────────── agent(Harness Tool 语义规则,由 semantic 引擎产生)───────────────────────────
  {
    id: 'SEN-AGENT-001',
    name: 'model-controlled-shell',
    severity: 'critical',
    category: 'agent',
    message: '模型可控输入进入 shell 执行(execute(args) → exec/spawn)',
    description: 'defineTool 的 execute(args) 中,模型可控参数(args.*)直接或经变量传播进入 shell 执行器。',
    recommendation: '拒绝把模型输入直接拼进 shell 命令;用参数数组形式 spawn(cmd, [args]) 并做白名单校验。',
  },
  {
    id: 'SEN-AGENT-002',
    name: 'model-controlled-file-read',
    severity: 'high',
    category: 'agent',
    message: '模型可控输入进入文件读取(execute(args) → readFile)',
    description: '模型可控参数进入文件读取调用,若无 workspace containment 则模型可读任意文件。',
    recommendation: '文件读取必须做 workspace containment(先 resolve 再校验在根目录内)。',
  },
  {
    id: 'SEN-AGENT-003',
    name: 'model-controlled-file-write',
    severity: 'high',
    category: 'agent',
    message: '模型可控输入进入文件写入(execute(args) → writeFile)',
    description: '模型可控参数进入文件写入调用,可写 HOME / 系统目录 / DSH profile / 其他插件目录。',
    recommendation: '文件写入必须做 workspace containment,并拒绝写入 HOME / 系统目录 / DSH profile。',
  },
  {
    id: 'SEN-AGENT-004',
    name: 'model-controlled-network-target',
    severity: 'high',
    category: 'agent',
    message: '模型可控输入进入网络请求目标(execute(args) → fetch/axios)',
    description: '模型可控参数成为网络请求 URL,即 SSRF / 任意出网能力面。',
    recommendation: '限制协议(http/https)与目标(禁 localhost / 内网 / 云元数据 169.254.169.254)。',
  },

  // ─────────────────────────── taint(污点传播,由语义引擎产生)───────────────────────────
  {
    id: 'SEN-TAINT-001',
    name: 'secret-to-network',
    severity: 'critical',
    category: 'taint',
    message: '凭据(env)流向网络请求,存在外传风险',
    description: 'process.env 中的凭据(API key/token/secret)直接或经变量传播进入网络请求。',
    recommendation: '确认请求目标完全可信;凭据绝不应流向非官方端点。',
  },
  {
    id: 'SEN-TAINT-002',
    name: 'workspace-to-network',
    severity: 'high',
    category: 'taint',
    message: '文件读取结果流向网络请求,存在源码/数据外传风险',
    description: 'readFile 等读取的结果(可能是工作区源码/配置)进入网络请求体。',
    recommendation: '确认工作区内容不会随网络请求离开本机。',
  },
  {
    id: 'SEN-TAINT-003',
    name: 'decode-to-exec-flow',
    severity: 'critical',
    category: 'taint',
    message: '解码后的内容流向动态执行,疑似混淆载荷',
    description: 'base64/hex/URI 解码(Buffer.from/atob/fromCharCode 等)的结果进入 eval/Function/exec。',
    recommendation: '解码内容必须人工复核;无文档说明的解码执行按恶意处理。',
  },

  // ─────────────────────────── agent:Harness 专属(Phase 6)───────────────────────────
  {
    id: 'SEN-AGENT-005',
    name: 'tool-prompt-poisoning',
    severity: 'medium',
    category: 'agent',
    message: '工具/指令文本疑似 prompt 投毒短语',
    description: 'defineTool 描述或指令文本含 "ignore previous instructions" / "do not tell the user" 等短语。注意:防御性说明也可能出现同类文字,需结合上下文。',
    recommendation: '人工判断短语是防御性说明还是恶意指令。',
  },
  {
    id: 'SEN-AGENT-006',
    name: 'capability-mismatch',
    severity: 'medium',
    category: 'agent',
    message: '工具描述与代码能力明显不符(潜在隐藏副作用)',
    description: '工具描述看似普通(天气/问候/换算等),但代码含 exec/fetch/文件读写等敏感能力。',
    recommendation: '人工核对工具描述与实际行为的差异。',
  },

  // ─────────────────────────── binary(由 engine/binary 产生)───────────────────────────
  {
    id: 'SEN-BIN-001',
    name: 'native-binary-present',
    severity: 'info',
    category: 'binary',
    message: '携带原生二进制(native binary present)',
    description: '插件包内含可执行原生代码(.exe/.dll/.so/.node 等)。可能完全正当(构建工具/平台库),但原生代码无法逐行静态审阅,需人工确认来源。',
    recommendation: '核对二进制与源码仓库的对应关系;无源码对应的原生代码按高度可疑处理。',
  },
  {
    id: 'SEN-BIN-002',
    name: 'suspicious-binary-strings',
    severity: 'medium',
    category: 'binary',
    message: '二进制内发现可疑字符串(外传端点/凭据标记/shell 工具)',
    description: '原生二进制的可打印字符串含 webhook/discord/ngrok、AWS_/API_KEY、curl/powershell、.ssh 等标记。注意:仅凭字符串不能判恶意,但必须人工复核。',
    recommendation: '人工检查二进制行为;无正当理由视为高度可疑。',
  },
  {
    id: 'SEN-BIN-003',
    name: 'high-entropy-binary',
    severity: 'medium',
    category: 'binary',
    message: '高熵二进制(疑似压缩/加密/加壳)',
    description: '采样熵值过高,通常表示压缩/加密/加壳。不直接判恶意,但意味着无法静态核验内容。',
    recommendation: '与构建产物对比;加壳二进制需人工复核。',
  },
  {
    id: 'SEN-WASM-001',
    name: 'wasm-module-present',
    severity: 'info',
    category: 'binary',
    message: '包含 WebAssembly 模块',
    description: '包内含 .wasm 模块。WASM 常用于合法性能敏感代码,也可能用于隐藏逻辑。',
    recommendation: '确认 WASM 来源与构建方式;无文档说明的原生/WASM 代码需人工复核。',
  },

  // ─────────────────────────── persistence(最低限度)───────────────────────────
  {
    id: 'SEN-PERSIST-001',
    name: 'persistence-mechanism',
    severity: 'medium',
    category: 'persistence',
    message: '使用系统持久化机制(cron / 计划任务 / 注册表 Run / systemd / launchd / Startup)',
    description: '代码注册自启动/定时任务:可让代码在用户不知情时反复执行。部分监控/提醒类工具有正当需求,但必须人工确认。',
    recommendation: '确认持久化机制的必要性与可见性;任何"安装后自启动"行为都应向用户明示。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      { re: /\b(?:crontab|schtasks|systemctl\s+enable|update-rc\.d|launchctl|reg\s+add)[^;\n]{0,120}/i },
      { re: /(?:HKCU|HKLM)[\\/][^;\n]{0,120}?\\Run\b/i },
      { re: /Startup\s*(?:folder|directory)|AppData[\\/]Roaming[\\/]Microsoft[\\/]Windows[\\/]Start\s+Menu/i },
    ],
  },
  {
    id: 'SEN-PERSIST-002',
    name: 'shell-profile-persist',
    severity: 'high',
    category: 'persistence',
    message: '写入 shell profile(.bashrc/.zshrc/PowerShell profile)——持久后门特征',
    description: '代码向 .bashrc/.zshrc/.profile 或 PowerShell $PROFILE 写入内容。正常插件没有任何理由修改用户的 shell 启动文件。',
    recommendation: '视为高度可疑:修改 shell profile 是经典持久化后门,需人工逐行确认。',
    filePattern: CODE,
    ignoreComments: true,
    linePatterns: [
      {
        re: /(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|openSync|exec|execSync|spawn|spawnSync)[^;\n]{0,120}?(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|Microsoft\.PowerShell_profile|profile\.ps1)/i,
      },
    ],
  },
])

/** Rules that are purely manifest/hygiene and produce one finding per target. */
export const MANIFEST_RULES = Object.freeze(RULES.filter((r) => r.category === 'manifest' || r.category === 'hygiene'))

export function severityWeight(severity) {
  return SEVERITY_WEIGHT[severity] ?? 0
}
