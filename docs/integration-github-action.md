# 集成:GitHub Action + SARIF Code Scanning

## 定位(重要)

- **SARIF 是报告交换格式,不是检测引擎**——真正检测能力来自 dsh-sentinel engine
- **GitHub Action 是自动化执行层,不是新算法**——它只是按配置运行 CLI 并上传结果
- 因此:Action 上线 ≠ 安全能力增强;扫描质量取决于 engine 本身

## 使用方式

在目标仓库添加 `.github/workflows/sentinel.yml`:

```yaml
name: DSH Sentinel

on:
  pull_request:
  push:
    branches: [master, main]

permissions:
  contents: read
  security-events: write

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: Eligahyu/dsh-sentinel-scanner@v0.4
        with:
          path: .
          mode: source      # source(默认)| package | profile
          fail-on: high     # critical|high|medium|low
          fail-on-incomplete: 'false'
          max-files: 3000

      - name: Upload SARIF to Code Scanning
        if: always() && hashFiles('sentinel.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: sentinel.sarif
```

## inputs

| input | 默认 | 说明 |
| --- | --- | --- |
| `path` | `.` | 扫描目标(目录或单文件) |
| `mode` | `source` | 扫描模式;package 会扫描 dist/build 等构建产物 |
| `fail-on` | `high` | 任一 finding ≥ 该级别时 job 失败 |
| `fail-on-incomplete` | `false` | 扫描不完整时以退出码 3 失败 |
| `max-files` | `3000` | 扫描文件数上限 |
| `sarif-file` | `sentinel.sarif` | SARIF 输出文件名 |

## outputs

| output | 说明 |
| --- | --- |
| `exit-code` | 0 通过 / 1 阈值被超过 / 2 运行错误 / 3 不完整扫描 |
| `sarif-path` | SARIF 文件绝对路径 |

## 实现说明

- Action 是自包含 composite action,直接运行仓库内 `bin/sentinel.mjs`;
  AST 依赖的 acorn 已 vendored 到 `.github/actions/dsh-sentinel/vendor/`
  (engine/semantic/ast.js 在包依赖缺失时自动回退到 vendored 副本)
- SARIF 输出使用仓库相对路径(不写本机绝对路径),每个结果带稳定指纹
  (rule + 归一化文件 + source + sink,不依赖行号)——代码移动不会产生全新告警
- Code Scanning 中可看到形如:
  `plugin/index.js:35 · SEN-AGENT-001 · Model-controlled input flows into shell execution`

## 本地验证

```sh
node bin/sentinel.mjs . --format sarif --out sentinel.sarif --fail-on high
# 校验 SARIF schema 结构
node -e "const s=require('./sentinel.sarif'); if(s.version!=='2.1.0'||!s.runs[0].results) process.exit(1)"
```

## 验收(§48)

- safe fixture → exit 0(pass)
- critical fixture → exit 1(fail)
- SARIF → 文件有效(version 2.1.0、tool.driver、rules、results、fingerprints 齐全)
- workflow 语法、upload 步骤设计、permissions 配置如上

> 说明:本地无法真正调用 GitHub Code Scanning API;上述通过本地 CLI +
> SARIF schema 校验验证,workflow 在仓库 CI 中运行时由 GitHub 侧执行。
