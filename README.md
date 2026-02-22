# 校园网自动登录脚本（Windows）

开机后自动连接校园网认证，无需手动打开浏览器登录。支持 WiFi / 有线自动识别，兼容 Mihomo / Clash 等代理工具的 Fake-IP 模式。

## 工作原理

```
开机 → 计划任务触发 → VBS 隐藏窗口 → PowerShell 入口
  │
  ├── 1. 网卡枚举 & Fake-IP 检测
  │     扫描所有网卡，识别 198.18.* IP 或 Mihomo/Clash 虚拟网卡
  │
  ├── 2. 网络就绪检查
  │     WiFi → 检查 SSID 是否匹配（如 xju_*）
  │     有线 → 检查 IP 是否匹配（如 10.*）
  │
  └── 3. Node.js 认证
        rad_user_info API 判断在线状态（已在线直接退出）
        → 自动发现 Portal URL（DNS 劫持探测）
        → Playwright 填写账号密码并登录
        → rad_user_info 确认登录成功
```

## 环境要求

- Windows 10 / 11
- Node.js 18+（需要全局 `fetch`）
- PowerShell 5.1+

## 快速开始

### 1. 安装依赖

```powershell
Set-Location "你的项目目录\campus-autologin"
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1 -Setup
```

### 2. 配置账号

```powershell
Copy-Item .\config.example.json .\config.json
notepad .\config.json
```

必填参数：

| 参数 | 说明 | 示例 |
|---|---|---|
| `username` | 学号 / 工号 | `"107556524108"` |
| `password` | 认证密码 | `"your_password"` |
| `operator` | 运营商 | `"中国移动"` / `"中国电信"` / `"中国联通"` |

> **安全建议**：使用环境变量存储密码，避免明文写入配置文件：
> ```powershell
> [Environment]::SetEnvironmentVariable("CAMPUS_PASSWORD", "你的密码", "User")
> ```
> 然后将 `config.json` 中的 `password` 留空即可。

### 3. 测试运行

```powershell
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1
```

### 4. 设置开机自启

```powershell
powershell -ExecutionPolicy Bypass -File .\install-task.ps1
```

脚本会创建计划任务 `CampusNetAutoLogin`，登录 Windows 时自动后台运行（无窗口）。

### 5. 卸载自启

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-task.ps1
```

## 配置参数说明

### 核心参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `username` | - | 学号 / 工号 |
| `password` | - | 认证密码（环境变量优先） |
| `operator` | - | `中国移动` / `中国电信` / `中国联通` |
| `passwordEnvVar` | `"CAMPUS_PASSWORD"` | 密码环境变量名 |
| `domainValue` | `""` | 手动指定线路（`@cmcc`/`@ctcc`/`@cucc`），留空自动映射 |

### Portal 与自动发现

| 参数 | 默认值 | 说明 |
|---|---|---|
| `portalUrl` | - | Portal 页面 URL（自动发现失败时使用） |
| `autoDiscoverPortal` | `true` | 是否通过 DNS 劫持探测 Portal URL |
| `detectUrls` | `["http://www.msftconnecttest.com/redirect"]` | 自动发现探测地址 |
| `detectTimeoutMs` | `3000` | 自动发现超时（网关劫持通常 < 1s） |

### 网络检查

| 参数 | 默认值 | 说明 |
|---|---|---|
| `wifiSsidPrefixes` | `["xju_"]` | 允许的 WiFi SSID 前缀 |
| `wifiWaitMaxSec` | `120` | 等待网络就绪的最大秒数 |
| `wifiWaitIntervalSec` | `3` | 网络就绪轮询间隔 |

### 浏览器与重试

| 参数 | 默认值 | 说明 |
|---|---|---|
| `browserChannel` | `"msedge"` | 浏览器引擎（`msedge` / `chrome` / `chromium`） |
| `headless` | `true` | 无头模式（调试时设为 `false` 可看到浏览器） |
| `maxRetries` | `6` | 最大重试次数 |
| `retryDelayMs` | `20000` | 重试间隔（ms） |
| `timeoutMs` | `20000` | 页面加载超时 |
| `resultTimeoutMs` | `4000` | 登录结果等待超时 |

### 日志

| 参数 | 默认值 | 说明 |
|---|---|---|
| `logDir` | `"./logs"` | 日志目录 |
| `logMaxSizeMB` | `5` | 单日志文件上限 |
| `logMaxFiles` | `30` | 最多保留日志文件数 |
| `saveArtifacts` | `true` | 失败时保存截图和页面快照 |

## 故障排查

查看最新日志：

```powershell
Get-Content (Get-ChildItem .\logs\campus-login-*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Tail 30
```

查看计划任务状态：

```powershell
schtasks /Query /TN CampusNetAutoLogin /V /FO LIST
```

常见问题：

| 现象 | 排查方向 |
|---|---|
| `rad_user_info reports offline` 后登录成功 | 正常流程，说明自动认证生效 |
| `Auto discover: no gateway hijack` | 网关未劫持探测 URL，使用 `portalUrl` fallback |
| `Cannot find login button` | Portal 页面结构变化，检查 `portalUrl` 是否正确 |
| 笔记本电池模式不触发 | 重新运行 `install-task.ps1` 更新电池设置 |

## 文件结构

```
campus-autologin/
├── login.js                      # Node.js 认证核心逻辑
├── run-campus-login.ps1          # PowerShell 入口（网卡检测 + 网络就绪）
├── run-campus-login-hidden.vbs   # 隐藏窗口启动器
├── install-task.ps1              # 安装开机自启计划任务
├── uninstall-task.ps1            # 卸载计划任务
├── config.json                   # 用户配置（不提交 Git）
├── config.example.json           # 配置模板
└── logs/                         # 运行日志
```
