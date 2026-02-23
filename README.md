# 🎓 Campus Auto Login

> 校园网自动认证登录工具（Windows），开机即连网，无需手动操作。

支持 WiFi / 有线自动识别，兼容 Mihomo / Clash 等代理工具的 **Fake-IP 模式**，基于 [Srun](https://www.srun.com/) 深澜认证系统。

---

## ✨ 特性

- **开机自动认证** —— 通过 Windows 计划任务在登录时自动后台运行
- **WiFi / 有线双模** —— 自动识别网络接入类型，按规则判断就绪状态
- **Portal 自动发现** —— 利用 DNS 劫持探测自动获取正确的 Portal URL 和 `ac_id`
- **Fake-IP 兼容** —— 自动检测代理工具虚拟网卡，添加路由绕行确保认证请求直连
- **多层容错** —— 重试机制、fallback URL、API + rad_user_info 双重验证
- **安全日志** —— 自动脱敏用户名/密码/Token，按日期轮转，支持大小和数量上限
- **零窗口干扰** —— VBS 隐藏启动器，后台静默完成全部流程

---

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     Windows 计划任务 (ONLOGON)                   │
│                              ▼                                   │
│              run-campus-login-hidden.vbs                         │
│                    (隐藏窗口启动)                                  │
│                              ▼                                   │
│  ┌───────────── run-campus-login.ps1 (PowerShell 入口) ──────┐  │
│  │                                                            │  │
│  │  Step 1: 网卡枚举 & Fake-IP 检测                            │  │
│  │    • 扫描所有网卡，识别 198.18/198.19 IP 段                  │  │
│  │    • 检测 Mihomo/Clash/Sing-box/WireGuard 虚拟网卡           │  │
│  │                                                            │  │
│  │  Step 2: 网络就绪检查                                       │  │
│  │    • WiFi → 轮询 SSID 是否匹配 (如 xju_*)                  │  │
│  │    • 有线 → 检查 IP 是否匹配 (如 10.*)                      │  │
│  │    • 最长等待 120s，超时退出                                  │  │
│  │                                                            │  │
│  │  Step 3: 在线状态检查 & 认证准备                              │  │
│  │    • rad_user_info 预检：已在线则跳过认证                      │  │
│  │    • Fake-IP 模式：添加路由绕行 + 临时 hosts 映射             │  │
│  │                           ▼                                │  │
│  │  ┌─────────── login.js (Node.js 认证核心) ──────────┐      │  │
│  │  │  1. HTTP 预检探测 Portal 可达性                    │      │  │
│  │  │  2. 自动发现 Portal URL（DNS 劫持/body 提取）       │      │  │
│  │  │  3. Playwright 打开页面、填写账号密码、点击登录       │      │  │
│  │  │  4. 监听 srun_portal API 响应确认结果               │      │  │
│  │  │  5. rad_user_info 轮询二次确认                      │      │  │
│  │  └────────────────────────────────────────────────────┘      │  │
│  │                                                            │  │
│  │  Cleanup: 清除路由绕行规则 + 临时 hosts 条目                  │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| Windows | 10 / 11 | 需要 PowerShell 5.1+（系统自带） |
| Node.js | 18+ | 需要全局 `fetch` API |
| 浏览器 | Edge / Chrome | Playwright 会调用系统已安装的浏览器 |

> [!IMPORTANT]
> 脚本需要以 **管理员身份** 运行 PowerShell。Fake-IP 模式下添加路由绕行规则（`route ADD`）、写入临时 hosts 映射、以及创建计划任务均需要管理员权限。

---

## 🚀 快速开始

### 1. 克隆项目

```powershell
git clone https://github.com/shubeipishu/campus-autologin.git
cd campus-autologin
```

### 2. 安装依赖

```powershell
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1 -Setup
```

> 该命令会自动执行 `npm install playwright`，安装 Playwright 浏览器驱动。

### 3. 配置账号

```powershell
Copy-Item .\config.example.json .\config.json
notepad .\config.json
```

**必填参数：**

| 参数 | 说明 | 示例 |
|---|---|---|
| `username` | 学号 / 工号 | `"your_student_id"` |
| `password` | 认证密码 | `"your_password"` |
| `operator` | 运营商 | `"中国移动"` / `"中国电信"` / `"中国联通"` |

> [!TIP]
> **密码安全**：推荐使用环境变量存储密码，避免明文写入配置文件：
> ```powershell
> [Environment]::SetEnvironmentVariable("CAMPUS_PASSWORD", "你的密码", "User")
> ```
> 然后将 `config.json` 中的 `password` 留空即可，脚本会自动从环境变量 `CAMPUS_PASSWORD` 读取。

### 4. 测试运行

以**管理员身份**打开 PowerShell，然后执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1
```

> [!TIP]
> 调试时可将 `config.json` 中的 `headless` 设为 `false`，这样可以看到浏览器操作过程。

### 5. 设置开机自启

> [!IMPORTANT]
> 需要以**管理员身份**运行 PowerShell，否则计划任务创建可能失败。

```powershell
powershell -ExecutionPolicy Bypass -File .\install-task.ps1
```

> 计划任务以最高权限（`/RL HIGHEST`）运行，确保路由绕行和 hosts 写入正常工作。

脚本会创建名为 `CampusNetAutoLogin` 的计划任务，Windows 登录时自动后台运行（无窗口弹出，笔记本电池模式同样生效）。

> 如果计划任务创建失败，脚本会自动 fallback 到 `HKCU\...\Run` 注册表启动项。

### 6. 卸载自启

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-task.ps1
```

---

## ⚙️ 配置参数详解

完整配置参见 [`config.example.json`](config.example.json)。

### 核心参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `username` | — | 学号 / 工号 |
| `password` | — | 认证密码（环境变量优先） |
| `operator` | — | 运营商：`中国移动` / `中国电信` / `中国联通` |
| `passwordEnvVar` | `"CAMPUS_PASSWORD"` | 密码环境变量名 |
| `domainValue` | `""` | 手动指定线路（`@cmcc` / `@ctcc` / `@cucc`），设置后 `operator` 被忽略 |
| `operatorSuffix` | `""` | 拼接到用户名后的后缀（当未设置 `domainValue` 和 `operator` 时使用） |

### Portal 与自动发现

| 参数 | 默认值 | 说明 |
|---|---|---|
| `portalUrl` | — | Portal 页面 URL（自动发现失败时的 fallback） |
| `autoDiscoverPortal` | `true` | 是否通过 DNS 劫持探测自动发现 Portal URL |
| `detectUrls` | `["http://www.msftconnecttest.com/redirect"]` | 自动发现探测地址列表 |
| `detectAttempts` | `10` | 自动发现最大重试轮数 |
| `detectTimeoutMs` | `1000` | 单次探测超时（网关劫持通常 < 1s） |

### 网络检查

| 参数 | 默认值 | 说明 |
|---|---|---|
| `wifiSsidPrefixes` | `["xju_"]` | 允许的 WiFi SSID 前缀列表 |
| `wifiWaitMaxSec` | `120` | 等待网络就绪的最大秒数 |
| `wifiWaitIntervalSec` | `3` | 网络就绪轮询间隔（秒） |
| `requireIpPrefix` | `"10."` | 有线网络要求的 IP 前缀 |
| `requireGatewayPrefix` | `"10."` | 网关地址要求的前缀 |

### Fake-IP 与路由绕行

| 参数 | 默认值 | 说明 |
|---|---|---|
| `useRouteBypassDuringAuth` | `true` | Fake-IP 模式下为认证目标添加路由绕行 |
| `useTemporaryHostsDuringAuth` | `false` | Fake-IP 模式下临时写入 hosts 文件映射 |
| `temporaryHostsMappings` | `{"www.msftconnecttest.com":"23.214.95.200"}` | 临时 hosts 映射表 |
| `routeBypassStaticIps` | — | 为域名配置静态 IPv4，跳过 DNS 解析直接添加路由 |
| `disableIpv6Auth` | `true` | 阻止浏览器向 IPv6 地址发起认证请求 |

### 浏览器与重试

| 参数 | 默认值 | 说明 |
|---|---|---|
| `browserChannel` | `"msedge"` | 浏览器引擎：`msedge` / `chrome` / `chromium` |
| `headless` | `true` | 无头模式（调试时设为 `false` 可看到浏览器窗口） |
| `maxRetries` | `6` | 最大重试次数 |
| `retryDelayMs` | `20000` | 重试间隔（ms） |
| `timeoutMs` | `20000` | 页面加载超时（ms） |
| `resultTimeoutMs` | `4000` | 登录结果等待超时（ms） |
| `postClickDelayMs` | `300` | 点击登录按钮后等待 API 响应的延迟（ms） |
| `portalOpenRetries` | `3` | Portal 页面打开失败的重试次数 |

### 日志配置

| 参数 | 默认值 | 说明 |
|---|---|---|
| `logDir` | `"logs"` | 日志目录（相对路径基于项目目录） |
| `logMaxSizeMB` | `5` | 单日志文件大小上限（MB），超出后自动轮转 |
| `logMaxFiles` | `30` | 最多保留日志文件数 |
| `saveArtifacts` | `true` | 登录失败时保存截图和页面快照 |
| `logPortalResponseBody` | `false` | 日志中记录完整 Portal API 响应体 |
| `verboseLogs` | `false` | 启用详细日志（PowerShell + Node.js） |
| `verboseNetworkLogs` | `false` | 启用详细网络请求日志 |
| `writePowerShellLogsToNodeLog` | `true` | PowerShell 日志写入 Node.js 同一日志文件 |

---

## 🔧 调试工具

### Portal 探测工具

`probe-portal.js` 是一个独立的诊断工具，可用于调试 Portal 自动发现问题：

```powershell
# 使用默认探测地址
node probe-portal.js

# 指定探测地址和超时
node probe-portal.js "http://www.msftconnecttest.com/redirect" 5000
```

输出信息包括：HTTP 状态码、重定向地址、响应头、响应体以及从中提取到的 Portal URL 候选列表。

---

## 🐛 故障排查

### 查看最新日志

```powershell
Get-Content (Get-ChildItem .\logs\campus-login-*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Tail 50
```

### 查看计划任务状态

```powershell
schtasks /Query /TN CampusNetAutoLogin /V /FO LIST
```

### 常见问题

| 现象 | 排查方向 |
|---|---|
| `rad_user_info reports offline` 后登录成功 | ✅ 正常流程，说明自动认证生效 |
| `Auto discover: no gateway hijack` | 网关未劫持探测 URL → 配置 `portalUrl` 作为 fallback |
| `Cannot find login button` | Portal 页面结构变化 → 检查 `portalUrl` 是否正确 |
| `Cannot find username/password input fields` | Portal 页面改版 → 确认 Portal 页面可正常打开 |
| `Browser launch failed with channel=msedge` | 未安装 Edge → 修改 `browserChannel` 为 `chrome` |
| 笔记本电池模式不触发 | 重新运行 `install-task.ps1` 更新电池设置 |
| `Network wait timeout` | WiFi 未连接或 SSID 不在 `wifiSsidPrefixes` 列表中 |
| Fake-IP 模式下认证失败 | 检查路由绕行是否生效，尝试启用 `useTemporaryHostsDuringAuth` |
| `Temporary hosts mapping failed` | 写入 hosts 需要管理员权限 → 以管理员身份运行或关闭此功能 |

---

## 📁 文件结构

```
campus-autologin/
├── login.js                      # Node.js 认证核心（Playwright 自动化登录）
├── run-campus-login.ps1          # PowerShell 入口（网卡检测 → 网络就绪 → 路由绕行 → 调用 login.js）
├── run-campus-login-hidden.vbs   # VBS 隐藏窗口启动器（计划任务调用入口）
├── probe-portal.js               # Portal 探测诊断工具
├── install-task.ps1              # 安装开机自启计划任务
├── uninstall-task.ps1            # 卸载计划任务 & 注册表启动项
├── config.example.json           # 配置模板（包含所有可选参数及注释）
├── config.json                   # 用户配置（.gitignore 已排除）
├── package.json                  # Node.js 依赖声明
└── logs/                         # 运行日志 & 失败截图（.gitignore 已排除）
```

---

## 📄 License

[ISC](https://opensource.org/licenses/ISC)
