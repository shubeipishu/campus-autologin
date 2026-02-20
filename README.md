# 校园网自动登录脚本（Windows）

## 环境要求
- Windows 10/11
- Windows PowerShell 5.1 及以上（推荐 5.1 或 PowerShell 7）
- Node.js 18 及以上（`login.js` 使用全局 `fetch`）
- 系统组件：`schtasks`、`wscript`（均为 Windows 自带）

## 1) 初始化依赖
在 PowerShell 里运行：

```powershell
cd C:\Users\admin\campus-autologin
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1 -Setup
```

## 2) 配置账号密码

```powershell
Copy-Item .\config.example.json .\config.json
if (Get-Command notepad.exe -ErrorAction SilentlyContinue) { notepad.exe .\config.json } else { Start-Process .\config.json }
```

推荐用环境变量保存密码（避免写入明文）：

```powershell
[Environment]::SetEnvironmentVariable("CAMPUS_PASSWORD", "你的密码", "User")
```

`config.json` 中将 `password` 留空，脚本会优先读取 `passwordEnvVar`（默认 `CAMPUS_PASSWORD`）。

`portalUrl` 与自动探测：
- 建议开启 `autoDiscoverPortal: true`
- 脚本会先访问 `detectUrl`（默认 `http://www.msftconnecttest.com/redirect`）
- 可配置 `detectUrls` 作为多探测地址列表，依次尝试
- 若被重定向到校园网 `srun_portal_pc`，会直接使用该链接
- 若未探测到，会回退到 `portalUrl`
- `startupDelayMs` 可用于开机后先等几秒再探测（避免网卡未就绪）
- `portalOpenRetries` 用于 portal 页面打开失败时同次重试（如 `ERR_EMPTY_RESPONSE`）
- 脚本会自动检测本机是否存在 `198.*` IPv4（常见于 Clash Fake-IP）；命中后会只使用校园网 portal 地址进行 refresh/detect/probe，避免外部探测地址超时拖慢流程

认证前网关刷新：
- `preAuthRefresh: true` 时，登录前先刷新网关页面，减少状态不同步
- `refreshUrls` 为刷新地址列表（可放 portal 与 detect 链接）
- `refreshCount` 刷新轮数，`refreshTimeoutMs` 单次超时，`refreshDelayMs` 每次间隔

认证前网络就绪检查：
- `preflightCheck: true` 开启前置检查
- `requireIpPrefix` 可要求拿到指定网段 IP（如 `10.`）
- 自动读取系统默认网关（IPv4）并校验；若存在多网卡（如 Clash Fake-IP `198.18.x.x`），会优先匹配 `requireIpPrefix` 对应的默认路由
- `requireGatewayPrefix` 可要求默认网关前缀（如 `10.`）
- `checkGatewayPing` 控制是否 Ping 默认网关
- `gatewayPingTimeoutMs` 为 Ping 超时
- `gatewayHost` 用于 DNS 检查（默认从 `portalUrl` 解析）
- `preflightProbeUrls` 用于连通性探测
- `preflightWaitMaxMs`/`preflightIntervalMs` 控制等待时长与轮询间隔

执行前 Wi-Fi 与 DHCP：
- `enforceWifiSsidCheck: true` 时，先检查当前 Wi-Fi SSID
- `wifiSsidPrefixes` 允许的 SSID 前缀列表（如 `xju_`）
- `wifiWaitMaxSec` / `wifiWaitIntervalSec` 控制 Wi-Fi 轮询等待时长（默认最多轮询 120 秒）；即使当前连到其他 Wi-Fi 也会持续等待，便于开机后手动切换
- 脚本会在 DHCP 刷新前先调用 `login.js --check-online-only` 进行严格在线检测（与主流程同一套判定）；若无需认证会直接退出
- `dhcpRefreshBeforeAuth: true` 时，登录前执行 `ipconfig /release` + `ipconfig /renew`
- `dhcpRefreshPauseSec` 控制 release 与 renew 之间间隔

已在线跳过认证：
- `skipAlreadyOnlineCheck: false` 时，先做外网连通性检测
- 若判定已联网（认证未过期），脚本直接成功返回，不再重复认证
- 现改为检查校园网状态页 `statusUrl`（更严格，避免误判）
- 命中 `srun_portal_success` 后，会联合页面关键字和 `rad_user_info` 状态判定，降低误判为未在线的概率
- `onlineCheckTimeoutMs` 可调检测超时

`operator` 必填，支持：
- `中国移动`
- `中国电信`
- `中国联通`

脚本会自动映射线路值（`@cmcc/@ctcc/@cucc`），`username` 请填纯学号/工号，`operatorSuffix` 留空即可。

调试建议：
- 将 `headless` 改为 `false`，可看到浏览器实际操作过程
- `saveArtifacts` 建议保持 `true`，失败会保存截图和页面快照
- `browserChannel` 默认 `msedge`，若启动失败会自动回退到 Playwright 默认 Chromium
- 日志默认在 `C:\Users\admin\campus-autologin\logs`
- 默认只记录脱敏日志；`logPortalResponseBody: true` 时才会记录脱敏后的响应体
- `logMaxSizeMB` 控制单个日志文件上限（默认 5MB），超过会自动切分
- `logMaxFiles` 控制最多保留的日志文件数量（默认 30），超出会自动删除最旧日志
- `disableIpv6Auth: true`（默认）会拦截 IPv6 的认证请求，仅走 IPv4，通常可减少双栈超时带来的额外等待
- 若历史日志是在旧版本生成，建议手动清理一次 `logs` 目录
- `resultTimeoutMs` 控制点击登录后等待结果的时长（默认 10000ms）
- `postClickDelayMs` 控制点击后短暂停顿（默认 300ms）

## 3) 手动测试一次

```powershell
powershell -ExecutionPolicy Bypass -File .\run-campus-login.ps1
```

## 4) 设置登录后自动执行

```powershell
powershell -ExecutionPolicy Bypass -File .\install-task.ps1
```

## 5) 任务管理
查看：
```powershell
schtasks /Query /TN CampusNetAutoLogin /V /FO LIST
```

删除：
```powershell
schtasks /Delete /TN CampusNetAutoLogin /F
```

## 6) 故障排查
查看最新日志：
```powershell
Get-ChildItem .\logs | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name,LastWriteTime,Length
Get-Content (Get-ChildItem .\logs\campus-login-*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Tail 120
```
