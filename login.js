const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const os = require('os');
const dns = require('dns').promises;
const { URL } = require('url');
const { execSync } = require('child_process');

const SENSITIVE_QUERY_KEYS = new Set([
  'password',
  'username',
  'chksum',
  'info',
  'token',
  'access_token',
  'usermac',
  'userip'
]);

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ts() {
  return new Date().toISOString();
}

function hhmmss() {
  const d = new Date();
  const p2 = (n) => String(n).padStart(2, '0');
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
}

function shouldInsertConsoleGap(msg) {
  const x = String(msg || '');
  return (
    x.startsWith('===== Campus Auto Login Start =====') ||
    /^Attempt \d+\/\d+/.test(x) ||
    x.startsWith('Preflight probing ...') ||
    x.startsWith('Pre-auth refresh:') ||
    x.startsWith('Auto discover portal via:') ||
    x.startsWith('Open page:') ||
    x.startsWith('Click login button.') ||
    x.startsWith('Login result:') ||
    x.startsWith('Campus login success.') ||
    x.startsWith('Attempt failed:')
  );
}

function nowFileSafe() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function toPositiveInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.floor(n);
}

function listManagedLogFiles(logDir) {
  if (!fs.existsSync(logDir)) return [];
  return fs
    .readdirSync(logDir)
    .filter((name) => /^campus-login-\d{4}-\d{2}-\d{2}(?:-[0-9TZ-]+)?\.log$/.test(name))
    .map((name) => {
      const full = path.join(logDir, name);
      const st = fs.statSync(full);
      return { name, full, mtimeMs: st.mtimeMs };
    })
    .sort((a, b) => a.mtimeMs - b.mtimeMs);
}

function pruneOldLogs(logDir, maxFiles) {
  if (!Number.isFinite(maxFiles) || maxFiles <= 0) return;
  const files = listManagedLogFiles(logDir);
  const toDelete = Math.max(0, files.length - maxFiles);
  for (let i = 0; i < toDelete; i++) {
    try {
      fs.unlinkSync(files[i].full);
    } catch (_) {}
  }
}

function createLogger(logDir, options = {}) {
  ensureDir(logDir);
  const maxFileBytes = toPositiveInt(options.maxFileBytes, 5 * 1024 * 1024);
  const maxFiles = toPositiveInt(options.maxFiles, 30);
  const logFile = path.join(logDir, `campus-login-${new Date().toISOString().slice(0, 10)}.log`);

  const rotateIfNeeded = (incomingBytes) => {
    if (!Number.isFinite(maxFileBytes) || maxFileBytes <= 0) return;
    if (!fs.existsSync(logFile)) return;
    const size = fs.statSync(logFile).size;
    if (size + incomingBytes <= maxFileBytes) return;
    const rotated = logFile.replace(/\.log$/i, `-${nowFileSafe()}.log`);
    try {
      fs.renameSync(logFile, rotated);
    } catch (_) {
      return;
    }
    pruneOldLogs(logDir, maxFiles);
  };

  pruneOldLogs(logDir, maxFiles);
  return {
    log: (msg) => {
      const line = `[${ts()}] ${msg}`;
      rotateIfNeeded(Buffer.byteLength(`${line}\n`, 'utf8'));
      if (shouldInsertConsoleGap(msg)) {
        console.log('');
      }
      console.log(`[${hhmmss()}] ${msg}`);
      fs.appendFileSync(logFile, `${line}\n`, 'utf8');
    },
    logFile
  };
}

function pickUsername(rawUsername, operatorSuffix) {
  if (!operatorSuffix) return rawUsername;
  if (rawUsername.includes('@')) return rawUsername;
  return `${rawUsername}@${operatorSuffix}`;
}

function resolveDomainValue(operator) {
  const x = String(operator || '').trim().toLowerCase();
  if (!x) return '';
  if (x === '中国移动' || x === '移动' || x === 'cmcc') return '@cmcc';
  if (x === '中国电信' || x === '电信' || x === 'ctcc' || x === 'telecom') return '@ctcc';
  if (x === '中国联通' || x === '联通' || x === 'cucc' || x === 'unicom') return '@cucc';
  throw new Error('operator must be one of: 中国移动 / 中国电信 / 中国联通');
}

async function firstVisible(page, selectors) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if ((await locator.count()) > 0) {
      try {
        if (await locator.isVisible()) return locator;
      } catch (_) {}
    }
  }
  return null;
}

function textContainsAny(pageText, words) {
  return words.some((w) => pageText.includes(w));
}

function isPortalUrl(url) {
  return /\/srun_portal(_pc|_success)?/i.test(url);
}

function getHost(rawUrl) {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

function getAuthHosts(cfg) {
  const s = new Set();
  if (cfg.gatewayHost) s.add(String(cfg.gatewayHost).toLowerCase());
  if (cfg.portalUrl) s.add(getHost(cfg.portalUrl));
  if (cfg.statusUrl) s.add(getHost(cfg.statusUrl));
  s.add('202.201.252.10');
  return Array.from(s).filter(Boolean);
}

function isPortalHost(cfg, host) {
  const x = String(host || '').toLowerCase();
  if (!x) return false;
  return getAuthHosts(cfg).includes(x);
}

function hasFakeIpAddress(ips) {
  return (ips || []).some((ip) => String(ip).startsWith('198.'));
}

function detectFakeIpModeNow() {
  return hasFakeIpAddress(getLocalIpv4List());
}

function filterUrlsForPortalOnly(cfg, urls, fakeIpMode) {
  const xs = Array.isArray(urls) ? urls : [];
  if (!fakeIpMode) return xs;
  return xs.filter((u) => {
    const h = getHost(u);
    return h && isPortalHost(cfg, h);
  });
}

function sanitizeUrlForLog(rawUrl) {
  if (!rawUrl) return '';
  try {
    const u = new URL(rawUrl);
    for (const key of Array.from(u.searchParams.keys())) {
      if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
        u.searchParams.set(key, '***');
      }
    }
    return u.toString();
  } catch (_) {
    return String(rawUrl);
  }
}

function maskUsername(username) {
  const x = String(username || '');
  if (!x) return '';
  if (x.length <= 4) return '***';
  return `${x.slice(0, 2)}***${x.slice(-2)}`;
}

function parseSrunJsonpPayload(rawBody) {
  const text = String(rawBody || '').trim();
  if (!text) return null;

  const first = text.indexOf('(');
  const last = text.lastIndexOf(')');
  if (first >= 0 && last > first) {
    const maybeJson = text.slice(first + 1, last);
    try {
      return JSON.parse(maybeJson);
    } catch (_) {}
  }

  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function sanitizePortalBodyForLog(rawBody) {
  let clean = String(rawBody || '');
  clean = clean.replace(/"access_token"\s*:\s*"[^"]*"/gi, '"access_token":"***"');
  clean = clean.replace(/"username"\s*:\s*"[^"]*"/gi, '"username":"***"');
  clean = clean.replace(/"user_name"\s*:\s*"[^"]*"/gi, '"user_name":"***"');
  clean = clean.replace(/"usermac"\s*:\s*"[^"]*"/gi, '"usermac":"***"');
  clean = clean.replace(/"userip"\s*:\s*"[^"]*"/gi, '"userip":"***"');
  return clean;
}

function summarizePortalResponse(rawBody) {
  const obj = parseSrunJsonpPayload(rawBody);
  if (!obj || typeof obj !== 'object') return 'unparseable response';

  const fields = [];
  if (obj.res !== undefined) fields.push(`res=${obj.res}`);
  if (obj.error !== undefined) fields.push(`error=${obj.error}`);
  if (obj.ecode !== undefined) fields.push(`ecode=${obj.ecode}`);
  if (obj.error_msg) fields.push(`error_msg=${obj.error_msg}`);
  if (obj.ploy_msg) fields.push(`ploy_msg=${obj.ploy_msg}`);
  if (obj.suc_msg) fields.push(`suc_msg=${obj.suc_msg}`);

  return fields.length > 0 ? fields.join(', ') : 'response without status fields';
}

function getPortalResponseStatus(rawBody) {
  const obj = parseSrunJsonpPayload(rawBody);
  if (!obj || typeof obj !== 'object') return { ok: false, code: '', message: '' };
  const ok = obj.res === 'ok' || obj.error === 'ok' || obj.ecode === 0 || obj.ecode === '0';
  const code = obj.res || obj.error || '';
  const message = obj.ploy_msg || obj.suc_msg || obj.error_msg || '';
  return { ok, code: String(code), message: String(message) };
}

function sanitizeMessage(message) {
  return String(message || '').replace(/https?:\/\/[^\s)"']+/g, (u) => sanitizeUrlForLog(u));
}

function isChromeErrorUrl(url) {
  return /^chrome-error:\/\//i.test(String(url || ''));
}

async function gotoWithRetry(page, url, timeoutMs, retries, logger, tag) {
  let lastErr = null;
  const total = Math.max(1, Number(retries || 1));
  for (let i = 1; i <= total; i++) {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
      const current = page.url();
      if (isChromeErrorUrl(current)) {
        throw new Error(`chrome error page: ${current}`);
      }
      return;
    } catch (err) {
      lastErr = err;
      logger.log(`${tag} goto failed (${i}/${total}): ${sanitizeMessage(err.message)}`);
      if (i < total) await sleep(1500);
    }
  }
  throw lastErr || new Error(`${tag} goto failed`);
}

function withCacheBust(url) {
  const sep = url.includes('?') ? '&' : '?';
  return `${url}${sep}_t=${Date.now()}`;
}

function getLocalIpv4List() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const item of nets[name] || []) {
      if (item.family === 'IPv4' && !item.internal) ips.push(item.address);
    }
  }
  return ips;
}

function pickGatewayHost(cfg) {
  if (cfg.gatewayHost) return cfg.gatewayHost;
  try {
    const u = new URL(cfg.portalUrl || 'http://202.201.252.10');
    return u.hostname;
  } catch (_) {
    return '202.201.252.10';
  }
}

async function probeHttp(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal });
    return { ok: true, status: res.status };
  } catch (err) {
    return { ok: false, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

function buildStatusUrl(cfg) {
  if (cfg.statusUrl) return cfg.statusUrl;
  try {
    const p = new URL(cfg.portalUrl || 'http://202.201.252.10/srun_portal_pc?ac_id=4&theme=pro');
    const ac = p.searchParams.get('ac_id') || '4';
    const theme = p.searchParams.get('theme') || 'pro';
    return `${p.origin}/srun_portal_success?ac_id=${encodeURIComponent(ac)}&theme=${encodeURIComponent(theme)}`;
  } catch (_) {
    return 'http://202.201.252.10/srun_portal_success?ac_id=4&theme=pro';
  }
}

async function checkAlreadyOnlineByPortal(page, cfg, logger) {
  if (cfg.skipAlreadyOnlineCheck === true) return false;
  const statusUrl = buildStatusUrl(cfg);
  const timeoutMs = Number(cfg.onlineCheckTimeoutMs || 5000);

  try {
    await gotoWithRetry(page, statusUrl, timeoutMs, 1, logger, 'online-check');
    const current = page.url();
    const pageText = await page.locator('body').innerText().catch(() => '');
    const hasSuccessText = textContainsAny(pageText, ['已用流量', 'IP 地址', '用户账号', '注销']);
    const hasOnlineUserInfo = await checkOnlineByRadUserInfo(cfg, timeoutMs, logger);
    const isSuccessUrl = /srun_portal_success/i.test(current);
    const isLoginUrl = /srun_portal_pc/i.test(current);
    logger.log(
      `Online check(portal): url=${sanitizeUrlForLog(current)} successText=${hasSuccessText} radOnline=${hasOnlineUserInfo}`
    );
    // Use rad_user_info as the source of truth to avoid portal-page false positives.
    if (hasOnlineUserInfo) return true;
    if (isSuccessUrl && hasSuccessText) {
      logger.log('Portal page looks online but rad_user_info says offline; continue auth flow.');
    }
    if (isLoginUrl) return false;
    return false;
  } catch (err) {
    logger.log(`Online check(portal) failed: ${sanitizeMessage(err.message)}`);
    return false;
  }
}

function getDefaultRoutesFromRoutePrint() {
  try {
    const out = execSync('route print -4', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
    const routes = [];
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(
        /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$/
      );
      if (m) {
        routes.push({
          gateway: m[1],
          interfaceIp: m[2],
          metric: Number(m[3])
        });
      }
    }
    routes.sort((a, b) => a.metric - b.metric);
    return routes;
  } catch (_) {
    return [];
  }
}

function getDefaultGatewayIPv4(preferredIpPrefix = '', preferredGatewayPrefix = '') {
  const routes = getDefaultRoutesFromRoutePrint();
  if (routes.length > 0) {
    const byBoth = routes.find(
      (r) =>
        (!preferredIpPrefix || r.interfaceIp.startsWith(preferredIpPrefix)) &&
        (!preferredGatewayPrefix || r.gateway.startsWith(preferredGatewayPrefix))
    );
    if (byBoth) return byBoth.gateway;

    if (preferredIpPrefix) {
      const byInterface = routes.find((r) => r.interfaceIp.startsWith(preferredIpPrefix));
      if (byInterface) return byInterface.gateway;
    }

    if (preferredGatewayPrefix) {
      const byGateway = routes.find((r) => r.gateway.startsWith(preferredGatewayPrefix));
      if (byGateway) return byGateway.gateway;
    }

    return routes[0].gateway;
  }

  try {
    const out = execSync(
      'powershell -NoProfile -Command "$gw=(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix \'0.0.0.0/0\' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop); if($gw){$gw}"',
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 1200 }
    )
      .toString()
      .trim();
    if (out) return out;
  } catch (_) {}

  return '';
}

async function checkOnlineByRadUserInfo(cfg, timeoutMs, logger) {
  const hosts = getAuthHosts(cfg);
  for (const host of hosts) {
    const url = `http://${host}/cgi-bin/rad_user_info?callback=autologin_${Date.now()}&_=${Date.now()}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal });
      if (!res.ok) continue;
      const body = await res.text();
      if (/not_online_error/i.test(body)) return false;
      if (/"error"\s*:\s*"ok"/i.test(body) || /"res"\s*:\s*"ok"/i.test(body)) return true;
    } catch (err) {
      logger.log(`Online check(rad_user_info) failed on ${host}: ${sanitizeMessage(err.message)}`);
    } finally {
      clearTimeout(timer);
    }
  }
  return false;
}

function probePing(host, timeoutMs) {
  if (!host) return false;
  const ms = Math.max(500, Number(timeoutMs || 1500));
  try {
    execSync(`ping -n 1 -w ${ms} ${host}`, { stdio: ['ignore', 'ignore', 'ignore'] });
    return true;
  } catch (_) {
    return false;
  }
}

async function preflightNetworkCheck(cfg, logger) {
  if (cfg.preflightCheck === false) return;
  const maxWaitMs = Number(cfg.preflightWaitMaxMs || 45000);
  const intervalMs = Number(cfg.preflightIntervalMs || 3000);
  const timeoutMs = Number(cfg.preflightProbeTimeoutMs || 3000);
  const host = pickGatewayHost(cfg);
  const requireIpPrefix = String(cfg.requireIpPrefix || '').trim();
  const requireGatewayPrefix = String(cfg.requireGatewayPrefix || '10.').trim();
  const checkGatewayPing = cfg.checkGatewayPing !== false;
  const gatewayPingTimeoutMs = Number(cfg.gatewayPingTimeoutMs || 1500);
  const probeUrlsRaw = Array.isArray(cfg.preflightProbeUrls) && cfg.preflightProbeUrls.length > 0
    ? cfg.preflightProbeUrls
    : [cfg.portalUrl || 'http://202.201.252.10', 'http://www.msftconnecttest.com/redirect'];
  const defaultProbeUrl = cfg.portalUrl || 'http://202.201.252.10';

  const start = Date.now();
  while (Date.now() - start <= maxWaitMs) {
    logger.log('Preflight probing ...');
    const ips = getLocalIpv4List();
    const fakeIpMode = hasFakeIpAddress(ips);
    const ipOk = requireIpPrefix ? ips.some((ip) => ip.startsWith(requireIpPrefix)) : ips.length > 0;
    const defaultGateway = getDefaultGatewayIPv4(requireIpPrefix, requireGatewayPrefix);
    const gwOk = defaultGateway
      ? (requireGatewayPrefix ? defaultGateway.startsWith(requireGatewayPrefix) : true)
      : false;
    const gwPingOk = checkGatewayPing ? probePing(defaultGateway, gatewayPingTimeoutMs) : true;

    let dnsOk = false;
    try {
      await dns.lookup(host);
      dnsOk = true;
    } catch (_) {}

    const probeUrls = filterUrlsForPortalOnly(cfg, probeUrlsRaw, fakeIpMode);
    const finalProbeUrls = probeUrls.length > 0 ? probeUrls : [defaultProbeUrl];
    let httpOk = false;
    for (const u of finalProbeUrls) {
      const r = await probeHttp(u, timeoutMs);
      if (r.ok) {
        httpOk = true;
        break;
      }
    }

    logger.log(
      `Preflight: fakeIpMode=${fakeIpMode} ipOk=${ipOk} ips=[${ips.join(', ')}] gateway=${defaultGateway || 'N/A'} gwOk=${gwOk} gwPingOk=${gwPingOk} dnsOk=${dnsOk} httpOk=${httpOk}`
    );
    if (ipOk && gwOk && gwPingOk && dnsOk && httpOk) return;
    await sleep(intervalMs);
  }

  throw new Error('Preflight network check timeout: network/DNS/default-gateway not ready.');
}

async function preAuthRefresh(page, cfg, logger) {
  if (cfg.preAuthRefresh === false) return;
  const fakeIpMode = detectFakeIpModeNow();
  const refreshUrlsRaw = Array.isArray(cfg.refreshUrls) && cfg.refreshUrls.length > 0
    ? cfg.refreshUrls
    : [
        cfg.portalUrl || '',
        'http://202.201.252.10/srun_portal_pc?ac_id=4&theme=pro',
        'http://www.msftconnecttest.com/redirect'
      ].filter(Boolean);
  const refreshUrls = filterUrlsForPortalOnly(cfg, refreshUrlsRaw, fakeIpMode);
  const finalRefreshUrls = refreshUrls.length > 0 ? refreshUrls : [cfg.portalUrl || 'http://202.201.252.10'];
  const refreshCount = Math.max(1, Number(cfg.refreshCount || 2));
  const refreshTimeoutMs = Number(cfg.refreshTimeoutMs || 8000);
  const refreshDelayMs = Number(cfg.refreshDelayMs || 600);

  logger.log(`Pre-auth refresh: fakeIpMode=${fakeIpMode}, count=${refreshCount}, urls=${finalRefreshUrls.length}`);
  for (let i = 1; i <= refreshCount; i++) {
    for (const rawUrl of finalRefreshUrls) {
      const u = withCacheBust(rawUrl);
      try {
        await page.goto(u, { waitUntil: 'domcontentloaded', timeout: refreshTimeoutMs });
        logger.log(`Refresh ok (${i}/${refreshCount}): ${rawUrl} -> ${sanitizeUrlForLog(page.url())}`);
      } catch (err) {
        logger.log(`Refresh fail (${i}/${refreshCount}): ${rawUrl} (${sanitizeMessage(err.message)})`);
      }
      await sleep(refreshDelayMs);
    }
  }
}

async function resolvePortalUrl(page, cfg, logger) {
  const fakeIpMode = detectFakeIpModeNow();
  const autoDiscover = cfg.autoDiscoverPortal !== false;
  const detectUrlsRaw = Array.isArray(cfg.detectUrls) && cfg.detectUrls.length > 0
    ? cfg.detectUrls
    : [cfg.detectUrl || 'http://www.msftconnecttest.com/redirect', 'http://connect.rom.miui.com/generate_204', 'http://neverssl.com/'];
  const detectUrls = filterUrlsForPortalOnly(cfg, detectUrlsRaw, fakeIpMode);
  const detectTimeoutMs = Number(cfg.detectTimeoutMs || 10000);

  if (autoDiscover) {
    for (const detectUrl of detectUrls) {
      try {
        logger.log(`Auto discover portal via: ${detectUrl}`);
        await page.goto(detectUrl, { waitUntil: 'domcontentloaded', timeout: detectTimeoutMs });
        const discovered = page.url();
        logger.log(`Detect result url: ${sanitizeUrlForLog(discovered)}`);
        if (isPortalUrl(discovered)) return discovered;
      } catch (err) {
        logger.log(`Detect url failed: ${sanitizeMessage(err.message)}`);
      }
    }
    if (fakeIpMode && detectUrls.length === 0) {
      logger.log('Auto discover skipped: fakeIpMode=true and no portal detect URLs.');
    }
  }

  if (cfg.portalUrl) {
    logger.log(`Fallback portalUrl from config: ${cfg.portalUrl}`);
    return cfg.portalUrl;
  }

  throw new Error('Cannot resolve portalUrl. Please set portalUrl in config.json.');
}

async function waitForLoginResult(page, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const url = page.url();
    if (/srun_portal_success/i.test(url)) return { ok: true, reason: `url=${url}` };

    const pageText = await page.locator('body').innerText().catch(() => '');
    if (textContainsAny(pageText, ['已用流量', 'IP 地址', '用户账号', '注销'])) {
      return { ok: true, reason: 'success keywords found' };
    }

    if (textContainsAny(pageText, ['密码错误', '账号错误', '认证失败', '登录失败', '拒绝', '错误'])) {
      return { ok: false, reason: 'error keywords found on page' };
    }

    await sleep(800);
  }

  return { ok: false, reason: 'timeout waiting login result' };
}

async function launchBrowser(cfg, logger) {
  const launchOptions = {
    headless: cfg.headless !== false,
    args: ['--disable-blink-features=AutomationControlled']
  };
  const configuredChannel = String(cfg.browserChannel || 'msedge').trim();
  if (configuredChannel) {
    try {
      return await chromium.launch({ ...launchOptions, channel: configuredChannel });
    } catch (err) {
      logger.log(
        `Browser launch failed with channel=${configuredChannel}: ${sanitizeMessage(err.message)}; fallback to default chromium.`
      );
    }
  }
  return chromium.launch(launchOptions);
}

async function tryLoginOnce(cfg, logger, attempt) {
  const browser = await launchBrowser(cfg, logger);

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const attemptTag = `attempt-${attempt}-${nowFileSafe()}`;
  const saveArtifacts = cfg.saveArtifacts !== false;
  let loginApiSuccess = false;

  if (cfg.disableIpv6Auth !== false) {
    await page.route('**/*', (route) => {
      const u = route.request().url();
      if (/^https?:\/\/\[[0-9a-f:]+\]\//i.test(u) && /\/cgi-bin\/(get_challenge|srun_portal)/i.test(u)) {
        return route.abort();
      }
      return route.continue();
    });
  }

  page.on('response', async (res) => {
    const u = res.url();
    if (
      u.includes('/cgi-bin/srun_portal') ||
      u.includes('/cgi-bin/get_challenge') ||
      u.includes('/cgi-bin/rad_user_info')
    ) {
      logger.log(`HTTP ${res.status()} ${sanitizeUrlForLog(u)}`);
      if (u.includes('/cgi-bin/srun_portal')) {
        try {
          const body = await res.text();
          const status = getPortalResponseStatus(body);
          if (status.ok) {
            loginApiSuccess = true;
          }
          if (cfg.logPortalResponseBody === true) {
            const clean = sanitizePortalBodyForLog(body).replace(/\s+/g, ' ').slice(0, 500);
            logger.log(`srun_portal response(sanitized): ${clean}`);
          } else {
            logger.log(`srun_portal summary: ${summarizePortalResponse(body)}`);
          }
        } catch (_) {}
      }
    }
  });

  try {
    if (Number(cfg.startupDelayMs || 0) > 0) {
      logger.log(`Startup delay: ${cfg.startupDelayMs} ms`);
      await sleep(Number(cfg.startupDelayMs));
    }
    await preflightNetworkCheck(cfg, logger);
    const alreadyOnlineByPortal = await checkAlreadyOnlineByPortal(page, cfg, logger);
    if (alreadyOnlineByPortal) {
      logger.log('Already online by portal status check, skip portal auth.');
      return true;
    }
    await preAuthRefresh(page, cfg, logger);

    const targetPortalUrl = await resolvePortalUrl(page, cfg, logger);
    if (page.url() !== targetPortalUrl) {
      await gotoWithRetry(
        page,
        targetPortalUrl,
        Number(cfg.timeoutMs || 20000),
        Number(cfg.portalOpenRetries || 3),
        logger,
        'portal'
      );
    }
    logger.log(`Open page: ${sanitizeUrlForLog(page.url())}`);

    const alreadyOnline = page.getByRole('button', { name: /注销|下线/i }).first();
    if ((await alreadyOnline.count()) > 0 && (await alreadyOnline.isVisible())) {
      logger.log('Already online, skip login.');
      return true;
    }

    const usernameLocator = await firstVisible(page, [
      'input#username',
      'input[name="username"]',
      'input[placeholder*="用户"]',
      'input[placeholder*="账号"]',
      'input[autocomplete="username"]',
      'input[type="text"]'
    ]);

    const passwordLocator = await firstVisible(page, [
      'input#password',
      'input[name="password"]',
      'input[placeholder*="密码"]',
      'input[autocomplete="current-password"]',
      'input[type="password"]'
    ]);

    if (!usernameLocator || !passwordLocator) {
      throw new Error('Cannot find username/password input fields.');
    }

    const domainSelect = page.locator('select#domain').first();
    if ((await domainSelect.count()) > 0) {
      const domainValue = cfg.domainValue || resolveDomainValue(cfg.operator);
      if (domainValue) {
        await domainSelect.selectOption(domainValue).catch(() => {});
        logger.log(`Select domain: ${domainValue}`);
      }
    }

    const shouldAppendSuffix = !(cfg.domainValue || cfg.operator);
    const finalUsername = shouldAppendSuffix
      ? pickUsername(cfg.username, cfg.operatorSuffix)
      : cfg.username;
    logger.log(`Use username: ${maskUsername(finalUsername)}`);
    await usernameLocator.fill(finalUsername);
    await passwordLocator.fill(cfg.password);

    if (saveArtifacts) {
      await page.screenshot({ path: path.join(cfg.logDir, `${attemptTag}-before-click.png`), fullPage: true }).catch(() => {});
    }

    const loginBtn = await firstVisible(page, [
      'button:has-text("登录")',
      'button:has-text("登 录")',
      'button[type="submit"]',
      'input[type="submit"]',
      '.login-btn',
      '.btn-login'
    ]);

    if (!loginBtn) {
      throw new Error('Cannot find login button.');
    }

    logger.log('Click login button.');
    await loginBtn.click();
    await page.waitForTimeout(Number(cfg.postClickDelayMs || 300));

    // Do not wait for "networkidle" here: portal pages keep polling, which can delay
    // completion by full timeout even when auth is already done.
    let result = await waitForLoginResult(page, Number(cfg.resultTimeoutMs || 10000));
    if (!result.ok && loginApiSuccess) {
      const onlineByApi = await checkOnlineByRadUserInfo(cfg, 2500, logger);
      if (onlineByApi) {
        result = { ok: true, reason: 'srun_portal api success + rad_user_info online' };
      } else {
        result = { ok: true, reason: 'srun_portal api success' };
      }
    }
    logger.log(
      `Login result: ok=${result.ok}, reason=${result.reason}, currentUrl=${sanitizeUrlForLog(page.url())}`
    );

    if (saveArtifacts && !result.ok) {
      await page.screenshot({ path: path.join(cfg.logDir, `${attemptTag}-failed.png`), fullPage: true }).catch(() => {});
      const html = await page.content().catch(() => '');
      if (html) {
        fs.writeFileSync(path.join(cfg.logDir, `${attemptTag}-failed.html`), html, 'utf8');
      }
      const pageText = await page.locator('body').innerText().catch(() => '');
      if (pageText) {
        fs.writeFileSync(path.join(cfg.logDir, `${attemptTag}-failed.txt`), pageText, 'utf8');
      }
    }

    return result.ok;
  } finally {
    await context.close();
    await browser.close();
  }
}

async function checkOnlineOnly(cfg, logger) {
  const browser = await launchBrowser(cfg, logger);
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  try {
    const online = await checkAlreadyOnlineByPortal(page, cfg, logger);
    logger.log(`Check-online-only result: online=${online}`);
    return online;
  } finally {
    await context.close();
    await browser.close();
  }
}

async function main() {
  const checkOnlineOnlyMode = process.argv.includes('--check-online-only');
  const cfgPath = path.join(__dirname, 'config.json');
  if (!fs.existsSync(cfgPath)) {
    throw new Error('config.json not found. Copy config.example.json to config.json first.');
  }

  const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  const passwordEnvVar = String(cfg.passwordEnvVar || 'CAMPUS_PASSWORD').trim() || 'CAMPUS_PASSWORD';
  const envPassword = process.env[passwordEnvVar];
  if (envPassword) {
    cfg.password = envPassword;
  }
  if (!checkOnlineOnlyMode && (!cfg.username || !cfg.password)) {
    throw new Error(`config.json missing required fields: username, password (or set env ${passwordEnvVar})`);
  }
  if (!checkOnlineOnlyMode && !cfg.operator && !cfg.domainValue) {
    throw new Error('config.json missing required field: operator (中国移动/中国电信/中国联通)');
  }

  cfg.logDir = cfg.logDir || path.join(__dirname, 'logs');
  cfg.logMaxSizeMB = Number.isFinite(Number(cfg.logMaxSizeMB)) ? Number(cfg.logMaxSizeMB) : 5;
  cfg.logMaxFiles = Number.isFinite(Number(cfg.logMaxFiles)) ? Number(cfg.logMaxFiles) : 30;
  const logger = createLogger(cfg.logDir, {
    maxFileBytes: Math.floor(cfg.logMaxSizeMB * 1024 * 1024),
    maxFiles: Math.floor(cfg.logMaxFiles)
  });
  if (!checkOnlineOnlyMode) {
    logger.log('===== Campus Auto Login Start =====');
    logger.log(`Log file: ${logger.logFile}`);
  }
  if (checkOnlineOnlyMode) {
    const online = await checkOnlineOnly(cfg, logger);
    process.exit(online ? 0 : 3);
  }

  const maxRetries = Number(cfg.maxRetries || 6);
  const retryDelayMs = Number(cfg.retryDelayMs || 20000);

  for (let i = 1; i <= maxRetries; i++) {
    try {
      logger.log(`Attempt ${i}/${maxRetries} ...`);
      const ok = await tryLoginOnce(cfg, logger, i);
      if (ok) {
        logger.log('Campus login success.');
        process.exit(0);
      }
      logger.log('Login not confirmed, retrying ...');
    } catch (err) {
      logger.log(`Attempt failed: ${sanitizeMessage(err.message)}`);
    }

    if (i < maxRetries) {
      await sleep(retryDelayMs);
    }
  }

  logger.log('Campus login failed after max retries.');
  throw new Error('Campus login failed after max retries.');
}

main().catch((err) => {
  console.error(sanitizeMessage(err.message || err));
  process.exit(1);
});
