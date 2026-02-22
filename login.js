const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const os = require('os');

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
    } catch (_) { }
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
      } catch (_) { }
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

// FAKE_IP_MODE is now provided by PowerShell via --fake-ip-mode argument.
function getFakeIpMode() {
  const arg = process.argv.find(a => a.startsWith('--fake-ip-mode='));
  if (arg) {
    return arg.split('=')[1] === 'true';
  }
  return hasFakeIpAddress(getLocalIpv4List());
}
const FAKE_IP_MODE = getFakeIpMode();

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
    } catch (_) { }
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



async function checkAlreadyOnlineByPortal(cfg, logger) {
  const timeoutMs = Number(cfg.onlineCheckTimeoutMs || 5000);
  try {
    const isOnline = await checkOnlineByRadUserInfo(cfg, timeoutMs, logger);
    if (isOnline) {
      logger.log(`Online check: rad_user_info reports online.`);
      return true;
    }
    logger.log(`Online check: rad_user_info reports offline.`);
    return false;
  } catch (err) {
    logger.log(`Online check failed: ${sanitizeMessage(err.message)}`);
    return false;
  }
}

// Default gateway resolution is now fully handled in PowerShell.

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



async function preflightNetworkCheck(cfg, logger) {
  // IP segment, Default Gateway and Ping checks are now handled by run-campus-login.ps1.
  // We only run light HTTP probe to detect actual portal reachability.
  const timeoutMs = Number(cfg.preflightProbeTimeoutMs || 3000);
  const probeUrlsRaw = Array.isArray(cfg.preflightProbeUrls) && cfg.preflightProbeUrls.length > 0
    ? cfg.preflightProbeUrls
    : [cfg.portalUrl || 'http://202.201.252.10', 'http://www.msftconnecttest.com/redirect'];
  const defaultProbeUrl = cfg.portalUrl || 'http://202.201.252.10';

  const probeUrls = filterUrlsForPortalOnly(cfg, probeUrlsRaw, FAKE_IP_MODE);
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
    `Preflight HTTP Probe: fakeIpMode=${FAKE_IP_MODE} httpOk=${httpOk}`
  );
  if (!httpOk) {
    logger.log('HTTP probe failed. Proceeding anyway, but login may fail.');
  }
}



async function resolvePortalUrl(cfg, logger) {
  const autoDiscover = cfg.autoDiscoverPortal !== false;
  const detectUrlsRaw = Array.isArray(cfg.detectUrls) && cfg.detectUrls.length > 0
    ? cfg.detectUrls
    : [cfg.detectUrl || 'http://www.msftconnecttest.com/redirect', 'http://connect.rom.miui.com/generate_204', 'http://neverssl.com/'];
  const detectUrls = filterUrlsForPortalOnly(cfg, detectUrlsRaw, FAKE_IP_MODE);
  // Use configurable detect timeout (fallback 3000ms) instead of hardcoded 500ms.
  const quickProbeMs = Math.max(800, Number(cfg.detectTimeoutMs || 3000));

  if (autoDiscover) {
    for (const detectUrl of detectUrls) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), quickProbeMs);
      try {
        logger.log(`Auto discover portal via: ${detectUrl} (${quickProbeMs}ms quick probe)`);
        const res = await fetch(detectUrl, { method: 'GET', redirect: 'manual', signal: ctrl.signal });
        // Check for 302/301/307 redirect
        const location = res.headers.get('location') || '';
        if (location && isPortalUrl(location)) {
          logger.log(`Discovered portal URL (redirect): ${sanitizeUrlForLog(location)}`);
          return location;
        }
        // DNS-hijacked gateways often return 200 with the portal page or a redirect page
        if (res.status === 200 || res.status === 302 || res.status === 301) {
          const body = await res.text();
          // Match various portal URL patterns in the response body
          const portalPatterns = [
            /(?:href|src|url|location)\s*[=:]\s*["']?(https?:\/\/[^"'\s>]*srun_portal[^"'\s>]*)/i,
            /(?:href|src|url|location)\s*[=:]\s*["']?(https?:\/\/gw\.[^"'\s>]+)/i,
            /window\.location\s*=\s*["'](https?:\/\/[^"'\s>]+srun_portal[^"'\s>]*)/i,
          ];
          for (const pat of portalPatterns) {
            const m = body.match(pat);
            if (m && m[1]) {
              const discovered = m[1].replace(/&amp;/g, '&');
              logger.log(`Discovered portal URL (body match): ${sanitizeUrlForLog(discovered)}`);
              return discovered;
            }
          }
        }
        logger.log(`Detect result: status=${res.status}, location=${location || 'none'}, no portal found.`);
      } catch (_) {
        // Timeout = gateway doesn't hijack this URL, skip to next or fallback
        logger.log(`Auto discover: no gateway hijack within ${quickProbeMs}ms, skipping.`);
      } finally {
        clearTimeout(timer);
      }
    }
    if (FAKE_IP_MODE && detectUrls.length === 0) {
      logger.log('Auto discover skipped: FAKE_IP_MODE=true and no portal detect URLs.');
    }
  }

  if (cfg.portalUrl) {
    logger.log(`Using portalUrl from config: ${cfg.portalUrl}`);
    return cfg.portalUrl;
  }

  throw new Error('Cannot resolve portalUrl. Please set portalUrl in config.json.');
}

async function waitForLoginByRadUserInfo(cfg, logger, timeoutMs) {
  const pollInterval = 800;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const online = await checkOnlineByRadUserInfo(cfg, 3000, logger);
    if (online) {
      return { ok: true, reason: 'rad_user_info confirmed online' };
    }
    await sleep(pollInterval);
  }
  return { ok: false, reason: 'rad_user_info timeout: still offline' };
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
  let loginApiError = '';

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
          } else if (status.code && status.code !== 'ok') {
            loginApiError = status.message || status.code;
          }
          if (cfg.logPortalResponseBody === true) {
            const clean = sanitizePortalBodyForLog(body).replace(/\s+/g, ' ').slice(0, 500);
            logger.log(`srun_portal response(sanitized): ${clean}`);
          } else {
            logger.log(`srun_portal summary: ${summarizePortalResponse(body)}`);
          }
        } catch (_) { }
      }
    }
  });

  try {
    // Check online status first (pure fetch, instant) — skip everything if already online
    const alreadyOnline = await checkAlreadyOnlineByPortal(cfg, logger);
    if (alreadyOnline) {
      logger.log('Already online, skip portal auth.');
      return true;
    }

    // Only do preflight when we actually need to authenticate
    await preflightNetworkCheck(cfg, logger);

    const targetPortalUrl = await resolvePortalUrl(cfg, logger);
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

    const pageAlreadyOnline = page.getByRole('button', { name: /注销|下线/i }).first();
    if ((await pageAlreadyOnline.count()) > 0 && (await pageAlreadyOnline.isVisible())) {
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
        await domainSelect.selectOption(domainValue).catch(() => { });
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
      await page.screenshot({ path: path.join(cfg.logDir, `${attemptTag}-before-click.png`), fullPage: true }).catch(() => { });
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
    // Wait for the srun_portal API response to arrive
    await sleep(Number(cfg.postClickDelayMs || 300));

    // If the API listener already detected a definitive error, fail fast
    if (loginApiError) {
      logger.log(`Login API error detected: ${loginApiError}`);
      const result = { ok: false, reason: `srun_portal error: ${loginApiError}` };
      logger.log(
        `Login result: ok=${result.ok}, reason=${result.reason}, currentUrl=${sanitizeUrlForLog(page.url())}`
      );

      if (saveArtifacts) {
        await page.screenshot({ path: path.join(cfg.logDir, `${attemptTag}-failed.png`), fullPage: true }).catch(() => { });
      }
      return false;
    }

    // If API listener confirmed success, verify with rad_user_info
    // Otherwise, poll rad_user_info as the sole authority
    const pollTimeout = loginApiSuccess ? 3000 : Number(cfg.resultTimeoutMs || 10000);
    const result = await waitForLoginByRadUserInfo(cfg, logger, pollTimeout);

    // If rad_user_info didn't confirm but API said ok, still trust API
    if (!result.ok && loginApiSuccess) {
      result.ok = true;
      result.reason = 'srun_portal api success (rad_user_info unconfirmed)';
    }

    logger.log(
      `Login result: ok=${result.ok}, reason=${result.reason}, currentUrl=${sanitizeUrlForLog(page.url())}`
    );

    if (saveArtifacts && !result.ok) {
      await page.screenshot({ path: path.join(cfg.logDir, `${attemptTag}-failed.png`), fullPage: true }).catch(() => { });
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
  // Pure fetch online check, removing Playwright browser instantiation.
  try {
    const online = await checkAlreadyOnlineByPortal(cfg, logger);
    logger.log(`Check-online-only result: online=${online}`);
    return online;
  } catch (err) {
    logger.log(`Check-online-only Error: ${err.message}`);
    return false;
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
