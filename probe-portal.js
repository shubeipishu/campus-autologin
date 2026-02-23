/*
  Portal probe tool
  Usage:
    node probe-portal.js
    node probe-portal.js "http://www.msftconnecttest.com/redirect" 5000
*/

const detectUrl = process.argv[2] || 'http://www.msftconnecttest.com/redirect';
const timeoutMs = Math.max(500, Number(process.argv[3] || 5000));

function toAbsoluteUrl(maybeUrl, baseUrl) {
  if (!maybeUrl) return '';
  try {
    return new URL(maybeUrl, baseUrl).toString();
  } catch (_) {
    return String(maybeUrl);
  }
}

function isRedirectStatus(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function printDivider(title) {
  console.log('\n' + '='.repeat(20) + ` ${title} ` + '='.repeat(20));
}

async function main() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    printDivider('REQUEST');
    console.log(`time: ${new Date().toISOString()}`);
    console.log(`url: ${detectUrl}`);
    console.log(`timeoutMs: ${timeoutMs}`);
    console.log('redirect mode: manual');

    const res = await fetch(detectUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: ctrl.signal
    });

    const location = res.headers.get('location') || '';
    const absoluteLocation = toAbsoluteUrl(location, detectUrl);

    printDivider('STATUS');
    console.log(`status: ${res.status} ${res.statusText}`);
    console.log(`isRedirect: ${isRedirectStatus(res.status)}`);
    console.log(`response.url: ${res.url}`);

    printDivider('LOCATION');
    console.log(`location(raw): ${location || '(empty)'}`);
    console.log(`location(absolute): ${absoluteLocation || '(empty)'}`);

    printDivider('HEADERS');
    const headerEntries = [];
    for (const [k, v] of res.headers.entries()) {
      headerEntries.push([k, v]);
    }
    if (headerEntries.length === 0) {
      console.log('(no headers)');
    } else {
      for (const [k, v] of headerEntries) {
        console.log(`${k}: ${v}`);
      }
    }

    const body = await res.text();
    printDivider('BODY');
    console.log(`body.length: ${body.length}`);
    const preview = body.slice(0, 3000);
    console.log(preview || '(empty)');
    if (body.length > 3000) {
      console.log(`... (truncated, remaining ${body.length - 3000} chars)`);
    }

    const patterns = [
      /https?:\/\/[^\s"'<>]*srun_portal[^\s"'<>]*/gi,
      /https?:\/\/gw\.[^\s"'<>]*/gi,
      /window\.location\s*=\s*["']([^"']+)["']/gi,
      /location\.href\s*=\s*["']([^"']+)["']/gi,
      /http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url=([^"']+)["']/gi
    ];

    const found = new Set();
    for (const p of patterns) {
      let m;
      while ((m = p.exec(body)) !== null) {
        const candidate = m[1] || m[0];
        if (candidate) found.add(toAbsoluteUrl(candidate, detectUrl));
      }
    }

    printDivider('CANDIDATES');
    if (absoluteLocation) {
      console.log(`from Location: ${absoluteLocation}`);
    }
    if (found.size === 0) {
      console.log('(no URL candidates found in body)');
    } else {
      for (const u of found) {
        console.log(u);
      }
    }
  } catch (err) {
    printDivider('ERROR');
    console.log(err && err.message ? err.message : String(err));
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
  }
}

main();

