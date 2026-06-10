#!/usr/bin/env node
'use strict';

/**
 * AnyRouter / NewAPI 每日自动签到 + 余额查询
 * --------------------------------------------------
 * anyrouter.top 挡在阿里云 ESA 的 acw_sc__v2 JS 挑战 WAF 后面，
 * 纯 HTTP 请求会被拦截并返回一段 JS。本脚本用 Node 的 vm 沙箱执行
 * 这段挑战 JS、算出 acw_sc__v2 cookie，再带着它完成签到与余额查询。
 *
 * 零第三方依赖，只用 Node 内置模块，适合 cron / GitHub Actions 定时运行。
 *
 * 配置（任选其一）：
 *   1) 环境变量 ANYROUTER_ACCOUNTS = JSON 数组，例如：
 *        [{"name":"账号1","session":"xxx","user_id":12345}]
 *   2) 与脚本同目录的 accounts.json（结构同上）
 *   3) 单账号：环境变量 ANYROUTER_SESSION + ANYROUTER_USER_ID
 *
 * 可选通知（设置了对应环境变量才启用，多个可同时设置）：
 *   BARK_URL        如 https://api.day.app/yourkey
 *   SC_KEY          Server酱 SendKey（SCT 开头）
 *   TG_BOT_TOKEN + TG_CHAT_ID   Telegram 机器人
 *   NOTIFY_WEBHOOK  通用 webhook，收到 {title, text} 的 JSON POST
 */

const https = require('https');
const zlib = require('zlib');
const vm = require('vm');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOST = 'anyrouter.top';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const QUOTA_PER_DOLLAR = 500000; // NewAPI 额度单位：500000 quota = $1

// ---------------------------------------------------------------- 基础 HTTPS

function httpRequest(method, urlPath, cookieHeader, extraHeaders, body) {
  return new Promise((resolve, reject) => {
    const headers = {
      'User-Agent': UA,
      Accept: 'application/json, text/plain, */*',
      'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      'Accept-Encoding': 'gzip, deflate',
      Cookie: cookieHeader || '',
      ...(extraHeaders || {}),
    };
    if (method === 'POST') headers['Content-Length'] = Buffer.byteLength(body || '');

    const req = https.request(
      { host: HOST, path: urlPath, method, headers, timeout: 30000 },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          let buf = Buffer.concat(chunks);
          const enc = String(res.headers['content-encoding'] || '').toLowerCase();
          try {
            if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
            else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
            else if (enc.includes('br')) buf = zlib.brotliDecompressSync(buf);
          } catch (_) { /* 解压失败则按原始字节处理 */ }
          resolve({ status: res.statusCode, headers: res.headers, body: buf.toString('utf8') });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
    req.end(method === 'POST' ? (body || '') : undefined);
  });
}

// ---------------------------------------------------------------- Cookie 罐

function mergeSetCookie(setCookie, jar) {
  if (!setCookie) return;
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const line of arr) {
    const m = line.match(/^\s*([^=;]+)=([^;]*)/);
    if (m) jar[m[1].trim()] = m[2];
  }
}

function buildCookie(jar) {
  return Object.entries(jar)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

// ---------------------------------------------------------------- 解 WAF 挑战

function isChallenge(body) {
  return typeof body === 'string' && body.includes('<script>') && body.includes('arg1');
}

/** 在隔离沙箱里执行挑战 JS，捕获它写入的 acw_sc__v2 */
function solveAcwChallenge(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;

  let captured = '';
  const docShim = {
    set cookie(v) { captured = v; },
    get cookie() { return captured; },
    location: { reload() {}, replace() {}, assign() {}, href: `https://${HOST}/` },
    createElement: () => ({ style: {}, setAttribute() {}, appendChild() {} }),
    getElementById: () => null,
    addEventListener: () => {},
  };
  const sandbox = {
    document: docShim,
    location: { reload() {}, replace() {}, assign() {}, href: `https://${HOST}/` },
    navigator: { userAgent: UA, appName: 'Netscape', platform: 'Win32' },
    screen: { width: 1920, height: 1080 },
    history: { pushState() {}, replaceState() {} },
    setTimeout: () => 0,
    setInterval: () => 0,
    clearTimeout: () => {},
    clearInterval: () => {},
  };
  sandbox.window = sandbox; // 让挑战脚本里的 window.* 指向沙箱自身
  sandbox.globalThis = sandbox;
  try {
    vm.runInNewContext(m[1], sandbox, { timeout: 5000 });
  } catch (_) {
    // 挑战脚本带反调试逻辑，可能在写完 cookie 后抛错，忽略即可
  }
  const mm = String(captured).match(/acw_sc__v2=([0-9a-fA-F]+)/);
  return mm ? mm[1] : null;
}

/** 发起请求，遇到 WAF 挑战自动解开并重试 */
async function fetchWithWaf(method, urlPath, jar, extraHeaders, body) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await httpRequest(method, urlPath, buildCookie(jar), extraHeaders, body);
    mergeSetCookie(res.headers['set-cookie'], jar); // 收下新的 acw_tc 等
    if (!isChallenge(res.body)) return res;

    const acw = solveAcwChallenge(res.body);
    if (!acw) throw new Error('无法解出 acw_sc__v2（WAF 挑战脚本可能已改版）');
    jar.acw_sc__v2 = acw; // 带上算出的凭证，下一轮重试
  }
  throw new Error('多次重试后仍被 WAF 拦截');
}

// ---------------------------------------------------------------- 业务逻辑

function fmtUSD(quota) {
  return '$' + (Number(quota || 0) / QUOTA_PER_DOLLAR).toFixed(2);
}

async function runAccount(acc) {
  const name = acc.name || acc.user_id || '账号';
  const jar = { session: acc.session };
  const authHeaders = { 'new-api-user': String(acc.user_id) };

  // 1) 签到
  let checkinMsg;
  try {
    const r = await fetchWithWaf('POST', '/api/user/sign_in', jar, authHeaders, '');
    let j = {};
    try { j = JSON.parse(r.body); } catch (_) {}
    if (r.status === 200 && j.success) checkinMsg = j.message ? `签到成功（${j.message}）` : '签到成功';
    else if (/已|repeat|already/i.test(j.message || '')) checkinMsg = `今日已签到（${j.message}）`;
    else checkinMsg = `签到未成功：${j.message || ('HTTP ' + r.status)}`;
  } catch (e) {
    checkinMsg = `签到异常：${e.message}`;
  }

  // 2) 查余额
  let balanceLine = '';
  let ok = false;
  try {
    const r = await fetchWithWaf('GET', '/api/user/self', jar, authHeaders);
    const j = JSON.parse(r.body);
    if (j.success && j.data) {
      const u = j.data;
      ok = true;
      balanceLine = `余额 ${fmtUSD(u.quota)}（已用 ${fmtUSD(u.used_quota)}）`;
      return {
        name,
        ok,
        username: u.username,
        display_name: u.display_name,
        quota: u.quota,
        used_quota: u.used_quota,
        text: `${checkinMsg}；${balanceLine}`,
      };
    }
    balanceLine = `查询余额失败：${j.message || ('HTTP ' + r.status)}`;
  } catch (e) {
    balanceLine = `查询余额异常：${e.message}`;
  }

  return { name, ok, text: `${checkinMsg}；${balanceLine}` };
}

// ---------------------------------------------------------------- 配置加载

function loadAccounts() {
  if (process.env.ANYROUTER_ACCOUNTS) {
    return JSON.parse(process.env.ANYROUTER_ACCOUNTS);
  }
  const cfgPath = path.join(__dirname, 'accounts.json');
  if (fs.existsSync(cfgPath)) {
    return JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  }
  if (process.env.ANYROUTER_SESSION && process.env.ANYROUTER_USER_ID) {
    return [{ session: process.env.ANYROUTER_SESSION, user_id: process.env.ANYROUTER_USER_ID }];
  }
  return [];
}

// ---------------------------------------------------------------- 通知（可选）

async function notify(title, text) {
  const full = `${title}\n${text}`;
  const tasks = [];
  const used = [];

  // Bark（GET）
  if (process.env.BARK_URL) {
    const base = process.env.BARK_URL.replace(/\/$/, '');
    tasks.push(httpGet(`${base}/${encodeURIComponent(title)}/${encodeURIComponent(text)}?group=AnyRouter`));
    used.push('Bark');
  }
  // Server酱（GET）
  if (process.env.SC_KEY) {
    tasks.push(httpGet(`https://sctapi.ftqq.com/${process.env.SC_KEY}.send?title=${encodeURIComponent(title)}&desp=${encodeURIComponent(text)}`));
    used.push('Server酱');
  }
  // Telegram（GET）
  if (process.env.TG_BOT_TOKEN && process.env.TG_CHAT_ID) {
    tasks.push(httpGet(`https://api.telegram.org/bot${process.env.TG_BOT_TOKEN}/sendMessage?chat_id=${process.env.TG_CHAT_ID}&text=${encodeURIComponent(full)}`));
    used.push('Telegram');
  }
  // 飞书 / Lark 自定义机器人（POST）
  if (process.env.FEISHU_WEBHOOK) {
    tasks.push(postJSON(process.env.FEISHU_WEBHOOK, { msg_type: 'text', content: { text: full } }));
    used.push('飞书');
  }
  // 企业微信群机器人（POST webhook）
  if (process.env.WECOM_WEBHOOK) {
    tasks.push(postJSON(process.env.WECOM_WEBHOOK, { msgtype: 'text', text: { content: full } }));
    used.push('企业微信群机器人');
  }
  // 企业微信「应用消息」——与青龙 QYWX_AM 同格式：corpid,corpsecret,touser,agentid[,media_id]
  if (process.env.QYWX_AM || process.env.WEWORK_APP_KEY) {
    tasks.push(wecomApp(title, text));
    used.push('企业微信应用');
  }
  // 钉钉自定义机器人（POST，支持加签 DINGTALK_SECRET）
  if (process.env.DINGTALK_WEBHOOK) {
    let url = process.env.DINGTALK_WEBHOOK;
    if (process.env.DINGTALK_SECRET) {
      const ts = Date.now();
      const sign = crypto
        .createHmac('sha256', process.env.DINGTALK_SECRET)
        .update(`${ts}\n${process.env.DINGTALK_SECRET}`)
        .digest('base64');
      url += `&timestamp=${ts}&sign=${encodeURIComponent(sign)}`;
    }
    tasks.push(postJSON(url, { msgtype: 'text', text: { content: full } }));
    used.push('钉钉');
  }
  // 通用 webhook（POST {title, text}）
  if (process.env.NOTIFY_WEBHOOK) {
    tasks.push(postJSON(process.env.NOTIFY_WEBHOOK, { title, text }));
    used.push('webhook');
  }

  if (!tasks.length) return;
  await Promise.allSettled(tasks);
  console.log(`已推送通知：${used.join('、')}`);
}

function httpGet(u) {
  return new Promise((resolve) => {
    try { https.get(u, (r) => { r.resume(); r.on('end', resolve); }).on('error', () => resolve()); }
    catch (_) { resolve(); }
  });
}

function postJSON(u, obj) {
  return new Promise((resolve) => {
    try {
      const data = JSON.stringify(obj);
      const { hostname, pathname, search, port } = new URL(u);
      const req = https.request(
        {
          hostname,
          port: port || 443,
          path: pathname + (search || ''),
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
        },
        (r) => { r.resume(); r.on('end', resolve); }
      );
      req.on('error', () => resolve());
      req.end(data);
    } catch (_) { resolve(); }
  });
}

/** 发请求并返回响应正文文本（出错返回空串），用于需要读返回值的渠道 */
function fetchText(method, u, obj) {
  return new Promise((resolve) => {
    try {
      const data = obj ? JSON.stringify(obj) : null;
      const { hostname, pathname, search, port } = new URL(u);
      const headers = data
        ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        : {};
      const req = https.request(
        { hostname, port: port || 443, path: pathname + (search || ''), method, headers },
        (r) => {
          const chunks = [];
          r.on('data', (c) => chunks.push(c));
          r.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        }
      );
      req.on('error', () => resolve(''));
      req.end(data || undefined);
    } catch (_) { resolve(''); }
  });
}

/**
 * 企业微信「应用消息」推送，参数格式与青龙 QYWX_AM 一致：
 *   corpid,corpsecret,touser,agentid[,media_id]
 * 不填 media_id 发文本消息；填了则发图文(mpnews)。touser 用 @all 或多个成员用 | 隔开。
 */
async function wecomApp(title, content) {
  const conf = process.env.QYWX_AM || process.env.WEWORK_APP_KEY || '';
  const p = conf.split(',').map((s) => s.trim());
  if (p.length < 4) {
    console.log('企业微信应用：QYWX_AM 配置格式错误，应为 corpid,corpsecret,touser,agentid[,media_id]');
    return;
  }
  const [corpid, corpsecret, touser, agentid, mediaId] = p;

  // 1) 取 access_token
  const tokRaw = await fetchText(
    'GET',
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(corpid)}&corpsecret=${encodeURIComponent(corpsecret)}`
  );
  let token = '';
  try { token = JSON.parse(tokRaw).access_token || ''; } catch (_) {}
  if (!token) {
    console.log('企业微信应用：获取 access_token 失败（请检查 corpid / corpsecret）');
    return;
  }

  // 2) 发消息
  let body;
  if (mediaId) {
    body = {
      touser, agentid, msgtype: 'mpnews',
      mpnews: { articles: [{ title, thumb_media_id: mediaId, author: 'AnyRouter', content_source_url: '', content: content.replace(/\n/g, '<br/>'), digest: content }] },
    };
  } else {
    body = { touser, agentid, msgtype: 'text', text: { content: `${title}\n\n${content}` }, safe: '0' };
  }
  const sendRaw = await fetchText('POST', `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`, body);
  try {
    const j = JSON.parse(sendRaw);
    if (j.errcode !== 0) console.log(`企业微信应用推送失败：${j.errmsg || sendRaw}`);
  } catch (_) {
    console.log('企业微信应用：发送响应解析失败');
  }
}

// ---------------------------------------------------------------- 主流程

async function main() {
  const accounts = loadAccounts();
  if (!accounts.length) {
    console.error('未找到账号配置。请设置 ANYROUTER_ACCOUNTS / accounts.json / ANYROUTER_SESSION+ANYROUTER_USER_ID');
    process.exit(1);
  }

  const results = [];
  for (const acc of accounts) {
    const r = await runAccount(acc);
    results.push(r);
    console.log(`${r.ok ? '✅' : '❌'} [${r.name}] ${r.text}`);
  }

  const okCount = results.filter((r) => r.ok).length;
  const lines = results.map((r) => `${r.ok ? '✅' : '❌'} [${r.name}] ${r.text}`);

  // 多账号时附上合计余额
  if (results.length > 1 && okCount > 0) {
    const totalQuota = results.reduce((s, r) => s + (r.quota || 0), 0);
    lines.push(`— 合计余额 ${fmtUSD(totalQuota)}`);
  }
  lines.push(`🕒 ${new Date().toLocaleString('zh-CN', { hour12: false, timeZone: 'Asia/Shanghai' })} (北京时间)`);

  const title = `AnyRouter 签到 ${okCount}/${results.length} 成功`;
  await notify(title, lines.join('\n'));
  process.exit(okCount === results.length ? 0 : 1);
}

main().catch((e) => {
  console.error('运行出错：', e);
  process.exit(1);
});
