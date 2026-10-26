/**
 * HyxAPI（hyxware.com）每日签到 —— Surge 原生模块
 * ---------------------------------------------------------------------------
 * 一个脚本同时承担三种角色，靠 $script.type 分流：
 *   http-response  捕获 Web 端会话（refresh cookie + session sid + access_token）
 *   cron           每日签到：续期 → 查状态 → 未签则签 → 取余额 → 通知
 *   generic        [Panel] 信息面板：今日是否已签、本月/累计次数、余额
 *
 * 站点内核：New API 定制版（前端 HyxAPI，version 0.0.1-dev），接口契约来自前端
 * 打包产物（index.fc3dc60602.js / async chunk t8.js）逐段核对，2026-10-24 实测：
 *
 *   POST /api/user/login                    登录，body {username,password}
 *                                           → data = {access_token, token_type,
 *                                             access_expires_at, user, session}
 *                                           开 2FA 时返回 {flow_token, expires_at, ...}
 *                                           需要 /api/user/login/verify 二次校验。
 *   POST /api/user/auth/refresh             续期，**只认 cookie**（见下），可带
 *                                           X-Auth-Session: <sid> 绑定会话
 *   GET  /api/user/checkin?month=YYYY-MM    签到状态 + 本月明细
 *   POST /api/user/checkin                  签到 → data = {checkin_date, quota_awarded}
 *   GET  /api/user/self                     余额 → data.quota / data.used_quota
 *   GET  /api/status                        站点开关 → data.checkin_enabled /
 *                                           data.turnstile_check / data.quota_per_unit
 *
 * 鉴权（实测）：`/api/user/*` 只认 `Authorization: Bearer <access_token>`，
 *   裸请求返回 401 {"code":"AUTH_UNAUTHORIZED","message":"Unauthorized, invalid
 *   access token"}。access_token 短命，靠 HttpOnly 的 `new_api_refresh` cookie
 *   （Path=/api/user/auth）换新 —— 所以本脚本抓 cookie 而不是只抓 token。
 *
 * Turnstile：本站 `turnstile_check=false`，签到与登录都不需要人机验证。
 *   若站点以后打开该开关，POST 会返回 turnstile 相关错误，脚本会如实通知，
 *   Surge 侧无法无人值守完成 —— 见 README。
 *
 * 已知边界：账号开了两步验证时，密码登录会停在 flow_token 上，脚本会明确报错，
 *   此时请改用「浏览器登录一次」的抓取模式（抓取不受 2FA 影响）。
 * ---------------------------------------------------------------------------
 * 配置优先级：模块参数（$argument） > 持久化存储 > 文件内 DEFAULT_CONFIG
 * 持久化键：hyx.cred / hyx.state
 */

"use strict";

/* ============================ 默认配置 ============================ */

var DEFAULT_CONFIG = {
  baseUrl: "https://hyxware.com",
  policy: "",
  timeoutSeconds: 20,
  notify: true,
  lowBalance: 0,
  username: "",
  password: "",
  token: "",
  quotaPerUnit: 500000
};

var STORE_KEY = {
  cred: "hyx.cred",
  state: "hyx.state"
};

var SENTINEL = { "未配置": 1, "无": 1, "-": 1, "none": 1, "#": 1 };

/** 面板和自检里会显示这个版本号，用来确认 Surge 跑的到底是不是新版脚本。 */
var SCRIPT_VERSION = "2026-10-26.1";

var UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/* ============================ 运行时状态 ============================ */

var CFG = null;
var FP = "[HyxAPI签到]";
var finished = false;
var notifyEnabled = true;
var DEADLINE = 0;          // 面板模式下用，超过就退回缓存，避免面板转圈
var lastError = "";

/* ============================ 基础工具 ============================ */

function finish(payload) {
  if (finished) return;
  finished = true;
  if (typeof $done === "function") {
    if (payload === undefined) $done();
    else $done(payload);
  }
}

function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function pad2(n) { return n < 10 ? "0" + n : "" + n; }

function formatTime(date) {
  var d = date || new Date();
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " +
    pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
}

function formatShort(date) {
  var d = date || new Date();
  return pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " +
    pad2(d.getHours()) + ":" + pad2(d.getMinutes());
}

function dayString(date) {
  var d = date || new Date();
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate());
}

function monthString(date) {
  var d = date || new Date();
  return d.getFullYear() + "-" + pad2(d.getMonth() + 1);
}

function nowSeconds() { return Math.floor(Date.now() / 1000); }

function log(message) {
  try {
    console.log(FP + " [" + formatTime() + "] " + message);
  } catch (e) { /* ignore */ }
}

function errText(err) {
  if (err && typeof err === "object") {
    return String(err.message || err.error || err.errMsg || JSON.stringify(err));
  }
  return String(err === null || err === undefined ? "未知错误" : err);
}

function trim(value) {
  if (typeof value === "string") return value.trim();
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function num(value) {
  if (value === null || value === undefined || value === "") return null;
  var n = Number(value);
  return isFinite(n) ? n : null;
}

function clampInt(value, fallback, min, max) {
  var n = parseInt(value, 10);
  if (!isFinite(n)) return fallback;
  if (min !== undefined && n < min) return min;
  if (max !== undefined && n > max) return max;
  return n;
}

function parseBool(value, fallback) {
  if (typeof value === "boolean") return value;
  var s = trim(value).toLowerCase();
  if (s === "1" || s === "true" || s === "yes" || s === "on") return true;
  if (s === "0" || s === "false" || s === "no" || s === "off") return false;
  return fallback;
}

/** Surge 模块参数不允许留空，所以用「未配置」之类占位值表示未设置。 */
function isUnset(value) {
  var s = trim(value);
  if (!s) return true;
  return has(SENTINEL, s) || has(SENTINEL, s.toLowerCase());
}

function argValue(name) {
  if (typeof $argument === "undefined" || $argument === null) return "";
  var raw = String($argument);
  if (!raw) return "";
  var parts = raw.split("&");
  for (var i = 0; i < parts.length; i++) {
    var item = parts[i];
    var idx = item.indexOf("=");
    if (idx < 0) continue;
    if (item.slice(0, idx) !== name) continue;
    var value = item.slice(idx + 1);
    try { value = decodeURIComponent(value); } catch (e) { /* keep raw */ }
    return value;
  }
  return "";
}

function readJSON(key) {
  try {
    if (typeof $persistentStore === "undefined" || !$persistentStore) return null;
    var raw = $persistentStore.read(key);
    if (!raw) return null;
    var parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (e) {
    return null;
  }
}

function writeJSON(key, value) {
  try {
    if (typeof $persistentStore === "undefined" || !$persistentStore) return false;
    if (value === null) { $persistentStore.write(null, key); return true; }
    $persistentStore.write(JSON.stringify(value), key);
    return true;
  } catch (e) {
    log("写入持久化存储失败：" + errText(e));
    return false;
  }
}

function parseJSON(text) {
  if (!text) return null;
  if (typeof text === "object") return text;
  try {
    return JSON.parse(String(text));
  } catch (e) {
    return null;
  }
}

/* ============================ 配置 ============================ */

function normalizeBaseUrl(value) {
  var s = trim(value);
  if (!s) return DEFAULT_CONFIG.baseUrl;
  s = s.replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return s;
}

function loadConfig() {
  var stored = readJSON(STORE_KEY.state) || {};
  var username = argValue("username");
  var password = argValue("password");
  var token = argValue("token");
  var timeout = clampInt(argValue("timeout"), DEFAULT_CONFIG.timeoutSeconds, 5, 120);
  var lowBalance = num(argValue("lowBalance"));
  var qpu = num(stored.qpu);

  return {
    baseUrl: normalizeBaseUrl(argValue("baseUrl")),
    policy: isUnset(argValue("policy")) ? "" : trim(argValue("policy")),
    timeoutSeconds: timeout,
    notify: parseBool(argValue("notify"), DEFAULT_CONFIG.notify),
    lowBalance: lowBalance === null ? DEFAULT_CONFIG.lowBalance : lowBalance,
    username: isUnset(username) ? "" : trim(username),
    password: isUnset(password) ? "" : String(password),
    token: isUnset(token) ? "" : trim(token),
    quotaPerUnit: qpu && qpu > 0 ? qpu : DEFAULT_CONFIG.quotaPerUnit
  };
}

/* ============================ 凭据 ============================ */

function loadCred() {
  var cred = readJSON(STORE_KEY.cred);
  if (!cred) {
    return {
      cookie: "", sid: "", token: "", exp: 0, uid: 0, user: "",
      capUid: 0, capNotified: 0, capCount: 0, capAt: 0
    };
  }
  return {
    cookie: trim(cred.cookie),
    sid: trim(cred.sid),
    token: trim(cred.token),
    exp: num(cred.exp) || 0,
    uid: num(cred.uid) || 0,
    user: trim(cred.user),
    capUid: num(cred.capUid) || 0,
    capNotified: num(cred.capNotified) || 0,
    capCount: num(cred.capCount) || 0,
    capAt: num(cred.capAt) || 0
  };
}

function saveCred(cred) {
  cred.at = nowSeconds();
  return writeJSON(STORE_KEY.cred, cred);
}

function hasCredential(cred) {
  return !!(CFG.token || (cred && (cred.cookie || cred.token || (CFG.username && CFG.password))));
}

/** 只让 token 失效，cookie 保留 —— 下次走续期。 */
function clearToken() {
  var cred = loadCred();
  if (!cred.token) return;
  cred.token = "";
  cred.exp = 0;
  saveCred(cred);
}

function cookieValue(cookieText, name) {
  if (!cookieText) return "";
  var parts = String(cookieText).split(";");
  for (var i = 0; i < parts.length; i++) {
    var item = trim(parts[i]);
    if (item.indexOf(name + "=") === 0) return item.slice(name.length + 1);
  }
  return "";
}

/** 只替换某一个 cookie 的值，其余原样保留（浏览器给的 Cookie 串最可信）。 */
function setCookieValue(cookieText, name, value) {
  var parts = cookieText ? String(cookieText).split(";") : [];
  var out = [];
  var found = false;
  for (var i = 0; i < parts.length; i++) {
    var item = trim(parts[i]);
    if (!item) continue;
    if (item.indexOf(name + "=") === 0) {
      out.push(name + "=" + value);
      found = true;
    } else {
      out.push(item);
    }
  }
  if (!found) out.unshift(name + "=" + value);
  return out.join("; ");
}

/* ============================ HTTP（Surge $httpClient） ============================ */

function baseHeaders() {
  return {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Origin": CFG.baseUrl,
    "Referer": CFG.baseUrl + "/topup",
    "User-Agent": UA,
    "Cache-Control": "no-store"
  };
}

function httpRequest(method, url, options, callback) {
  options = options || {};
  if (DEADLINE && Date.now() > DEADLINE) {
    return callback(new Error("面板刷新超时"), null);
  }
  if (typeof $httpClient === "undefined" || !$httpClient) {
    return callback(new Error("当前环境不支持 $httpClient，请在 Surge 中运行本脚本"), null);
  }
  // $httpClient 的方法名全是小写，传 "POST" 会取到 undefined 并静默退化成 GET。
  var fn = $httpClient[String(method).toLowerCase()] || $httpClient.get;
  var opts = {
    url: url,
    headers: options.headers || {},
    timeout: options.timeout || CFG.timeoutSeconds
  };
  if (options.body !== undefined) opts.body = options.body;
  if (CFG.policy) opts.policy = CFG.policy;
  if (options.insecure) opts.insecure = true;

  fn.call($httpClient, opts, function (error, response, data) {
    if (error) {
      var msg = errText(error);
      log("请求失败 " + method.toUpperCase() + " " + url + " → " + msg);
      return callback(new Error("网络请求失败：" + msg), null);
    }
    callback(null, {
      status: (response && response.status) || 0,
      headers: (response && response.headers) || {},
      body: data === null || data === undefined ? "" : String(data)
    });
  });
}

/* ============================ 鉴权 ============================ */

function applyAuth(headers, cred) {
  headers.Authorization = "Bearer " + cred.token;
  return headers;
}

function cookieHeaderFor(cred) {
  var text = trim(cred.cookie);
  if (!cookieValue(text, "new_api_refresh")) return "";
  // 浏览器抓到的整串 Cookie 直接复用；只在缺 has_session 时补一个。
  if (!cookieValue(text, "new_api_has_session")) {
    text = text + "; new_api_has_session=1";
  }
  return text;
}

/** 从续期/登录响应里取 bundle，字段名与前端解析保持一致。 */
function bundleOf(json) {
  if (!json || json.success !== true) return null;
  var data = json.data;
  if (!data || typeof data !== "object") return null;
  if (!data.access_token) return null;
  return data;
}

function mergeBundle(cred, bundle) {
  cred.token = trim(bundle.access_token);
  cred.exp = num(bundle.access_expires_at) || 0;
  if (bundle.session && bundle.session.sid) cred.sid = trim(bundle.session.sid);
  if (bundle.user) {
    if (num(bundle.user.id)) cred.uid = num(bundle.user.id);
    if (bundle.user.username) cred.user = trim(bundle.user.username);
  }
  return cred;
}

function refreshAuth(cred, callback) {
  var headers = baseHeaders();
  headers.Cookie = cookieHeaderFor(cred);
  if (cred.sid) headers["X-Auth-Session"] = cred.sid;
  headers["Content-Type"] = "application/json";

  log("续期 access_token");
  httpRequest("POST", CFG.baseUrl + "/api/user/auth/refresh", {
    headers: headers,
    body: "{}"
  }, function (err, res) {
    if (err) return callback(err);
    var json = parseJSON(res.body);
    var bundle = bundleOf(json);
    if (!bundle) {
      var msg = (json && (json.message || json.code)) || ("HTTP " + res.status);
      var dead = res.status === 401 || /Unauthorized/i.test(msg);
      return callback(new Error(dead
        ? "会话已失效（服务端拒绝续期）。请用浏览器打开一次 hyxware.com 重新登录，" +
          "脚本会自动抓取新会话；或改用「系统访问令牌」模式（TOKEN 参数），一劳永逸"
        : "会话续期失败（" + msg + "）"));
    }
    mergeBundle(cred, bundle);
    // 服务端可能在续期时轮换 refresh cookie，这里必须跟着更新，
    // 否则下一次续期就会拿着作废的 cookie 去撞 401。
    var rotated = pickRefreshCookie(headerValues(res.headers, "Set-Cookie"));
    if (rotated) {
      var next = setCookieValue(cred.cookie, "new_api_refresh",
        rotated.slice("new_api_refresh=".length));
      if (next !== cred.cookie) {
        cred.cookie = next;
        cred.capCount = (cred.capCount || 0) + 1;
        cred.capAt = nowSeconds();
        log("续期时 cookie 已轮换，已更新");
      }
    }
    saveCred(cred);
    log("续期成功，用户 " + (cred.user || cred.uid || "?"));
    callback(null, cred);
  });
}

function loginAuth(cred, callback) {
  if (!CFG.username || !CFG.password) {
    return callback(new Error("没有可用凭据"));
  }
  var headers = baseHeaders();
  headers["Content-Type"] = "application/json";
  log("使用账号密码登录：" + CFG.username);

  httpRequest("POST", CFG.baseUrl + "/api/user/login", {
    headers: headers,
    body: JSON.stringify({ username: CFG.username, password: CFG.password })
  }, function (err, res) {
    if (err) return callback(err);
    var json = parseJSON(res.body);
    if (json && json.success === true && json.data && json.data.flow_token) {
      return callback(new Error("该账号启用了两步验证，密码登录无法自动完成；请改用浏览器登录一次的抓取模式"));
    }
    var bundle = bundleOf(json);
    if (!bundle) {
      var msg = (json && (json.message || json.code)) || ("HTTP " + res.status);
      var hint = "";
      // 这个站点的登录框只要「用户名」，注册时用户名和邮箱是两个字段。
      // 用邮箱当用户名登录就会落在这句错误上，所以专门提示一次。
      if (/incorrect|banned/i.test(msg)) {
        hint = /@/.test(CFG.username)
          ? "；注意：登录用的是「用户名」，不是邮箱，请填注册时设的用户名"
          : "；请确认用户名和密码（不是邮箱）";
      }
      return callback(new Error("登录失败（" + msg + "）" + hint));
    }
    mergeBundle(cred, bundle);
    saveCred(cred);
    log("登录成功，用户 " + (cred.user || cred.uid || "?"));
    callback(null, cred);
  });
}

/**
 * 拿到一个可用的 access_token。
 * 优先级：模块里填的「系统访问令牌」→ 本地未过期 token → cookie 续期 → 账号密码。
 * 令牌模式完全绕开 cookie 会话，是唯一不会因为浏览器会话过期而失效的路径。
 */
function ensureAuth(callback) {
  if (CFG.token) {
    return callback(null, {
      cookie: "", sid: "", token: CFG.token, exp: nowSeconds() + 315360000,
      uid: 0, user: "", capUid: 0, capNotified: 0, capCount: 0, capAt: 0, pat: true
    });
  }

  var cred = loadCred();
  var now = nowSeconds();
  if (cred.token && cred.exp > now + 120) return callback(null, cred);

  if (cred.cookie) {
    return refreshAuth(cred, function (err, next) {
      if (!err && next) return callback(null, next);
      if (CFG.username && CFG.password) {
        log("续期失败，改用账号密码：" + errText(err));
        return loginAuth(cred, callback);
      }
      callback(err);
    });
  }

  if (CFG.username && CFG.password) return loginAuth(cred, callback);

  callback(new Error("尚未捕获凭据：请在浏览器登录一次 " + CFG.baseUrl.replace(/^https?:\/\//, "") +
    "（需已启用 MITM），或填好 TOKEN 参数"));
}

/**
 * 带一次 401 重试的 API 调用。
 * callback(err, { status, json, body })
 */
function apiCall(method, path, body, callback) {
  var attempt = 0;

  function run() {
    attempt += 1;
    ensureAuth(function (err, cred) {
      if (err) return callback(err, null);
      var headers = applyAuth(baseHeaders(), cred);
      var options = { headers: headers };
      if (body !== undefined && body !== null) {
        headers["Content-Type"] = "application/json";
        options.body = typeof body === "string" ? body : JSON.stringify(body);
      }
      httpRequest(method, CFG.baseUrl + path, options, function (reqErr, res) {
        if (reqErr) return callback(reqErr, null);
        var json = parseJSON(res.body);
        var unauthorized = res.status === 401 ||
          (json && (json.code === "AUTH_UNAUTHORIZED" || json.code === "AUTH_TOKEN_EXPIRED"));
        if (unauthorized && cred.pat) {
          return callback(new Error("访问令牌被拒绝（401）：令牌无效、已撤销，" +
            "或没有签到所需的权限。请到 hyxware.com → 设置 → 安全 → 系统访问令牌 重新生成一个"), null);
        }
        if (unauthorized && attempt === 1) {
          log("access_token 被拒，重新鉴权后重试");
          clearToken();
          return run();
        }
        callback(null, { status: res.status, json: json, body: res.body });
      });
    });
  }

  run();
}

/* ============================ 业务 ============================ */

function msgOf(json, fallback) {
  if (json && typeof json === "object") {
    var m = json.message || json.message_key || json.code || json.error;
    if (m && typeof m === "string") return m;
    if (m && typeof m === "object" && m.message) return String(m.message);
  }
  return fallback || "";
}

function formatQuota(quota, qpu) {
  var unit = qpu && qpu > 0 ? qpu : DEFAULT_CONFIG.quotaPerUnit;
  var value = (num(quota) || 0) / unit;
  var decimals = Math.abs(value) >= 1 ? 2 : 4;
  return "$" + value.toFixed(decimals);
}

function fetchQuotaPerUnit(callback) {
  var state = readJSON(STORE_KEY.state) || {};
  if (num(state.qpu) > 0) return callback(num(state.qpu));
  httpRequest("GET", CFG.baseUrl + "/api/status", { headers: baseHeaders() }, function (err, res) {
    if (err) return callback(DEFAULT_CONFIG.quotaPerUnit);
    var json = parseJSON(res.body);
    var qpu = json && json.data && num(json.data.quota_per_unit);
    if (qpu && qpu > 0) {
      CFG.quotaPerUnit = qpu;
      var next = readJSON(STORE_KEY.state) || {};
      next.qpu = qpu;
      writeJSON(STORE_KEY.state, next);
      return callback(qpu);
    }
    callback(DEFAULT_CONFIG.quotaPerUnit);
  });
}

function saveState(patch) {
  var state = readJSON(STORE_KEY.state) || {};
  for (var key in patch) {
    if (has(patch, key)) state[key] = patch[key];
  }
  writeJSON(STORE_KEY.state, state);
  return state;
}

function notify(title, subtitle, body) {
  if (!notifyEnabled) return;
  try {
    if (typeof $notification !== "undefined" && $notification && $notification.post) {
      $notification.post(title, subtitle, body);
    }
  } catch (e) {
    log("通知发送失败：" + errText(e));
  }
}

function failNotify(err) {
  var text = errText(err);
  lastError = text;
  log("失败：" + text);
  saveState({ at: Date.now(), error: text });
  notify("HyxAPI 签到", "失败", text);
  finish();
}

/**
 * 签到主流程。callback(result)，result 结构见 buildResult。
 * 面板模式传 withBalance=false 时不额外查余额（用缓存里的值）。
 */
function runCheckin(options, callback) {
  options = options || {};
  var month = monthString();

  apiCall("GET", "/api/user/checkin?month=" + month, null, function (err, res) {
    if (err) return callback(err);
    if (!res || !res.json) return callback(new Error("签到状态响应无法解析（HTTP " + (res && res.status) + "）"));
    var json = res.json;
    if (json.success !== true) {
      return callback(new Error("查询签到状态失败：" + (msgOf(json) || ("HTTP " + res.status))));
    }

    var data = json.data || {};
    if (data.enabled === false) {
      return callback(null, { disabled: true, data: data });
    }

    var stats = data.stats || {};
    var today = trim(data.today) || dayString();
    if (stats.checked_in_today) {
      return callback(null, { already: true, data: data, today: today, stats: stats });
    }

    log("今日未签到，发起签到");
    apiCall("POST", "/api/user/checkin", {}, function (postErr, postRes) {
      if (postErr) return callback(postErr);
      var pjson = postRes && postRes.json;
      if (!pjson || pjson.success !== true) {
        var reason = msgOf(pjson, "HTTP " + (postRes && postRes.status));
        // 服务端可能在「查询」与「提交」之间认为已签（并发/时区差），复查一次再定性。
        return apiCall("GET", "/api/user/checkin?month=" + month, null, function (reErr, reRes) {
          var reJson = reRes && reRes.json;
          if (!reErr && reJson && reJson.success === true && reJson.data &&
              reJson.data.stats && reJson.data.stats.checked_in_today) {
            return callback(null, {
              already: true,
              data: reJson.data,
              today: trim(reJson.data.today) || today,
              stats: reJson.data.stats,
              note: reason
            });
          }
          callback(new Error("签到失败：" + reason));
        });
      }
      var payload = pjson.data || {};
      var awarded = num(payload.quota_awarded) || 0;
      callback(null, {
        awarded: awarded,
        checkinDate: trim(payload.checkin_date) || today,
        today: trim(payload.checkin_date) || today,
        stats: {
          total_checkins: (num(stats.total_checkins) || 0) + 1,
          checkin_count: (num(stats.checkin_count) || 0) + 1,
          checked_in_today: true,
          records: []
        },
        data: data
      });
    });
  });
}

function fetchBalance(callback) {
  apiCall("GET", "/api/user/self", null, function (err, res) {
    if (err) return callback(null, null);
    var json = res && res.json;
    if (!json || json.success !== true || !json.data) return callback(null, null);
    callback(null, {
      quota: num(json.data.quota),
      used: num(json.data.used_quota),
      username: trim(json.data.username || json.data.display_name)
    });
  });
}

function buildResult(outcome, balance) {
  var stats = outcome.stats || {};
  var qpu = CFG.quotaPerUnit;
  return {
    date: outcome.today || dayString(),
    checked: true,
    awarded: num(outcome.awarded) || 0,
    total: num(stats.total_checkins) || 0,
    monthCount: num(stats.checkin_count) || 0,
    balance: balance ? balance.quota : null,
    used: balance ? balance.used : null,
    user: balance ? balance.username : "",
    note: outcome.note || ""
  };
}

function resultLine(result) {
  var parts = [];
  if (result.awarded > 0) parts.push("获得 " + formatQuota(result.awarded, CFG.quotaPerUnit));
  if (result.monthCount) parts.push("本月 " + result.monthCount + " 次");
  if (result.total) parts.push("累计 " + result.total + " 次");
  if (result.balance !== null && result.balance !== undefined) {
    parts.push("余额 " + formatQuota(result.balance, CFG.quotaPerUnit));
  }
  return parts.join(" · ");
}

/* ============================ 角色一：凭据抓取 ============================ */

function headerValues(headers, name) {
  var out = [];
  if (!headers) return out;
  var lower = String(name).toLowerCase();
  if (Object.prototype.toString.call(headers) === "[object Array]") {
    for (var i = 0; i < headers.length; i++) {
      var item = headers[i] || {};
      var field = String(item.field || item.name || "");
      if (field.toLowerCase() !== lower) continue;
      out.push(String(item.value === null || item.value === undefined ? "" : item.value));
    }
    return out;
  }
  for (var key in headers) {
    if (!has(headers, key)) continue;
    if (String(key).toLowerCase() !== lower) continue;
    var value = headers[key];
    if (Object.prototype.toString.call(value) === "[object Array]") {
      for (var j = 0; j < value.length; j++) out.push(String(value[j]));
    } else {
      out.push(String(value === null || value === undefined ? "" : value));
    }
  }
  return out;
}

function headerValue(headers, name) {
  var values = headerValues(headers, name);
  return values.length ? values[0] : "";
}

/** 从 Set-Cookie 里挑出非空的 new_api_refresh（空值 = 服务端在清除，不采纳）。 */
function pickRefreshCookie(setCookieValues) {
  for (var i = setCookieValues.length - 1; i >= 0; i--) {
    var text = setCookieValues[i] || "";
    var match = /(?:^|,|\s)new_api_refresh=([^;,\s]*)/.exec(text);
    if (match && match[1]) return "new_api_refresh=" + match[1];
  }
  return "";
}

function handleCapture() {
  try {
    var reqHeaders = (typeof $request !== "undefined" && $request && $request.headers) || null;
    var resHeaders = (typeof $response !== "undefined" && $response && $response.headers) || null;
    var body = (typeof $response !== "undefined" && $response && $response.body) || "";
    var json = parseJSON(body);

    var cred = loadCred();
    var prevUid = cred.capUid;
    var changed = false;

    // 1) 浏览器发上来的整串 Cookie 最可信，先原样收下。
    var reqCookie = headerValue(reqHeaders, "Cookie");
    if (reqCookie && /new_api_refresh=/.test(reqCookie) && reqCookie !== cred.cookie) {
      cred.cookie = reqCookie;
      changed = true;
    }

    // 2) 服务端轮换了 refresh cookie 就替换那一段，其余 cookie 保留。
    var rotated = pickRefreshCookie(headerValues(resHeaders, "Set-Cookie"));
    if (rotated) {
      var next = setCookieValue(cred.cookie, "new_api_refresh",
        rotated.slice("new_api_refresh=".length));
      if (next !== cred.cookie) {
        cred.cookie = next;
        changed = true;
      }
    }

    var sid = headerValue(reqHeaders, "X-Auth-Session");
    if (sid && sid !== cred.sid) {
      cred.sid = sid;
      changed = true;
    }

    var bundle = bundleOf(json);
    if (bundle) {
      mergeBundle(cred, bundle);
      changed = true;
    }

    if (changed) {
      var firstTime = !cred.capNotified || (cred.uid && cred.uid !== prevUid);
      cred.capUid = cred.uid;
      cred.capCount = (cred.capCount || 0) + 1;
      cred.capAt = nowSeconds();
      if (firstTime) cred.capNotified = 1;
      saveCred(cred);
      log("凭据已更新（用户 " + (cred.user || cred.uid || "?") +
        "，cookie " + (cred.cookie ? "有" : "无") + "，token " + (cred.token ? "有" : "无") + "）");

      // 只在「首次抓取」或「换了账号」时提醒，避免每次登录/续期都弹一条。
      if (firstTime) {
        saveState({ user: cred.user || String(cred.uid || ""), capturedAt: Date.now() });
        notify("HyxAPI 签到", "凭据已捕获",
          (cred.user || cred.uid || "会话") + " 已保存，之后每天自动签到。");
      }
    }
  } catch (e) {
    log("抓取凭据异常：" + errText(e));
  }
  finish({});
}

/* ============================ 角色二：定时签到 ============================ */

function handleCron() {
  var startedAt = Date.now();
  log("开始执行，用户 " + (CFG.token ? "访问令牌" : (CFG.username || loadCred().user || "已捕获")));

  fetchQuotaPerUnit(function () {
    runCheckin({}, function (err, outcome) {
      if (err) return failNotify(err);

      if (outcome && outcome.disabled) {
        log("站点未开启签到");
        saveState({ at: Date.now(), disabled: true, error: "" });
        notify("HyxAPI 签到", "跳过", "站点当前未开启每日签到。");
        return finish();
      }

      fetchBalance(function (balanceErr, balance) {
        var result = buildResult(outcome, balance);
        var state = readJSON(STORE_KEY.state) || {};
        var today = dayString();
        var alreadyNotified = state.notifiedDate === today;

        saveState({
          at: Date.now(),
          date: result.date,
          checked: true,
          awarded: result.awarded,
          total: result.total,
          monthCount: result.monthCount,
          balance: result.balance,
          used: result.used,
          user: result.user || state.user || "",
          error: "",
          disabled: false,
          notifiedDate: today,
          elapsedMs: Date.now() - startedAt
        });

        var line = resultLine(result);
        log("结果：" + line);

        if (outcome.already && alreadyNotified) {
          // 今天已经报过一次「已签到」，不重复打扰。
          return finish();
        }

        if (outcome.already) {
          notify("HyxAPI 签到", "今日已签到", line);
        } else {
          notify("HyxAPI 签到", "签到成功", line);
        }

        if (CFG.lowBalance > 0 && result.balance !== null && result.balance !== undefined) {
          var dollars = result.balance / (CFG.quotaPerUnit || DEFAULT_CONFIG.quotaPerUnit);
          if (dollars < CFG.lowBalance) {
            notify("HyxAPI 余额提醒", "余额偏低",
              "当前余额 " + formatQuota(result.balance, CFG.quotaPerUnit) +
              "，低于设定阈值 $" + CFG.lowBalance + "。");
          }
        }

        finish();
      });
    });
  });
}

/* ============================ 角色三：信息面板 ============================ */

/** 面板底部那行：凭据模式 + 版本 + 抓取次数，用来判断脚本是不是新版、走的是哪条鉴权路。 */
function panelFooter(cred) {
  var mode = CFG.token ? "令牌" : "会话";
  var cap = CFG.token ? "" : (" · 抓取 " + (cred.capCount || 0) + " 次");
  return mode + cap + " · v" + SCRIPT_VERSION;
}

function panelFromState(extraNote) {
  var state = readJSON(STORE_KEY.state) || {};
  var cred = loadCred();
  var lines = [];

  if (!state.at && !hasCredential(cred)) {
    return {
      title: "HyxAPI 签到",
      content: "尚未捕获凭据\n请在浏览器退出登录再登录一次\n" +
        CFG.baseUrl.replace(/^https?:\/\//, "") + "\n" + panelFooter(cred),
      style: "alert",
      icon: "exclamationmark.triangle",
      "icon-color": "#FF9F0A"
    };
  }

  if (state.error) {
    lines.push("状态：失败");
    lines.push(String(state.error).slice(0, 120));
  } else if (state.checked) {
    var award = num(state.awarded) || 0;
    lines.push("今日：" + (award > 0 ? "已签到 " + formatQuota(award, CFG.quotaPerUnit) : "已签到"));
  } else if (state.at) {
    lines.push("今日：未签到");
  } else {
    lines.push("今日：等待首次运行");
  }

  if (num(state.monthCount) !== null && state.monthCount !== undefined) {
    lines.push("本月 " + (num(state.monthCount) || 0) + " 次 · 累计 " + (num(state.total) || 0) + " 次");
  }
  if (state.balance !== null && state.balance !== undefined && num(state.balance) !== null) {
    var usedText = state.used !== null && state.used !== undefined
      ? "（已用 " + formatQuota(state.used, CFG.quotaPerUnit) + "）" : "";
    lines.push("余额 " + formatQuota(state.balance, CFG.quotaPerUnit) + usedText);
  }
  if (state.at) {
    lines.push("更新 " + formatShort(new Date(state.at)) + (state.user ? " · " + state.user : ""));
  }
  if (extraNote) lines.push(extraNote);
  lines.push(panelFooter(cred));

  var good = !state.error && state.checked;
  return {
    title: "HyxAPI 签到",
    content: lines.join("\n"),
    style: state.error ? "error" : (good ? "good" : "info"),
    icon: state.error ? "exclamationmark.triangle" : "checkmark.seal",
    "icon-color": state.error ? "#FF453A" : (good ? "#30D158" : "#0A84FF")
  };
}

function handlePanel() {
  DEADLINE = Date.now() + 12000;
  var cred = loadCred();
  if (!hasCredential(cred)) {
    return finish(panelFromState(""));
  }

  fetchQuotaPerUnit(function () {
    runCheckin({}, function (err, outcome) {
      if (err) {
        log("面板实时刷新失败：" + errText(err));
        return finish(panelFromState("（实时刷新失败，显示上次结果）"));
      }
      if (outcome && outcome.disabled) {
        return finish({
          title: "HyxAPI 签到",
          content: "站点当前未开启每日签到",
          style: "info",
          icon: "info.circle",
          "icon-color": "#0A84FF"
        });
      }
      fetchBalance(function (balanceErr, balance) {
        var result = buildResult(outcome, balance);
        var state = readJSON(STORE_KEY.state) || {};
        saveState({
          at: Date.now(),
          date: result.date,
          checked: true,
          awarded: result.awarded,
          total: result.total,
          monthCount: result.monthCount,
          balance: result.balance,
          used: result.used,
          user: result.user || state.user || "",
          error: "",
          disabled: false
        });
        finish(panelFromState(""));
      });
    });
  });
}

/* ============================ 角色四：手动自检 ============================ */

/**
 * 在 Surge 的脚本编辑器里点「运行」时，$script.type 不是上面三种之一。
 * 以前这里直接 $done()，编辑器里只显示一个 {}，看着像「运行失败」。
 * 现在改成跑一次只读自检，把关键信息直接显示出来，不写存储、不发通知。
 */
function handleDiagnose(type) {
  DEADLINE = Date.now() + 15000;
  var lines = [];
  var cred = loadCred();
  var state = readJSON(STORE_KEY.state) || {};

  lines.push("脚本版本：" + SCRIPT_VERSION);
  lines.push("运行方式：" + (type || "未知") + "（编辑器手动运行）");
  lines.push("站点：" + CFG.baseUrl);

  if (!cred.cookie && !cred.token && !(CFG.username && CFG.password) && !CFG.token) {
    lines.push("凭据：没有（抓取 " + (cred.capCount || 0) + " 次）");
    lines.push("→ 推荐填 TOKEN（系统访问令牌）");
    lines.push("→ 或浏览器退出登录再登录一次");
    lines.push("→ 或填好 USERNAME / PASSWORD");
    log(lines.join("\n"));
    return finish({
      title: "HyxAPI 自检",
      content: lines.join("\n"),
      style: "alert",
      icon: "exclamationmark.triangle",
      "icon-color": "#FF9F0A"
    });
  }

  if (CFG.token) {
    lines.push("凭据：系统访问令牌（长度 " + CFG.token.length + "）");
  } else {
    lines.push("凭据：cookie " + (cred.cookie ? "有" : "无") +
      " · token " + (cred.token ? "有" : "无"));
    if (cred.capCount) lines.push("抓取：" + cred.capCount + " 次");
  }
  if (cred.user) lines.push("账号：" + cred.user);
  if (cred.exp) {
    var expired = cred.exp <= nowSeconds();
    lines.push("token 到期：" + formatShort(new Date(cred.exp * 1000)) + (expired ? "（已过期）" : ""));
  }
  if (state.error) lines.push("上次错误：" + String(state.error).slice(0, 80));

  log(lines.join("\n"));

  fetchQuotaPerUnit(function () {
    runCheckin({}, function (err, outcome) {
      if (err) {
        lines.push("实时查询：失败");
        lines.push(errText(err).slice(0, 120));
        log(lines.join("\n"));
        return finish({
          title: "HyxAPI 自检",
          content: lines.join("\n"),
          style: "error",
          icon: "exclamationmark.triangle",
          "icon-color": "#FF453A"
        });
      }
      if (outcome && outcome.disabled) {
        lines.push("实时查询：站点未开启签到");
        log(lines.join("\n"));
        return finish({
          title: "HyxAPI 自检",
          content: lines.join("\n"),
          style: "info",
          icon: "info.circle",
          "icon-color": "#0A84FF"
        });
      }
      fetchBalance(function (balanceErr, balance) {
        var result = buildResult(outcome, balance);
        lines.push("实时查询：正常" + (outcome.already ? "（今日已签到）" : "（今日未签到）"));
        lines.push(resultLine(result));
        log(lines.join("\n"));
        finish({
          title: "HyxAPI 自检",
          content: lines.join("\n"),
          style: "good",
          icon: "checkmark.seal",
          "icon-color": "#30D158"
        });
      });
    });
  });
}

/* ============================ 入口 ============================ */

function main() {
  CFG = loadConfig();
  notifyEnabled = CFG.notify;

  var type = "";
  try {
    type = (typeof $script !== "undefined" && $script && $script.type) || "";
  } catch (e) {
    type = "";
  }

  if (type === "http-response" || type === "http-request") {
    return handleCapture();
  }
  if (type === "cron") {
    return handleCron();
  }
  if (type === "generic") {
    return handlePanel();
  }

  // 编辑器手动运行 / 未知类型 → 只读自检，不产生任何副作用。
  return handleDiagnose(type);
}

try {
  main();
} catch (e) {
  lastError = errText(e);
  log("脚本异常：" + lastError);
  try {
    notify("HyxAPI 签到", "脚本异常", lastError);
  } catch (e2) { /* ignore */ }
  finish();
}
