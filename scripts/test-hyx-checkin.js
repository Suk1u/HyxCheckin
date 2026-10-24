#!/usr/bin/env node
/**
 * Mock tests for src/hyx_checkin.js — runs the real script end to end against
 * the surge-scripting skill's Surge mock runtime.
 *
 * Covers: capture (login / refresh / cookie rotation / clearing Set-Cookie),
 * cron success, already-checked-in, token expiry → refresh, 401 → re-auth retry,
 * password login, no-credential, network error, HTML/WAF, site disabled,
 * POST "already checked" recovery, notify off, duplicate-notification
 * suppression, and both panel states.
 *
 * Usage: node scripts/test-hyx-checkin.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const MOCK = require(
  process.env.SURGE_MOCK ||
  'C:/Users/VOS-User/.workbuddy-ai/skills/surge-scripting/scripts/surge_mock.js'
);

const SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'src', 'hyx_checkin.js'), 'utf8');

const B = 'https://hyxware.com';
const NOW = Math.floor(Date.now() / 1000);
const TOKEN1 = 'AT-aaaa-1111';
const TOKEN2 = 'AT-bbbb-2222';
const SID = 'SID-xyz';
const UID = 10086;

const JSON_H = { 'Content-Type': 'application/json' };

const ARG_CRON = [
  'baseUrl=hyxware.com',
  'username=未配置',
  'password=未配置',
  'policy=DIRECT',
  'timeout=20',
  'notify=true',
  'lowBalance=0'
].join('&');

const ARG_CRON_SILENT = ARG_CRON.replace('notify=true', 'notify=false');

/* --------------------------- canned bodies --------------------------- */

function bundle(token, exp) {
  return JSON.stringify({
    success: true,
    data: {
      access_token: token,
      token_type: 'Bearer',
      access_expires_at: exp || (NOW + 3600),
      user: { id: UID, username: 'tester', role: 1 },
      session: { sid: SID, current: true, created_at: 1, last_active_at: 1, expires_at: 9999999999 }
    }
  });
}

function checkinBody(checked) {
  return JSON.stringify({
    success: true,
    data: {
      enabled: true,
      today: '2026-10-24',
      stats: {
        total_checkins: checked ? 34 : 33,
        checkin_count: checked ? 11 : 10,
        checked_in_today: !!checked,
        records: []
      }
    }
  });
}

const POST_OK = JSON.stringify({
  success: true,
  data: { checkin_date: '2026-10-24', quota_awarded: 200 }
});

const SELF_OK = JSON.stringify({
  success: true,
  data: { id: UID, username: 'tester', quota: 8780000, used_quota: 0 }
});

const STATUS_OK = JSON.stringify({
  success: true,
  data: { checkin_enabled: true, turnstile_check: false, quota_per_unit: 500000 }
});

const UNAUTHORIZED = JSON.stringify({
  code: 'AUTH_UNAUTHORIZED',
  message: 'Unauthorized, invalid access token',
  success: false
});

/* --------------------------- helpers --------------------------- */

function credStore(over) {
  const cred = Object.assign({
    cookie: 'new_api_refresh=R1',
    sid: SID,
    token: TOKEN1,
    exp: NOW + 3600,
    uid: UID,
    user: 'tester',
    capUid: UID,
    capNotified: 1
  }, over || {});
  return { 'hyx.cred': JSON.stringify(cred) };
}

function stateStore(over) {
  return { 'hyx.state': JSON.stringify(Object.assign({ qpu: 500000 }, over || {})) };
}

/** Final persistent-store value, including the seeded value when nothing was written. */
function parsedStore(report, key) {
  const raw = report.sandbox.$persistentStore.read(key);
  if (raw === null || raw === undefined || raw === '') return null;
  try { return JSON.parse(raw); } catch (e) { return raw; }
}

/** Handler whose status/body change between successive calls. */
function seqHandler(match, seq) {
  let i = 0;
  const h = { match: match };
  Object.defineProperty(h, 'status', {
    enumerable: true,
    get: function () {
      return seq[Math.min(i, seq.length - 1)].status;
    }
  });
  h.body = function () {
    const cur = seq[Math.min(i, seq.length - 1)];
    i += 1;
    return cur.body;
  };
  return h;
}

const CHECKIN_GET = /\/api\/user\/checkin\?month=/;
const CHECKIN_POST = /\/api\/user\/checkin$/;

/** Explicit, order matters (first match wins). GET 带 ?month=，POST 不带，据此区分。 */
function buildHttp(spec) {
  const list = [];
  if (spec.status) {
    list.push({
      match: '/api/status',
      status: 200,
      body: spec.status === true ? STATUS_OK : spec.status,
      headers: JSON_H
    });
  }
  if (spec.getSeq) list.push(seqHandler(CHECKIN_GET, spec.getSeq));
  else if (spec.checkin) list.push(Object.assign({ match: CHECKIN_GET }, spec.checkin));
  if (spec.post) list.push(Object.assign({ match: CHECKIN_POST }, spec.post));
  else list.push({ match: CHECKIN_POST, status: 200, body: POST_OK, headers: JSON_H });
  if (spec.refresh) list.push(Object.assign({ match: '/api/user/auth/refresh' }, spec.refresh));
  if (spec.login) list.push(Object.assign({ match: '/api/user/login' }, spec.login));
  if (spec.self) list.push(Object.assign({ match: '/api/user/self' }, spec.self));
  return list;
}

function calls(report, re) {
  return report.requests.filter(function (r) { return re.test(r.url); });
}

function notifyText(report) {
  return report.notifications.map(function (n) {
    return (n.title || '') + ' | ' + (n.subtitle || '') + ' | ' + (n.body || '');
  }).join('\n');
}

function assertNoTokenLeak(report) {
  const hay = JSON.stringify({ logs: report.logs, notifications: report.notifications });
  [TOKEN1, TOKEN2, 'new_api_refresh=R1', 'new_api_refresh=R2'].forEach(function (s) {
    assert(hay.indexOf(s) === -1, 'secret ' + s + ' leaked into logs/notifications');
  });
}

/* --------------------------- cases --------------------------- */

const cases = [];

/* ---- 1. capture: login response ---- */
cases.push({
  name: 'capture 登录响应 → 写入 cookie + token 并通知一次',
  cfg: {
    type: 'http-response',
    argument: 'notify=true',
    request: {
      url: B + '/api/user/login',
      method: 'POST',
      headers: [{ field: 'Content-Type', value: 'application/json' }]
    },
    response: {
      status: 200,
      headers: [
        { field: 'Set-Cookie', value: 'new_api_refresh=R1; Path=/api/user/auth; HttpOnly; SameSite=Strict' },
        { field: 'Set-Cookie', value: 'new_api_has_session=1; Path=/' },
        { field: 'Content-Type', value: 'application/json' }
      ],
      body: bundle(TOKEN1)
    }
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const cred = parsedStore(r, 'hyx.cred');
    assert(cred, '凭据必须写进持久化存储');
    assert(cred.cookie.indexOf('new_api_refresh=R1') === 0, 'cookie 应来自 Set-Cookie，实际 ' + cred.cookie);
    assert(cred.token === TOKEN1, 'token 应来自响应体');
    assert(cred.uid === UID, 'uid 应来自 data.user.id');
    assert(cred.sid === SID, 'sid 应来自 data.session.sid');
    assert.strictEqual(r.notifications.length, 1, '首次抓取应通知一次');
    assert.strictEqual(r.notifications[0].subtitle, '凭据已捕获');
    assertNoTokenLeak(r);
  }
});

/* ---- 2. capture: refresh rotation, no duplicate notify ---- */
cases.push({
  name: 'capture 续期响应 → 轮换 cookie，不重复通知',
  cfg: {
    type: 'http-response',
    argument: 'notify=true',
    store: Object.assign(credStore(), stateStore({ user: 'tester' })),
    request: {
      url: B + '/api/user/auth/refresh',
      method: 'POST',
      headers: [
        { field: 'Cookie', value: 'new_api_refresh=R1; new_api_has_session=1' },
        { field: 'X-Auth-Session', value: SID }
      ]
    },
    response: {
      status: 200,
      headers: [{ field: 'Set-Cookie', value: 'new_api_refresh=R2; Path=/api/user/auth; HttpOnly' }],
      body: bundle(TOKEN2)
    }
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const cred = parsedStore(r, 'hyx.cred');
    assert(cred.cookie.indexOf('new_api_refresh=R2') === 0, '应采纳轮换后的 cookie，实际 ' + cred.cookie);
    assert(cred.token === TOKEN2, '应采纳新 token');
    assert.strictEqual(r.notifications.length, 0, '同一账号不应重复通知');
    assertNoTokenLeak(r);
  }
});

/* ---- 3. capture: clearing Set-Cookie must not wipe stored cookie ---- */
cases.push({
  name: 'capture 清除型 Set-Cookie → 不清空已存 cookie',
  cfg: {
    type: 'http-response',
    argument: 'notify=true',
    store: credStore(),
    request: { url: B + '/api/user/auth/refresh', method: 'POST', headers: [] },
    response: {
      status: 401,
      headers: [{ field: 'Set-Cookie', value: 'new_api_refresh=; Path=/api/user/auth; Max-Age=0' }],
      body: UNAUTHORIZED
    }
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const cred = parsedStore(r, 'hyx.cred');
    assert(cred.cookie.indexOf('new_api_refresh=R1') === 0, '清空型 Set-Cookie 不应覆盖已存 cookie');
  }
});

/* ---- 4. cron: success ---- */
cases.push({
  name: 'cron token 有效且未签到 → 提交签到并通知成功',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: { status: 200, body: checkinBody(false), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const posts = calls(r, CHECKIN_POST).filter(function (x) { return x.method === 'POST'; });
    assert.strictEqual(posts.length, 1, '未签到时必须提交一次签到');
    assert.strictEqual(posts[0].headers.Authorization, 'Bearer ' + TOKEN1, '签到请求必须带 Bearer token');
    const n = r.notifications[0];
    assert.strictEqual(n.subtitle, '签到成功');
    assert(n.body.indexOf('$0.0004') !== -1, '通知里应有本次获得额度，实际 ' + n.body);
    assert(n.body.indexOf('本月 11 次') !== -1, '通知里应有本月次数，实际 ' + n.body);
    assert(n.body.indexOf('余额 $17.56') !== -1, '通知里应有余额，实际 ' + n.body);
    const st = parsedStore(r, 'hyx.state');
    assert.strictEqual(st.checked, true);
    assert.strictEqual(st.monthCount, 11);
    assertNoTokenLeak(r);
  }
});

/* ---- 5. cron: already checked in ---- */
cases.push({
  name: 'cron 今日已签到 → 不发 POST，通知已签到',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: { status: 200, body: checkinBody(true), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const posts = calls(r, CHECKIN_POST).filter(function (x) { return x.method === 'POST'; });
    assert.strictEqual(posts.length, 0, '已签到不应再提交');
    assert.strictEqual(r.notifications[0].subtitle, '今日已签到');
  }
});

/* ---- 6. cron: token expired → refresh first ---- */
cases.push({
  name: 'cron token 过期 → 先用 cookie 续期再签到',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore({ token: TOKEN1, exp: NOW - 100 }), stateStore()),
    http: buildHttp({
      refresh: { status: 200, body: bundle(TOKEN2), headers: JSON_H },
      checkin: { status: 200, body: checkinBody(false), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(r.requests[0].url, B + '/api/user/auth/refresh', '第一步应是续期');
    assert(String(r.requests[0].headers.Cookie).indexOf('new_api_refresh=R1') !== -1, '续期必须带 refresh cookie');
    assert.strictEqual(r.requests[0].headers['X-Auth-Session'], SID, '续期应带会话 sid');
    const checkin = calls(r, /\/api\/user\/checkin/)[0];
    assert.strictEqual(checkin.headers.Authorization, 'Bearer ' + TOKEN2, '续期后应使用新 token');
    const cred = parsedStore(r, 'hyx.cred');
    assert.strictEqual(cred.token, TOKEN2, '新 token 必须落盘');
    assertNoTokenLeak(r);
  }
});

/* ---- 7. cron: no credential ---- */
cases.push({
  name: 'cron 无凭据 → 失败通知，不发任何请求',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: stateStore(),
    http: []
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(r.requests.length, 0, '没有凭据时不应发请求');
    assert.strictEqual(r.notifications.length, 1);
    assert.strictEqual(r.notifications[0].subtitle, '失败');
    assert(r.notifications[0].body.indexOf('尚未捕获凭据') !== -1, '应提示去浏览器登录一次');
  }
});

/* ---- 8. cron: 401 → clear token, re-auth, retry once ---- */
cases.push({
  name: 'cron token 被拒 → 清 token 重新鉴权并重试一次',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore({ token: TOKEN1, exp: NOW + 3600 }), stateStore()),
    http: buildHttp({
      getSeq: [
        { status: 401, body: UNAUTHORIZED },
        { status: 200, body: checkinBody(false) }
      ],
      refresh: { status: 200, body: bundle(TOKEN2), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(calls(r, /\/api\/user\/auth\/refresh/).length, 1, '应触发一次续期');
    const gets = calls(r, CHECKIN_GET);
    assert.strictEqual(gets.length, 2, '401 后应重试一次查询');
    assert.strictEqual(gets[1].headers.Authorization, 'Bearer ' + TOKEN2, '重试应使用续期后的 token');
    assert.strictEqual(r.notifications[0].subtitle, '签到成功');
  }
});

/* ---- 9. cron: password login mode ---- */
cases.push({
  name: 'cron 账号密码模式 → 登录后签到',
  cfg: {
    type: 'cron',
    argument: ARG_CRON.replace('username=未配置', 'username=tester').replace('password=未配置', 'password=p%40ss'),
    store: stateStore(),
    http: buildHttp({
      login: { status: 200, body: bundle(TOKEN2), headers: JSON_H },
      checkin: { status: 200, body: checkinBody(false), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.requests[0].url, B + '/api/user/login', '应先登录');
    const body = JSON.parse(r.requests[0].body);
    assert.strictEqual(body.username, 'tester');
    assert.strictEqual(body.password, 'p@ss', '密码里的百分号编码应被还原');
    assert.strictEqual(calls(r, /checkin/)[0].headers.Authorization, 'Bearer ' + TOKEN2);
    assert.strictEqual(r.notifications[0].subtitle, '签到成功');
    assertNoTokenLeak(r);
  }
});

/* ---- 10. cron: 2FA challenge on password login ---- */
cases.push({
  name: 'cron 密码登录撞上两步验证 → 明确报错',
  cfg: {
    type: 'cron',
    argument: ARG_CRON.replace('username=未配置', 'username=tester').replace('password=未配置', 'password=pw'),
    store: stateStore(),
    http: buildHttp({
      login: {
        status: 200,
        headers: JSON_H,
        body: JSON.stringify({ success: true, data: { flow_token: 'FT', expires_at: NOW + 600, methods: ['2fa'] } })
      }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.notifications[0].subtitle, '失败');
    assert(r.notifications[0].body.indexOf('两步验证') !== -1, '应说明 2FA 无法自动完成');
  }
});

/* ---- 11. cron: network error ---- */
cases.push({
  name: 'cron 网络错误 → 失败通知',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({ checkin: { error: 'connection reset' } })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.notifications[0].subtitle, '失败');
    assert(r.notifications[0].body.indexOf('网络请求失败') !== -1);
    const st = parsedStore(r, 'hyx.state');
    assert(st.error && st.error.length > 0, '失败原因应落盘给面板用');
  }
});

/* ---- 12. cron: HTML / WAF ---- */
cases.push({
  name: 'cron 返回 HTML（WAF/被拦） → 明确报错不崩溃',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<html><body>Just a moment...</body></html>' }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(r.notifications[0].subtitle, '失败');
    assert(r.notifications[0].body.indexOf('无法解析') !== -1, '应提示响应无法解析，实际 ' + r.notifications[0].body);
  }
});

/* ---- 13. cron: site disabled ---- */
cases.push({
  name: 'cron 站点关闭签到 → 跳过',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: {
        status: 200,
        headers: JSON_H,
        body: JSON.stringify({ success: true, data: { enabled: false, stats: {} } })
      }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.notifications[0].subtitle, '跳过');
    assert.strictEqual(calls(r, CHECKIN_POST).length, 0, '不应提交签到');
  }
});

/* ---- 14. cron: POST says already checked → recheck ---- */
cases.push({
  name: 'cron 提交报「已签到」 → 复查后按已签到处理',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      getSeq: [
        { status: 200, body: checkinBody(false) },
        { status: 200, body: checkinBody(true) }
      ],
      post: { status: 200, body: JSON.stringify({ success: false, message: '今天已经签到过了' }), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(r.notifications[0].subtitle, '今日已签到', '实际通知：' + notifyText(r));
  }
});

/* ---- 15. cron: notify off ---- */
cases.push({
  name: 'cron NOTIFY=false → 全程静默',
  cfg: {
    type: 'cron',
    argument: ARG_CRON_SILENT,
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: { status: 200, body: checkinBody(false), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.notifications.length, 0, '关闭通知后不应发通知');
    assert(parsedStore(r, 'hyx.state').checked === true, '结果仍应落盘');
  }
});

/* ---- 16. cron: same-day duplicate notification suppression ---- */
cases.push({
  name: 'cron 同一天已通知过「已签到」 → 不重复打扰',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(
      credStore(),
      stateStore({ notifiedDate: new Date().toISOString().slice(0, 10), checked: true })
    ),
    http: buildHttp({
      checkin: { status: 200, body: checkinBody(true), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.notifications.length, 0, '同日重复运行不应再通知');
  }
});

/* ---- 17. panel: live refresh ---- */
cases.push({
  name: 'panel 有凭据 → 返回面板字段',
  cfg: {
    type: 'generic',
    argument: ARG_CRON_SILENT,
    input: { purpose: 'panel', position: 'policy-selection', panelName: 'HyxAPI 签到' },
    trigger: 'auto-interval',
    store: Object.assign(credStore(), stateStore()),
    http: buildHttp({
      checkin: { status: 200, body: checkinBody(true), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    const out = r.result || {};
    assert(out.title, '面板必须返回 title');
    assert(String(out.content).indexOf('已签到') !== -1, '面板应显示今日状态，实际 ' + out.content);
    assert(String(out.content).indexOf('$17.56') !== -1, '面板应显示余额，实际 ' + out.content);
    assert.strictEqual(out.style, 'good');
  }
});

/* ---- 18. panel: no credential ---- */
cases.push({
  name: 'panel 无凭据 → alert 提示',
  cfg: {
    type: 'generic',
    argument: ARG_CRON_SILENT,
    input: { purpose: 'panel', position: 'policy-selection', panelName: 'HyxAPI 签到' },
    store: {},
    http: []
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert.strictEqual(r.result.style, 'alert');
    assert(String(r.result.content).indexOf('hyxware.com') !== -1, '应提示去登录哪个站点');
    assert.strictEqual(r.requests.length, 0, '没有凭据时面板不应发请求');
  }
});

/* ---- 19. panel: request failure falls back to cache ---- */
cases.push({
  name: 'panel 请求失败 → 退回上次缓存并标注',
  cfg: {
    type: 'generic',
    argument: ARG_CRON_SILENT,
    input: { purpose: 'panel', position: 'policy-selection', panelName: 'HyxAPI 签到' },
    store: Object.assign(credStore(), stateStore({
      at: Date.now() - 3600 * 1000,
      checked: true,
      awarded: 200,
      monthCount: 10,
      total: 33,
      balance: 8780000,
      used: 0,
      user: 'tester'
    })),
    http: buildHttp({ checkin: { error: 'timeout' } })
  },
  check: function (r) {
    MOCK.assertDone(r);
    assert(String(r.result.content).indexOf('已签到') !== -1, '应回退到缓存内容，实际 ' + r.result.content);
    assert(String(r.result.content).indexOf('实时刷新失败') !== -1, '应标注实时刷新失败');
  }
});

/* ---- 20. cron: quota_per_unit from /api/status when not cached ---- */
cases.push({
  name: 'cron 未缓存汇率 → 读 /api/status 的 quota_per_unit',
  cfg: {
    type: 'cron',
    argument: ARG_CRON,
    store: Object.assign(credStore(), {}),
    http: buildHttp({
      status: true,
      checkin: { status: 200, body: checkinBody(false), headers: JSON_H },
      self: { status: 200, body: SELF_OK, headers: JSON_H }
    })
  },
  check: function (r) {
    MOCK.assertDone(r);
    MOCK.assertNoErrors(r);
    assert.strictEqual(calls(r, /\/api\/status/).length, 1, '应查询一次站点状态');
    assert.strictEqual(parsedStore(r, 'hyx.state').qpu, 500000, 'qpu 应落盘复用');
    assert.strictEqual(r.notifications[0].subtitle, '签到成功');
  }
});

/* --------------------------- run --------------------------- */

MOCK.runAll(cases.map(function (c) {
  return { name: c.name, code: SCRIPT, cfg: c.cfg, check: c.check };
})).then(function (summary) {
  if (summary.failed) process.exit(1);
}).catch(function (err) {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
