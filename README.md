# HyxAPI 每日签到 · Surge 模块

`hyxware.com`（站点名 **HyxAPI**）的 Surge 每日签到模块。定时签到、把「今日是否已签 /
本月次数 / 累计次数 / 余额」送进信息面板，失败会告诉你失败在哪一步。

签到本身只有两个请求（查状态 + 提交），真正麻烦的是**鉴权**：这个站点是 New API 的
定制版，`/api/user/*` 只认短命的 `access_token`，续期靠一个 `HttpOnly` 的
`new_api_refresh` cookie。所以模块做了两件事：抓一次会话，之后每天自己续期。

## 一键安装

Surge → 首页 → 模块 → 安装新模块，填：

```
https://raw.githubusercontent.com/Suk1u/HyxCheckin/main/HyxCheckin.sgmodule
```

GitHub 慢的话换 jsDelivr：

```
https://cdn.jsdelivr.net/gh/Suk1u/HyxCheckin@main/HyxCheckin.sgmodule
```

脚本地址模块内部已写死（`.../main/hyx_checkin.js`），不用手填。安装后确认
`hyxware.com` 在 MITM 主机名里（模块会自己 `%APPEND%`）。

## 仓库结构

| 路径 | 说明 |
|---|---|
| `src/hyx_checkin.js` | **源码**，改这个 |
| `hyx_checkin.js` | 构建产物（= src 的副本），Surge 实际下载的就是它 |
| `HyxCheckin.sgmodule` | 模块，`script-path` 指向上面那个文件 |
| `scripts/build-hyx.js` | `node scripts/build-hyx.js` 把 src 同步到根目录；`--check` 做一致性校验 |
| `scripts/test-hyx-checkin.js` | 28 个 mock 场景 |
| `scripts/validate_sgmodule.py` | 模块静态校验 |

改脚本的流程是 **改 `src/` → `node scripts/build-hyx.js` → 提交推送**。
只改 `src/` 不跑构建，Surge 那边下载到的还是旧文件（`--check` 会直接报错提醒）。

## 推荐：填一个「系统访问令牌」

**浏览器会话会过期，令牌不会。** 实测抓取到的会话在 20 小时左右就被服务端拒了
（面板显示「会话已失效」），所以只靠抓取的方案必须每天有人打开站点续命。
想让它真正无人值守，用令牌：

1. 浏览器打开 `hyxware.com` → 右上角头像 → **设置 → 安全 → 系统访问令牌**
   （英文界面是 System access tokens / Personal tokens for the management API）
2. **创建访问令牌**，有效期选**永不过期**，权限至少勾上能读写账号的那几项
3. 复制生成的令牌，粘到模块参数 `TOKEN` 里
4. 完成 —— 不再需要 MITM、不再需要抓取、不再需要密码

令牌模式下脚本只用 `Authorization: Bearer <TOKEN>`，不碰 cookie、不续期、不登录。
面板底部会显示 `令牌 · v...`，看到这个就说明走的是令牌路径。

## 备选：抓浏览器会话

抓取发生在**登录响应**和**续期响应**上。启用模块后，在手机浏览器里：

1. 打开 `https://hyxware.com`；
2. 如果已经登录着，**退出登录再登录一次**（这一步必定产生登录响应，最稳）；
3. 打开 Surge → 首页 → 模块 → 该模块的面板，应该能看到余额。

登录成功会收到一条「凭据已捕获」通知。没收到就是没抓到，常见原因：

| 现象 | 原因 |
|---|---|
| 面板显示「尚未捕获凭据」+ `抓取 0 次` | MITM 没开 / 没信任证书 / 模块被其它模块的 MITM 行覆盖 |
| 面板显示「会话已失效」 | 浏览器会话过期了。重新登录一次即可恢复；想彻底解决就换令牌 |
| 通知说「两步验证」 | 账号开了 2FA，密码登录走不通，用令牌或抓取 |

> 抓取模式的一个固有弱点：浏览器自己续期时会**轮换** `new_api_refresh`，
> 如果你在那次续期时没开 Surge，存下来的 cookie 就作废了。令牌模式没有这个问题。

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `TIME` | `30 8 * * *` | cron 表达式，默认每天 08:30 |
| `TASK_NAME` | `HyxAPI签到` | 定时任务行名，改成 `#` 关闭定时签到 |
| `CAPTURE` | `HyxAPI凭据捕获` | 抓取行名，改成 `#` 关闭自动抓取（含兜底抓取行） |
| `PANEL_NAME` | `HyxAPI签到面板` | 面板名，改成 `#` 关闭面板 |
| `TOKEN` | `未配置` | **系统访问令牌，推荐填**。填了就完全绕开 cookie 会话 |
| `USERNAME` / `PASSWORD` | `未配置` | 留「未配置」表示用抓取到的会话。注意登录名是**用户名不是邮箱** |
| `NOTIFY` | `true` | 结果通知开关 |
| `POLICY` | `未配置` | 出站策略组，留「未配置」按分流规则走 |
| `TIMEOUT` | `20` | 单请求超时（秒） |
| `LOW_BALANCE` | `0` | 余额低于该美元金额时额外提醒，0 关闭 |
| `MITM_HOST` | `hyxware.com` | 需要解密的域名 |
| `BASE_URL` | `hyxware.com` | 站点域名，不要带 `https://` |

所有参数都必须有值（Surge 的硬性要求），不需要的保留默认即可。

## 模块构成（4 条 `[Script]` + 1 个 `[Panel]`）

| 行 | 类型 | 作用 |
|---|---|---|
| `{{{CAPTURE}}}` | http-response | 读登录/续期响应体 → `access_token` / `session.sid`，读 `Set-Cookie` → `new_api_refresh`。`requires-body=true`，`max-size=131072`，`full-header-mode=true` |
| `{{{CAPTURE}}}Fallback` | http-response | 只看 `Set-Cookie`，兜住第三方登录（GitHub / LinuxDO 不走 `/api/user/login`）。不读响应体，也**刻意不开 `full-header-mode`**——万一设备上的 Surge 不认这个参数，这条仍能把 cookie 收下来 |
| `{{{TASK_NAME}}}` | cron | 每日签到，`timeout=180`、`wake-system=true` |
| `HyxAPI签到脚本` | generic | 面板数据源 |

两条抓取行的顺序不能反：Surge 对同一请求只跑**第一条**匹配的 http-response 脚本，
窄的（登录/续期）必须在宽的前面。

主抓取行上 `full-header-mode=true` 是必需的 —— 不开它，多个 `Set-Cookie` 会被合并成一条，
轮换后的 `new_api_refresh` 有可能读不出来（脚本两种形态都能解析，只是开了更稳）。

## 怎么确认跑的是不是新版脚本

面板最后一行和自检第一行都带**版本号**和**抓取次数**：

```
抓取 3 次 · 10-25 12:30 · v2026-10-25.2
```

- 看不到 `v...` 这行 → Surge 跑的还是旧缓存（远程脚本默认 24 小时才更新一次）。
  删掉模块重装一次即可立刻拿到新版。
- `抓取 0 次` → 抓取从来没触发过，说明 MITM 没生效，或者你还没退出登录再登录一次。

## 接口（2026-10-24 核对）

契约来自站点前端打包产物（`assets/js/index.fc3dc60602.js` 与
`assets/js/async/t8.*.js`），并实测过未授权响应：

```
GET  /api/status                          公开。checkin_enabled / turnstile_check / quota_per_unit
POST /api/user/login                      {username,password} → data{access_token,token_type,
                                          access_expires_at,user,session}；开 2FA 时返回 flow_token
POST /api/user/auth/refresh               Cookie: new_api_refresh=…（+ X-Auth-Session: <sid>）
                                          → 同上 bundle；未授权时 401 + 清空型 Set-Cookie
GET  /api/user/checkin?month=YYYY-MM      data{enabled,today,stats{total_checkins,checkin_count,
                                          checked_in_today,records[]}}
POST /api/user/checkin                    data{checkin_date,quota_awarded}
GET  /api/user/self                       data{quota,used_quota,…}
```

- 鉴权头：`Authorization: Bearer <access_token>`。裸请求实测返回
  `401 {"code":"AUTH_UNAUTHORIZED","message":"Unauthorized, invalid access token"}`。
- 本站 `turnstile_check=false`，签到**不需要**人机验证。若站点以后打开它，
  `POST /api/user/checkin?turnstile=<token>` 需要真实 token，Surge 侧无法无人值守完成，
  脚本会如实通知失败原因。
- 余额换算：`quota / quota_per_unit`（本站 `quota_display_type=USD`、`quota_per_unit=500000`）。
  脚本会把 `/api/status` 里的值缓存起来，不重复查。

## 脚本行为

```
cron:
  1. 本地 access_token 未过期（>120s）→ 直接用
  2. 否则用 cookie 续期；续期失败 → 退回账号密码登录
  3. GET checkin?month=当前月
     · enabled=false        → 通知「跳过」
     · checked_in_today     → 通知「今日已签到」（同一天只提醒一次）
     · 否则 POST checkin    → 通知「签到成功 +$x」
  4. GET /api/user/self 取余额（失败不影响主流程）
  5. 写状态到 hyx.state，供面板使用
```

- 任何一步拿到 401 / `AUTH_UNAUTHORIZED`，会清掉本地 token 重新鉴权并**重试一次**。
- POST 报「已签到」时不做有罪推定：复查一次 GET，确认已签就按已签到处理。
- 失败通知里带服务端原始 message，不用猜。

### 手动自检

在 Surge 的脚本编辑器里点「运行」时，`$script.type` 不属于上面三种，脚本会走**只读自检**分支，
直接把结果显示在控制台里（以前这里只返回 `{}`，看着像运行失败）：

```
运行方式：manual（编辑器手动运行）
站点：https://hyxware.com
凭据：cookie 有 · token 有
账号：xxx
token 到期：10-25 12:30
实时查询：正常（今日已签到）
本月 11 次 · 累计 34 次 · 余额 $17.56
```

自检不写存储、不发通知，可以放心点。凭据有问题时它会直接说是哪一步断的。

持久化键：

- `hyx.cred` — `{cookie, sid, token, exp, uid, user, capUid}`
- `hyx.state` — `{at, date, checked, awarded, total, monthCount, balance, used, user, error, notifiedDate, qpu}`

## 已知限制

- **2FA**：账号开了两步验证，密码登录会停在 `flow_token` 上，脚本明确报错。用抓取模式不受影响。
- **凭据过期不会自动复活**：cookie 被服务端吊销后只能重新登录一次。脚本会通知「会话续期失败」。
- **抓取依赖 MITM**：关掉 MITM 就抓不到；已抓到的凭据仍可用，直到过期。
- **`checked_in_today` 的时区**以服务端为准，脚本按手机本地时间拼 `month=YYYY-MM`；
  跨月那天的月度统计可能差一天，不影响签到本身。

## 测试

```bash
python scripts/validate_sgmodule.py HyxCheckin.sgmodule   # 静态校验，0 error
node --check src/hyx_checkin.js                           # 语法
node scripts/build-hyx.js --check                         # 模块 ↔ 脚本一致性（含产物是否落后于 src）
node scripts/test-hyx-checkin.js                          # 28 个 mock 场景
```

`scripts/test-hyx-checkin.js` 覆盖：登录响应抓取、续期轮换 cookie、清除型 Set-Cookie 不覆盖、
签到成功、今日已签到、token 过期续期、401 重新鉴权重试、账号密码登录、2FA 报错、
网络错误、HTML/WAF、站点关闭签到、POST 报已签到后复查、通知开关、
同日不重复通知、面板正常/无凭据/请求失败回退、`quota_per_unit` 缓存、
编辑器自检三态、整串 cookie 保留、令牌模式成功/被拒、令牌模式面板。

其中「401 重新鉴权重试」这条抓过一个真 bug：`$httpClient` 的方法名是小写的，
传 `"POST"` 会取到 `undefined` 并**静默退化成 GET** —— 签到请求会变成一次多余的查询。
