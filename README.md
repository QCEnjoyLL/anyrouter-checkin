# AnyRouter 自动签到 + 余额查询

[anyrouter.top](https://anyrouter.top)（基于 NewAPI 的 Claude 中转站）每日自动签到，并返回账户余额。

<details>
<summary>为什么是脚本，而不是 QD（签到框架）的 HAR 模板？</summary>

anyrouter.top 挡在 **阿里云 ESA 的 `acw_sc__v2` JS 挑战 WAF** 后面：

1. 任何请求第一次都会先收到一段 **JavaScript 挑战**，必须执行它算出 `acw_sc__v2` cookie，带着它再请求才能拿到真数据；
2. `acw_sc__v2` 是 **按来源 IP 现场计算** 的——浏览器里导出的旧值换到别的机器上直接失效；
3. QD / 签到 这类框架是 **纯 HTTP、不执行 JavaScript**，所以无法自行过这道 WAF。

因此用一个会执行挑战 JS 的 Node 脚本来做。脚本通过 Node 内置的 `vm` 沙箱执行挑战脚本，自动算出 `acw_sc__v2`，**零第三方依赖**。

</details>

## 准备：拿到 `session` 和 `user_id`

1. 浏览器登录 anyrouter.top；
2. 按 `F12` → **Application（应用）** → 左侧 **Cookies** → 选 `https://anyrouter.top` → 复制 **`session`** 的值（很长一串）；
3. `F12` → **Network（网络）** → 刷新页面，随便点一个发往 `/api/...` 的请求 → **Request Headers（请求标头）** 里找 **`new-api-user`**，它的值就是你的 `user_id`（通常 4~5 位数字）。

> `session` 默认约 1 个月有效，过期后脚本会报“未登录/401”，届时重新获取即可。

## 配置（任选其一）

**方式 A：本地配置文件**（推荐本地使用）

```bash
cp accounts.example.json accounts.json
# 编辑 accounts.json，填入你的 session 和 user_id
```

`accounts.json` 已被 `.gitignore` 忽略，不会被提交。支持多账号。

**方式 B：环境变量（单账号）**

```bash
export ANYROUTER_SESSION='你的session'
export ANYROUTER_USER_ID='12345'
```

**方式 C：环境变量（多账号，适合 CI/Secrets）**

```bash
export ANYROUTER_ACCOUNTS='[{"name":"主号","session":"xxx","user_id":12345}]'
```

## 运行

```bash
node checkin.js
```

输出示例：

```
✅ [主号] 签到成功；余额 $2024.41（已用 $358.55）
```

> 需要 Node.js 18 及以上。重复运行无副作用（当天已签到再签依然安全）。

## 定时运行

**Linux / macOS（crontab）**——每天 8:07 跑一次：

```cron
7 8 * * * cd /path/to/anyrouter-checkin && /usr/bin/node checkin.js >> checkin.log 2>&1
```

**Windows**：用「任务计划程序」新建任务，程序填 `node`，参数填 `checkin.js`，起始位置填脚本目录。

**GitHub Actions（免费托管，无需自己开机）**：

1. 把本目录推到一个 **私有** GitHub 仓库；
2. 仓库 **Settings → Secrets and variables → Actions** 新建 secret：
   - 名称 `ANYROUTER_ACCOUNTS`
   - 值为 JSON 数组：`[{"name":"主号","session":"xxx","user_id":12345}]`
3. 已内置 [`.github/workflows/checkin.yml`](.github/workflows/checkin.yml)，每天 **北京时间早 8 点、晚 8 点** 各自动跑一次，也可在 Actions 页面手动触发。

> GitHub Actions 定时常有几分钟~十几分钟延迟，属正常现象；重复签到无副作用。若想改时间，编辑 workflow 里的 `cron`（用 UTC，北京时间减 8 小时）。

> ⚠️ session 是敏感凭证，**务必用私有仓库 + Secrets**，不要把它写进代码或公开仓库。

## 可选：签到结果通知

设置了对应环境变量（或 Actions Secret）才启用，可同时配多个。多账号会**汇总成一条消息**推送（含每个账号余额、合计余额、成功计数和时间）。

| 渠道 | 环境变量 |
| --- | --- |
| 飞书 / Lark | `FEISHU_WEBHOOK`（自定义机器人 webhook 地址） |
| 钉钉 | `DINGTALK_WEBHOOK`，加签可选填 `DINGTALK_SECRET` |
| **企业微信应用** | `QYWX_AM` = `corpid,corpsecret,touser,agentid[,media_id]` |
| 企业微信群机器人 | `WECOM_WEBHOOK`（群机器人 webhook 地址） |
| Telegram | `TG_BOT_TOKEN` + `TG_CHAT_ID` |
| Bark | `BARK_URL`（如 `https://api.day.app/yourkey`） |
| Server酱 | `SC_KEY`（`SCT` 开头的 SendKey） |
| 通用 webhook | `NOTIFY_WEBHOOK`（收到 `{title, text}` 的 JSON POST） |

> 钉钉 / 企业微信群机器人若设了「自定义关键词」安全策略，关键词填 `签到` 或 `AnyRouter` 即可（推送标题已包含）。钉钉用「加签」则填 `DINGTALK_SECRET`。

**企业微信应用 `QYWX_AM`**（逗号分隔，请用英文逗号）：

```
corpid,corpsecret,touser,agentid[,media_id]
```

- `corpid`：企业 ID；`corpsecret`：应用的 Secret；`agentid`：应用 AgentId；
- `touser`：接收成员，`@all` 发给全部，多个成员用 `|` 隔开；
- `media_id`：**选填**，不填发文本消息，填了发图文(mpnews)；
- 例：`wwcfrs,B-76WERQ,qinglong,1000001,2COat`（占位示例；兼容写法 `WEWORK_APP_KEY` 同义）。

推送消息示例（多账号）：

```
AnyRouter 签到 2/2 成功
✅ [主号] 签到成功；余额 $2024.41（已用 $358.55）
✅ [小号] 今日已签到；余额 $50.00（已用 $0.00）
— 合计余额 $2074.41
🕒 2026/6/10 21:30:00
```

## 说明

- 余额换算：NewAPI 的额度单位中 `500000 quota = $1`，脚本已自动换算成美元。
- 仅供学习与个人账号自动化使用。
