# VulnPulse 🔍

> 漏洞情报追踪器 — 自动抓取 CVE/NVD/GitHub Advisory，按关键词过滤，推送到飞书

**仓库：** https://github.com/Qa486/VulnPulse-

---

## 功能

- 🤖 自动抓取 NVD CISA GitHub Security Advisories 的漏洞披露
- 🧠 AI 优先级分类（Critical / High / Medium / Low）
- 🔎 按关键词过滤（技术栈、语言、框架）
- 📩 飞书即时推送
- ⚙️ GitHub Actions 定时调度，无需自建服务器

---

## 快速开始

```bash
pip install -r requirements.txt
cp config_example.json config.json
# 编辑 config.json 填入你的关键词和飞书 Webhook
python vulnpulse.py
```

---

## 配置

编辑 `config.json`：

```json
{
  "keywords": ["python", "javascript", "java", "react", "django", "spring", "log4j", "fastapi"],
  "min_severity": "MEDIUM",
  "max_results_per_source": 20,
  "feishu_webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_WEBHOOK_ID",
  "feishu_bot_name": "VulnPulse",
  "github_tokens": ["YOUR_GITHUB_TOKEN"]
}
```

---

## GitHub Actions 自动运行

workflow 文件位于 `workflows/vulnpulse.yml`，默认每天 09:00 UTC+8 自动运行。

在 GitHub 仓库 Settings → Secrets 配置以下密钥：

| Secret 名称 | 说明 |
|---|---|
| `FEISHU_WEBHOOK` | 飞书机器人 Webhook 地址 |
| `GH_TOKEN_1` | GitHub Token（可选，用于提高 API 限额）|

---

## 数据来源

- **NVD API v2** — 美国国家漏洞数据库
- **GitHub Security Advisories** — GitHub 官方漏洞情报
- **CISA KEV** — 已知被利用的漏洞目录

---

## License

MIT
