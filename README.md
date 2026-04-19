# VulnPulse 🔍

> 漏洞情报追踪器 — 自动抓取 CVE/NVD/GitHub Advisory，按关键词过滤，推送到飞书

## 功能

- 🤖 自动抓取 NVD CISA GitHub Security Advisories 的漏洞披露
- 🧠 AI 优先级分类（Critical / High / Medium / Low）
- 🔎 按关键词过滤（技术栈、语言、框架）
- 📩 飞书即时推送
- ⚙️ GitHub Actions 定时调度，无需自建服务器

## 快速开始

```bash
pip install -r requirements.txt
cp config_example.json config.json
# 编辑 config.json 填入你的关键词和飞书 Webhook
python vulnpulse.py
```

## 配置

编辑 `config.json`：

```json
{
  "keywords": ["python", "django", "react", "spring", "log4j"],
  "min_severity": "MEDIUM",
  "feishu_webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx",
  "github_tokens": ["your_github_token"]
}
```

## GitHub Actions 自动运行

`.github/workflows/vulnpulse.yml` 已包含在仓库中，默认每天 9:00 自动运行。

## License

MIT
