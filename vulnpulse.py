#!/usr/bin/env python3
"""
VulnPulse - 漏洞情报追踪器
自动抓取 CVE/NVD/GitHub Advisory，按关键词过滤，推送到飞书
"""

import json
import requests
import time
import os
import sys
from datetime import datetime, timedelta, timezone
from dateutil import parser as dateutil_parser
from typing import List, Dict, Any, Optional

# ============================================================
# 配置
# ============================================================

def load_config() -> Dict[str, Any]:
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if not os.path.exists(config_path):
        print(f"[!] config.json not found. Copy config_example.json and edit it.")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

CONFIG = load_config()

# ============================================================
# 工具函数
# ============================================================

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def severity_score(s: str) -> int:
    return SEVERITY_ORDER.get(s.upper(), 99)

def filter_by_keywords(text: str, keywords: List[str]) -> bool:
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in keywords)

def parse_date(date_str: str) -> datetime:
    try:
        return dateutil_parser.isoparse(date_str)
    except Exception:
        return datetime.now(timezone.utc)

def format_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC")

# ============================================================
# 数据源：NVD API v2
# ============================================================

def fetch_nvd(days_back: int = 7, max_results: int = 50) -> List[Dict[str, Any]]:
    """从 NVD API 获取最近披露的漏洞"""
    pub_start = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000 UTC")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": pub_start,
        "resultsPerPage": min(max_results, 100),
    }
    headers = {"Accept": "application/json"}
    
    print(f"[NVD] Fetching from {pub_start}...")
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        print(f"[NVD] Got {len(vulns)} vulnerabilities")
        return vulns
    except Exception as e:
        print(f"[NVD] Error: {e}")
        return []

def parse_nvd_vuln(item: Dict, keywords: List[str]) -> Optional[Dict[str, Any]]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descs = cve.get("descriptions", [])
    en_desc = next((d["value"] for d in descs if d.get("lang", "").startswith("en")), descs[0]["value"] if descs else "")
    
    if not filter_by_keywords(f"{cve_id} {en_desc}", keywords):
        return None
    
    metrics = cve.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    cvss_v2 = metrics.get("cvssMetricV2", [])
    
    score = None
    severity = "MEDIUM"
    if cvss_v31:
        s = cvss_v31[0]["cvssData"]
        score = s.get("baseScore")
        severity = s.get("baseSeverity", "MEDIUM")
    elif cvss_v30:
        s = cvss_v30[0]["cvssData"]
        score = s.get("baseScore")
        severity = s.get("baseSeverity", "MEDIUM")
    elif cvss_v2:
        score = cvss_v2[0]["cvssData"].get("baseScore")
        severity = "MEDIUM" if score and score >= 7 else ("LOW" if score and score < 4 else "MEDIUM")
    
    refs = cve.get("references", [])
    ref_url = refs[0]["url"] if refs else ""
    
    return {
        "id": cve_id,
        "source": "NVD",
        "severity": severity.upper(),
        "score": score,
        "description": en_desc[:300],
        "url": ref_url,
        "published": cve.get("published", ""),
    }

# ============================================================
# 数据源：GitHub Security Advisories
# ============================================================

def fetch_github_advisories(keywords: List[str], max_results: int = 50) -> List[Dict[str, Any]]:
    """从 GitHub Advisory API 获取数据库漏洞"""
    # GH API 不需要 token 也能读 public advisories，但有 token 限额更高
    headers = {"Accept": "application/vnd.github+json"}
    tokens = CONFIG.get("github_tokens", [])
    token = tokens[0] if tokens else None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    # 查询最近 7 天更新，且包含关键词的
    query = " ".join(keywords)
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    print(f"[GitHub] Searching advisories updated since {since}...")
    results = []
    
    try:
        url = "https://api.github.com/advisories"
        params = {
            "affects": "*",  # 所有生态系统
            "updated_since": since,
            "per_page": min(max_results, 100),
            "direction": "desc",
        }
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        advisories = resp.json()
        
        for adv in advisories:
            gh_id = adv.get("ghsa_id", "")
            cve_id = adv.get("cve_id", "")
            summary = adv.get("summary", "")
            description = adv.get("description", "")
            severity = adv.get("severity", "MEDIUM")
            published = adv.get("published_at", "")
            updated = adv.get("updated_at", "")
            html_url = adv.get("html_url", "")
            vuln_url = adv.get("url", "")
            
            text_to_check = f"{gh_id} {cve_id} {summary} {description}"
            
            # 过滤
            matched_kws = [kw for kw in keywords if kw.lower() in text_to_check.lower()]
            if not matched_kws:
                continue
            
            # 解析影响范围
            packages = []
            for vuln_iface in adv.get("vulnerabilities", []):
                pkg = vuln_iface.get("package", "")
                ecosystem = vuln_iface.get("ecosystem", "")
                if pkg:
                    packages.append(f"{ecosystem}:{pkg}")
            
            results.append({
                "id": gh_id,
                "cve": cve_id,
                "source": "GitHub Advisory",
                "severity": severity.upper(),
                "score": None,
                "description": summary,
                "detail": description[:200] if description else "",
                "url": html_url,
                "packages": packages[:5],
                "keywords": matched_kws,
                "published": published,
                "updated": updated,
            })
        
        print(f"[GitHub] Found {len(advisories)} recent, matched {len(results)} with keywords")
        
    except Exception as e:
        print(f"[GitHub] Error: {e}")
    
    return results

# ============================================================
# 数据源：CISA Known Exploited Vulnerabilities
# ============================================================

def fetch_cisa_kev(days_back: int = 30) -> List[Dict[str, Any]]:
    """从 CISA KEV 目录获取已知被利用的漏洞"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print(f"[CISA] Fetching KEV catalog...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
        recent = []
        for v in vulns:
            date_added = v.get("dateAdded", "")
            if date_added:
                dt = parse_date(date_added)
                if dt.replace(tzinfo=None) >= cutoff.replace(tzinfo=None):
                    recent.append({
                        "id": v.get("cveID", ""),
                        "source": "CISA KEV",
                        "severity": "CRITICAL",
                        "score": 10.0,
                        "description": v.get("vulnerabilityName", ""),
                        "url": v.get("vendorProject", ""),
                        "date_added": date_added,
                        "short_description": v.get("shortDescription", ""),
                    })
        print(f"[CISA] Found {len(recent)} recent KEV entries")
        return recent
    except Exception as e:
        print(f"[CISA] Error: {e}")
        return []

# ============================================================
# 飞书推送
# ============================================================

def build_feishu_message(vulns: List[Dict[str, Any]], title: str = "🆕 今日漏洞情报") -> Dict:
    """构建飞书富文本消息"""
    if not vulns:
        return None
    
    # 按严重性排序
    sorted_vulns = sorted(vulns, key=lambda v: severity_score(v.get("severity", "MEDIUM")))
    
    # 按严重性分组
    by_severity = {}
    for v in sorted_vulns:
        sev = v.get("severity", "MEDIUM").upper()
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(v)
    
    # 构建卡片内容
    elements = [
        {
            "tag": "markdown",
            "content": f"**{title}**\n共 {len(vulns)} 条 | 关键词匹配\n---\n"
        }
    ]
    
    # 按 CRITICAL > HIGH > MEDIUM > LOW 顺序输出
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev not in by_severity:
            continue
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[sev]
        items = by_severity[sev]
        elements.append({
            "tag": "markdown",
            "content": f"**{sev_icon} {sev}** ({len(items)} 条)\n"
        })
        
        for v in items[:5]:  # 每类最多显示5条
            vid = v.get("id", v.get("cve", ""))
            desc = v.get("description", v.get("short_description", ""))[:80]
            url = v.get("url", "")
            score = v.get("score")
            packages = v.get("packages", [])
            kws = v.get("keywords", [])
            
            score_str = f"CVSS {score}" if score else ""
            pkg_str = f" | {', '.join(packages[:2])}" if packages else ""
            kw_str = f"匹配: `{'`, `'.join(kw for kw in kws[:3])}`" if kws else ""
            
            line = f"**{vid}** {score_str} {pkg_str}\n{desc}..."
            if url:
                line += f"\n[链接]({url})"
            if kw_str:
                line += f"\n{kw_str}"
            line += "\n---\n"
            
            elements.append({"tag": "markdown", "content": line})
        
        if len(items) > 5:
            elements.append({"tag": "markdown", "content": f"_...还有 {len(items)-5} 条 {sev} 漏洞_"})
    
    # 如果总数超过20，加上总计
    if len(vulns) > 20:
        elements.append({
            "tag": "markdown",
            "content": f"\n---\n📊 共 {len(vulns)} 条漏洞，按严重性排序。"
        })
    
    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": f"🔍 VulnPulse - {title}"},
                "template": "red"
            },
            "elements": elements
        }
    }

def send_feishu(message: Dict) -> bool:
    webhook = CONFIG.get("feishu_webhook", "")
    if not webhook or "YOUR_WEBHOOK_ID" in webhook:
        print("[!] Feishu webhook not configured. Skipping push.")
        return False
    
    bot_name = CONFIG.get("feishu_bot_name", "VulnPulse")
    headers = {"Content-Type": "application/json"}
    
    # 飞书自定义机器人的签名（如果配置了）
    # 目前用简单 webhook 方式
    try:
        resp = requests.post(webhook, json=message, headers=headers, timeout=15)
        result = resp.json()
        if result.get("code") == 0 or result.get("StatusCode") == 0:
            print(f"[✓] Feishu push success: {len(message.get('card', {}).get('elements', []))} elements")
            return True
        else:
            print(f"[!] Feishu push failed: {result}")
            return False
    except Exception as e:
        print(f"[!] Feishu push error: {e}")
        return False

# ============================================================
# 主流程
# ============================================================

def main():
    print(f"\n{'='*60}")
    print(f"VulnPulse 漏洞情报追踪器")
    print(f"运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    keywords = CONFIG.get("keywords", [])
    min_severity = CONFIG.get("min_severity", "MEDIUM").upper()
    max_per = CONFIG.get("max_results_per_source", 20)
    
    if not keywords:
        print("[!] No keywords configured. Edit config.json")
        sys.exit(1)
    
    print(f"[*] 关键词: {', '.join(keywords)}")
    print(f"[*] 最低严重性: {min_severity}")
    print()
    
    all_vulns = []
    
    # 1. NVD
    nvd_raw = fetch_nvd(days_back=7, max_results=max_per)
    for item in nvd_raw:
        parsed = parse_nvd_vuln(item, keywords)
        if parsed and severity_score(parsed["severity"]) <= severity_score(min_severity):
            all_vulns.append(parsed)
    
    time.sleep(1)
    
    # 2. GitHub Advisories
    gh_raw = fetch_github_advisories(keywords, max_results=max_per)
    for v in gh_raw:
        if severity_score(v["severity"]) <= severity_score(min_severity):
            all_vulns.append(v)
    
    time.sleep(1)
    
    # 3. CISA KEV
    cisa_raw = fetch_cisa_kev(days_back=30)
    for v in cisa_raw:
        if severity_score(v["severity"]) <= severity_score(min_severity):
            # KEV 默认就是 CRITICAL，不过滤关键词
            if filter_by_keywords(v.get("description", ""), keywords):
                all_vulns.append(v)
    
    # 去重（按 ID）
    seen = set()
    unique_vulns = []
    for v in all_vulns:
        vid = v.get("id", "")
        if vid and vid not in seen:
            seen.add(vid)
            unique_vulns.append(v)
    
    print(f"\n[*] 去重后共 {len(unique_vulns)} 条漏洞匹配")
    
    if not unique_vulns:
        print("[*] 没有新的漏洞匹配关键词配置")
        print("[*] VulnPulse 退出")
        return
    
    # 构建并推送
    title = f"漏洞情报 {datetime.now().strftime('%m/%d')} | {len(unique_vulns)} 条"
    msg = build_feishu_message(unique_vulns, title)
    if msg:
        send_feishu(msg)
    
    print(f"\n[✓] VulnPulse 完成")
    print(f"[*] 共处理 {len(unique_vulns)} 条漏洞")

if __name__ == "__main__":
    main()
