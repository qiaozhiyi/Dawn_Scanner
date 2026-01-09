#!/bin/bash

# 一键：启动 Juice Shop、执行扫描并生成中文 Markdown 报告。
set -euo pipefail

TARGET_NAME="juice-shop"
TARGET_PORT="3000"
TARGET_URL="http://host.docker.internal:${TARGET_PORT}"
API_BASE="http://localhost:8080"
AUTH_TOKEN="dawn_scanner_dev_token"
REPORT_DIR="reports"
BASELINE_DIR="baselines"
BASELINE_URL="https://raw.githubusercontent.com/juice-shop/juice-shop/master/data/static/challenges.yml"
PACKAGE_URL="https://raw.githubusercontent.com/juice-shop/juice-shop/master/package.json"

if [ -z "${DASHSCOPE_API_KEY:-}" ]; then
  echo "错误: 未设置 DASHSCOPE_API_KEY 环境变量"
  echo "请先导出密钥，例如: export DASHSCOPE_API_KEY=your_key"
  exit 1
fi

if ! python3 - <<'PY'
import requests  # noqa: F401
PY
then
  echo "缺少 requests，正在安装..."
  python3 -m pip install requests
fi

if ! python3 - <<'PY'
import yaml  # noqa: F401
PY
then
  echo "缺少 pyyaml，正在安装..."
  python3 -m pip install pyyaml
fi

echo "启动扫描器服务..."
docker-compose up --build -d go-backend python-worker llm-service

echo "启动 OWASP Juice Shop..."
if docker ps -a --format '{{.Names}}' | grep -q "^${TARGET_NAME}$"; then
  docker start "${TARGET_NAME}"
else
  docker run -d --name "${TARGET_NAME}" -p "${TARGET_PORT}:3000" bkimminich/juice-shop
fi

echo "等待 Juice Shop 就绪..."
python3 - <<'PY'
import time
import requests

url = "http://localhost:3000"
timeout = 60
start = time.time()
while time.time() - start < timeout:
    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            print("Juice Shop 已就绪")
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(2)
raise SystemExit("等待 Juice Shop 超时")
PY

echo "获取 Juice Shop 权威基线..."
mkdir -p "${BASELINE_DIR}"
curl -L "${BASELINE_URL}" -o "${BASELINE_DIR}/juice_shop_challenges.yml"
curl -L "${PACKAGE_URL}" -o "${BASELINE_DIR}/juice_shop_package.json"

echo "提交扫描任务..."
TASK_ID="$(python3 - <<'PY'
import requests

api = "http://localhost:8080"
headers = {"Authorization": "Bearer dawn_scanner_dev_token", "Content-Type": "application/json"}
payload = {"url": "http://host.docker.internal:3000"}

resp = requests.post(f"{api}/api/tasks", headers=headers, json=payload, timeout=10)
resp.raise_for_status()
print(resp.json().get("task_id", ""))
PY
)"

if [ -z "${TASK_ID}" ]; then
  echo "未获取到 task_id，退出"
  exit 1
fi

echo "任务已提交: ${TASK_ID}"
echo "等待任务完成..."

TASK_ID="${TASK_ID}" python3 - <<'PY'
import json
import os
import time
import requests
from datetime import datetime
import yaml
import sys

api = "http://localhost:8080"
headers = {"Authorization": "Bearer dawn_scanner_dev_token", "Content-Type": "application/json"}
task_id = os.environ["TASK_ID"]

start = time.time()
data = None
while time.time() - start < 120:
    r = requests.get(f"{api}/api/tasks/{task_id}", headers=headers, timeout=10)
    r.raise_for_status()
    data = r.json()
    status = data.get("status")
    if status in ("completed", "failed"):
        break
    time.sleep(5)

if not data or data.get("status") != "completed":
    raise SystemExit("任务未完成或失败")

result = data.get("result", {})
vulns = result.get("vulnerabilities", [])
summary = result.get("summary", "")
report_text = result.get("report", "")

# Poll until LLM report replaces the placeholder text.
llm_start = time.time()
while report_text in ("", "Initial scan report generated") and time.time() - llm_start < 120:
    time.sleep(5)
    r = requests.get(f"{api}/api/tasks/{task_id}", headers=headers, timeout=10)
    r.raise_for_status()
    data = r.json()
    result = data.get("result", {})
    report_text = result.get("report", "")

baseline_path = os.path.join("baselines", "juice_shop_challenges.yml")
package_path = os.path.join("baselines", "juice_shop_package.json")
with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = yaml.safe_load(f) or []
with open(package_path, "r", encoding="utf-8") as f:
    package = json.load(f)

if isinstance(baseline, list):
    challenges = baseline
else:
    challenges = baseline.get("challenges", [])
baseline_version = package.get("version", "unknown")

def normalize(text):
    return (text or "").lower()

category_rules = [
    ("Security Headers", ["header", "csp", "content-security-policy", "xss-protection", "hsts"]),
    ("TLS/HTTPS", ["https", "tls", "ssl"]),
    ("XSS", ["xss", "cross-site scripting", "cross site scripting"]),
    ("SQL Injection", ["sql", "sqli", "database", "nosql"]),
    ("CSRF", ["csrf", "cross-site request forgery"]),
    ("SSRF", ["ssrf", "server-side request forgery"]),
    ("XXE", ["xxe", "xml external entity"]),
    ("Command Injection", ["command injection", "rce", "remote code"]),
    ("Path Traversal", ["path traversal", "directory traversal"]),
    ("File Upload", ["upload", "file"]),
    ("Auth/Session", ["auth", "authentication", "password", "session", "jwt", "token"]),
    ("Access Control", ["access control", "idor", "insecure direct object", "broken access"]),
    ("Crypto/Secrets", ["crypto", "encryption", "secret", "key", "hash"]),
    ("CORS", ["cors", "cross-origin"]),
    ("Clickjacking", ["clickjacking", "frame"]),
    ("Info Disclosure", ["information disclosure", "leak", "expose", "sensitive"]),
    ("Rate Limiting", ["rate limit", "brute force", "lockout"]),
    ("Misconfiguration", ["misconfiguration", "default", "debug", "error"]),
    ("Business Logic", ["business", "logic", "workflow"]),
]

def categorize_first(text):
    t = normalize(text)
    for cat, keys in category_rules:
        if any(k in t for k in keys):
            return cat
    return "Other"

def categorize_all(text):
    t = normalize(text)
    matches = []
    for cat, keys in category_rules:
        if any(k in t for k in keys):
            matches.append(cat)
    return matches

baseline_categories = {}
for ch in challenges:
    name = ch.get("name", "")
    desc = ch.get("description", "")
    cat = categorize_first(f"{name} {desc}")
    baseline_categories.setdefault(cat, []).append(name or desc or "Unnamed challenge")

found_categories = set()
for v in vulns:
    vtext = f"{v.get('type', '')}"
    for cat in categorize_all(vtext):
        found_categories.add(cat)

baseline_cat_list = sorted(baseline_categories.keys())
covered = [c for c in baseline_cat_list if c in found_categories]
missing = [c for c in baseline_cat_list if c not in found_categories]
coverage_pct = 0.0
if baseline_cat_list:
    coverage_pct = (len(covered) / len(baseline_cat_list)) * 100.0

ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
report_dir = "reports"
os.makedirs(report_dir, exist_ok=True)
path = os.path.join(report_dir, f"juice_shop_report_{ts}.md")

lines = []
lines.append(f"# Dawn Scanner 报告 - OWASP Juice Shop")
lines.append("")
lines.append(f"- 目标: http://host.docker.internal:3000")
lines.append(f"- 任务 ID: {task_id}")
lines.append(f"- 状态: {data.get('status')}")
lines.append(f"- 摘要: {summary}")
lines.append(f"- 基线: Juice Shop challenges.yml (版本 {baseline_version})")
lines.append("")
lines.append("## 基线覆盖情况")
lines.append(f"- 基线类别数: {len(baseline_cat_list)}")
lines.append(f"- 扫描覆盖类别数: {len(covered)}")
lines.append(f"- 覆盖率: {coverage_pct:.1f}%")
lines.append("")
lines.append("### 已覆盖类别")
if covered:
    lines.extend([f"- {c}" for c in covered])
else:
    lines.append("- 无")
lines.append("")
lines.append("### 缺失类别（示例挑战）")
if missing:
    for c in missing:
        sample = baseline_categories.get(c, [])[:5]
        lines.append(f"- {c}: {', '.join(sample)}")
else:
    lines.append("- 无")
lines.append("")
lines.append("## 漏洞列表")
if not vulns:
    lines.append("未发现漏洞。")
else:
    for idx, v in enumerate(vulns, 1):
        lines.append(f"### {idx}. {v.get('type', 'Unknown')}")
        lines.append(f"- 严重程度: {v.get('severity', 'Unknown')}")
        lines.append(f"- URL: {v.get('url', '')}")
        lines.append(f"- 描述: {v.get('description', '')}")
        details = v.get("details", "")
        if details:
            lines.append(f"- 详情: {details}")
        lines.append("")

if report_text:
    lines.append("## LLM 报告")
    lines.append(report_text)
    lines.append("")

with open(path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
try:
    from juice_shop_targeted_checks import run_checks
    targeted = run_checks("http://host.docker.internal:3000")
except Exception as exc:
    targeted = [{"check": "TargetedScripts", "hit": False, "details": f"error: {exc}"}]

with open(path, "a", encoding="utf-8") as f:
    f.write("\n")
    f.write("## 定向探测脚本结果\n")
    for item in targeted:
        status = "命中" if item.get("hit") else "未命中"
        f.write(f"- {item.get('check')}: {status} ({item.get('details')})\n")

print(path)
PY

echo ""
echo "报告已生成（Markdown）："
echo "reports/juice_shop_report_<timestamp>.md"
