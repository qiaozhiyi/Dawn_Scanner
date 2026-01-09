#!/bin/bash

# Dawn Scanner 一键启动 + 测试脚本
set -euo pipefail

echo "启动 Dawn Scanner 系统..."

# 检查API密钥环境变量
if [ -z "${DASHSCOPE_API_KEY:-}" ]; then
  echo "错误: 未设置 DASHSCOPE_API_KEY 环境变量"
  echo "请先导出密钥，例如: export DASHSCOPE_API_KEY=your_key"
  exit 1
fi

# 启动必要服务（跳过 dev）
echo "正在构建并启动服务..."
docker-compose up --build -d go-backend python-worker llm-service

# 确保本地测试依赖可用
if ! python3 - <<'PY'
import requests  # noqa: F401
PY
then
  echo "缺少 requests，正在安装..."
  python3 -m pip install requests
fi

# 等待后端健康检查可用
echo "等待服务启动..."
python3 - <<'PY'
import time
import requests

url = "http://localhost:8080/health"
timeout = 60
start = time.time()
while time.time() - start < timeout:
    try:
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            print("后端健康检查通过")
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(2)
raise SystemExit("等待后端健康检查超时")
PY

# 检查服务状态
echo "检查服务状态..."
docker-compose ps

# 运行测试
echo "运行功能测试..."
python3 test_system.py

echo ""
echo "系统与测试已完成！"
echo "Go后端: http://localhost:8080"
echo "LLM服务: http://localhost:8000"
echo "Python Worker: http://localhost:9000"
echo ""
echo "要停止服务，请执行: docker-compose down"
