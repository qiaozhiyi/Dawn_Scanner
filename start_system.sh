#!/bin/bash

# Dawn Scanner 启动和测试脚本

echo "启动 Dawn Scanner 系统..."

# 设置API密钥环境变量
export DASHSCOPE_API_KEY=sk-83dc2763afc24c23adefc1c502270ab4

# 启动所有服务
echo "正在构建并启动服务..."
docker-compose up --build -d

echo "等待服务启动..."
sleep 10

# 检查服务状态
echo "检查服务状态..."
docker-compose ps

echo ""
echo "系统已启动！"
echo "Go后端将在 http://localhost:8080 上运行"
echo "LLM服务将在 http://localhost:8000 上运行"
echo ""
echo "要运行测试，请执行: python3 test_system.py"
echo ""
echo "要停止服务，请执行: docker-compose down"