# Dawn Scanner

本项目是一个本地漏洞扫描系统，由 Go 后端、Python 扫描 Worker 和 LLM 报告服务组成（Qwen + LangChain）。

## 架构
- `go-backend/` 负责任务 API、任务存储、扫描编排、LLM 报告对接。
- `python-worker/` 负责具体的扫描与检测逻辑。
- `llm-service/` 负责生成详细的漏洞报告。

各模块说明：
- `go-backend/README.md`
- `python-worker/README.md`
- `llm-service/README.md`

## 快速开始
```bash
export DASHSCOPE_API_KEY=your_key
docker-compose up --build -d
python3 test_system.py
```

## 一键 Juice Shop 扫描 + 基线对比
```bash
export DASHSCOPE_API_KEY=your_key
bash run_juice_shop_test.sh
```
该脚本会：
- 启动扫描器服务与本地 OWASP Juice Shop
- 针对 `http://host.docker.internal:3000` 进行扫描
- 拉取官方 Juice Shop 基线（challenges.yml）
- 生成包含“基线覆盖率”的 Markdown 报告
- 等待 LLM 报告生成完成后再写入 Markdown

报告输出目录：`reports/`
定向探测脚本：`scripts/juice_shop_targeted_checks.py`

## API 概览（Go Backend）
- `GET /health` 系统健康检查
- `POST /api/tasks` 提交扫描任务
- `GET /api/tasks` 列出任务
- `GET /api/tasks/:id` 查询任务状态/结果
- `DELETE /api/tasks/:id` 删除任务

鉴权：`Authorization: Bearer <token>`，默认 token 为 `dawn_scanner_dev_token`。

## 数据目录
- `data/tasks/` 任务存储
- `data/results/` 扫描结果
- `data/reports/` LLM 报告产物
- `reports/` 脚本生成的 Markdown 报告

## 环境变量
通用：
- `DASHSCOPE_API_KEY` Qwen API Key

Go Backend：
- `GO_ENV` `development|production`
- `PORT` 默认 `8080`
- `LLM_SERVICE_URL` 默认 `http://llm-service:8000`
- `PYTHON_WORKER_URL` 默认 `http://python-worker:9000`
- `TASK_STORE_PATH` 默认 `/app/data/tasks/tasks.json`
- `DEFAULT_AUTH_TOKEN` 默认 `dawn_scanner_dev_token`

Python Worker：
- `SCAN_TIMEOUT` 默认 `300`
- `MAX_CRAWL_PAGES` 默认 `30`
- `MAX_PARAM_TESTS` 默认 `50`

LLM Service：
- `PORT` 默认 `8000`
- `LLM_MODEL_NAME` 默认 `qwen-max`

## 说明
- 当前扫描为启发式检测，即使加深探测也无法保证覆盖“所有已知漏洞”。
- 建议只在授权或本地环境使用。
