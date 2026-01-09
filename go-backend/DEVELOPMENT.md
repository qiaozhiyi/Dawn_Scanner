# go-backend

## 目的
Go 后端负责：任务管理 API（提交扫描/查询）、作业队列管理（简易实现为文件或 DB）、与 llm-service 的对接（调用报告生成接口）、鉴权与日志。

## 目录结构
```txt
go-backend/
├─ main.go
├─ handlers.go
├─ report_client.go
├─ task_store.go
├─ Dockerfile
├─ go.mod
├─ go.sum
└─ tests/
```

## 关键环境变量
- `GO_ENV`=development|production
- `PORT`=8080
- `LLM_SERVICE_URL`=http://llm-service:8000
- `PYTHON_WORKER_URL`=http://python-worker:9000
- `OPENAI_API_KEY`（若后端直接调用 OpenAI）

不要把密钥写到代码或 Dockerfile 中。

## 本地运行（开发）
```bash
cd go-backend
go build -o go-backend
PORT=8080 ./go-backend
