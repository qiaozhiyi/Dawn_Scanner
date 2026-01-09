# Go 后端

Go 后端是 API 与编排层：接收扫描任务、存储任务状态、调用 Python Worker、触发 LLM 报告生成。

## 职责
- 任务管理 API（`/api/tasks`）
- 任务存储（默认文件存储）
- 扫描编排（异步流程）
- LLM 报告对接
- 鉴权中间件与请求日志

## 关键文件
- `main.go` 入口
- `scanner_flow.go` 扫描编排流程
- `handlers.go` 任务 API 处理
- `task_store.go` 任务模型与存储
- `report_client.go` LLM 服务客户端
- `middleware.go` 鉴权与日志
- `entrypoint.sh` 容器启动脚本（修正卷权限）

## API 端点
- `GET /health` 健康检查
- `POST /api/tasks` 提交扫描任务
- `GET /api/tasks` 列出任务
- `GET /api/tasks/:id` 查询任务状态/结果
- `DELETE /api/tasks/:id` 删除任务

鉴权：`Authorization: Bearer <token>`，默认 token 为 `dawn_scanner_dev_token`。

## 任务流程
1. 调用 `/api/tasks` 提交 `{ "url": "http://target" }`
2. 任务落库并标记为 `pending`
3. Worker 异步执行扫描
4. 任务更新为 `completed` 并写入结果
5. 触发 LLM 报告生成并回写

## 环境变量
- `GO_ENV` `development|production`
- `PORT` 默认 `8080`
- `LLM_SERVICE_URL` 默认 `http://llm-service:8000`
- `PYTHON_WORKER_URL` 默认 `http://python-worker:9000`
- `TASK_STORE_PATH` 默认 `/app/data/tasks/tasks.json`
- `DEFAULT_AUTH_TOKEN` 默认 `dawn_scanner_dev_token`

## 本地运行
```bash
cd go-backend
go build -o dawn-scanner
PORT=8080 ./dawn-scanner
```
