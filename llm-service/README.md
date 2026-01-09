# LLM 服务

LLM 服务负责将扫描结果整理为结构化的中文报告，使用 Tongyi Qwen（LangChain 调用）。

## 职责
- 接收扫描结果
- 生成结构化安全报告
- 返回报告给 Go 后端

## API 端点
- `GET /health` 健康检查
- `POST /api/report/generate` 生成报告

请求示例：
```json
{
  "task_id": "task_123",
  "url": "http://target",
  "summary": "Found vulnerabilities: 1 high severity",
  "vulnerabilities": [
    {
      "id": "ssl-missing",
      "type": "SSL/TLS Missing",
      "severity": "High",
      "description": "Site does not use HTTPS encryption",
      "url": "http://target",
      "details": "The website does not use HTTPS"
    }
  ]
}
```

响应示例：
```json
{
  "task_id": "task_123",
  "report": "Generated report text",
  "status": "completed",
  "error": null
}
```

## 环境变量
- `DASHSCOPE_API_KEY` 必填
- `LLM_MODEL_NAME` 默认 `qwen-max`
- `PORT` 默认 `8000`

## 说明
- 报告内容会随模型与参数变化。
