# Python Worker

Python Worker 负责执行具体扫描检测，并通过 FastAPI 提供 HTTP 接口给 Go 后端调用。

## 职责
- 校验目标可达性
- 有限页面爬取（受 `MAX_CRAWL_PAGES` 限制）
- 执行启发式安全检测并返回标准化结果

## API 端点
- `GET /health` 健康检查
- `POST /api/scan` 扫描目标 URL

请求示例：
```json
{ "url": "http://target" }
```

响应示例：
```json
{
  "url": "http://target",
  "vulnerabilities": [],
  "summary": "No vulnerabilities detected",
  "timestamp": "2026-01-01T00:00:00",
  "scan_duration": 1.23
}
```

## 已实现检测
- HTTPS/TLS 使用情况
- 安全响应头（CSP、HSTS、X-Frame-Options 等）
- CORS 配置风险
- Cookie 安全标记（HttpOnly/Secure/SameSite）
- 服务器信息泄露头
- 反射型 XSS（多 payload 回显）
- SQL 错误回显检测
- SQLi 启发式检测（响应差异与错误提示）
- CSRF Token 缺失（POST 表单）
- 表单提交探测（XSS/SQLi）
- 目录列举暴露
- 敏感配置文件暴露
- 文件上传表单检测
- 管理路径暴露（弱访问控制）
- SSRF 参数探测（常见参数名+错误特征）
- XXE 入口探测（XML/DTD 错误提示）
- REST 搜索端点探测（/rest/products/search 的 SQLi/XSS）
- 开放重定向探测（Location 指向外部 URL）
- 路径穿越探测（敏感文件回显）
- API 端点发现与 JSON 探测（GET/POST 变异测试）
- 认证后操作探测（自动注册/登录后进行受保护接口测试）
- 定向探测脚本（`scripts/juice_shop_targeted_checks.py`）

## 深度探测说明
- Worker 会生成一组常见的参数化 URL 作为种子，用于 XSS/SQLi/SSRF 等检测。
- 可通过 `MAX_CRAWL_PAGES` 与 `MAX_PARAM_TESTS` 控制扫描深度与成本。
- 对 OWASP Juice Shop 会自动注册并登录，使用 Bearer Token 扫描认证后接口。

## 环境变量
- `SCAN_TIMEOUT` 默认 `300` 秒
- `MAX_CRAWL_PAGES` 默认 `30`
- `MAX_PARAM_TESTS` 默认 `50`

## 说明
- 检测为启发式规则，可能存在误报或漏报。
- 仅在授权或本地环境使用。
