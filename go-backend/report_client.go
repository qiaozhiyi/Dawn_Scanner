package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ReportClient 与LLM服务通信的客户端
type ReportClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewReportClient 创建新的报告客户端
func NewReportClient() *ReportClient {
	baseURL := os.Getenv("LLM_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://llm-service:8000"
	}

	return &ReportClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second, // 增加超时时间以适应Qwen API
		},
	}
}

// ScanReportRequest 发送到LLM服务的扫描报告请求
type ScanReportRequest struct {
	TaskID          string          `json:"task_id"`
	URL             string          `json:"url"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         string          `json:"summary"`
}

// ScanReportResponse 从LLM服务接收的扫描报告响应
type ScanReportResponse struct {
	TaskID string `json:"task_id"`
	Report string `json:"report"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// GenerateReport 调用LLM服务生成详细的安全报告
func (rc *ReportClient) GenerateReport(task *Task) (*ScanReportResponse, error) {
	if task.Result == nil {
		return nil, fmt.Errorf("task has no result to generate report from")
	}

	reqBody := ScanReportRequest{
		TaskID:          task.ID,
		URL:             task.URL,
		Vulnerabilities: task.Result.Vulnerabilities,
		Summary:         task.Result.Summary,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/api/report/generate", rc.BaseURL)
	resp, err := rc.HTTPClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to LLM service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LLM service returned status %d: %s", resp.StatusCode, string(body))
	}

	var reportResp ScanReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&reportResp); err != nil {
		return nil, fmt.Errorf("failed to decode response from LLM service: %w", err)
	}

	return &reportResp, nil
}

// HealthCheck 检查LLM服务是否健康
func (rc *ReportClient) HealthCheck() error {
	url := fmt.Sprintf("%s/health", rc.BaseURL)
	resp, err := rc.HTTPClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to reach LLM service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LLM service health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// IntegrationWithLLM 将LLM集成到扫描流程中的辅助函数
func (rc *ReportClient) IntegrationWithLLM(task *Task) error {
	// 首先检查LLM服务是否可用
	if err := rc.HealthCheck(); err != nil {
		return fmt.Errorf("LLM service is not available: %w", err)
	}

	// 生成详细报告
	reportResp, err := rc.GenerateReport(task)
	if err != nil {
		return fmt.Errorf("failed to generate report from LLM service: %w", err)
	}

	// 更新任务结果中的报告字段
	if task.Result != nil {
		task.Result.Report = reportResp.Report
	}

	return nil
}