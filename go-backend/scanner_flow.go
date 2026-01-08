/*
 * Dawn Scanner - Complete Vulnerability Scanning Flow
 * This file demonstrates how all components work together
 */

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// Scanner orchestrates the complete vulnerability scanning workflow
type Scanner struct {
	taskStore   TaskStore
	reportClient *ReportClient
}

// NewScanner creates a new scanner instance
func NewScanner(taskStore TaskStore) *Scanner {
	return &Scanner{
		taskStore:    taskStore,
		reportClient: NewReportClient(),
	}
}

// CompleteScanFlow performs the complete vulnerability scanning workflow
func (s *Scanner) CompleteScanFlow(url string) (*Task, error) {
	// Step 1: Create a new scan task
	task, err := s.taskStore.CreateTask(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan task: %w", err)
	}

	// Log the event
	LogEvent("scan_task_created", "New scan task created", map[string]interface{}{
		"task_id": task.ID,
		"url":     url,
	})

	// Step 2: Trigger the actual scan (this would typically be asynchronous)
	// In a real implementation, this might trigger a Python worker via API
	go s.executeCompleteScan(task.ID)

	return task, nil
}

// executeCompleteScan executes the complete scanning workflow
func (s *Scanner) executeCompleteScan(taskID string) {
	// Get the task
	task, err := s.taskStore.GetTask(taskID)
	if err != nil {
		LogEvent("error", fmt.Sprintf("Failed to get task %s: %v", taskID, err), nil)
		return
	}

	// Update task status to running
	now := time.Now()
	task.Status = TaskRunning
	task.StartedAt = &now
	if err := s.taskStore.UpdateTask(task); err != nil {
		LogEvent("error", fmt.Sprintf("Failed to update task %s status: %v", taskID, err), nil)
		return
	}

	// Log the event
	LogEvent("scan_started", "Scan started", map[string]interface{}{
		"task_id": task.ID,
		"url":     task.URL,
	})

	// Step 1: Call Python worker to perform the actual scan
	scanResult, err := s.callPythonWorker(task.URL)
	if err != nil {
		// Handle error
		task.Status = TaskFailed
		task.Error = fmt.Sprintf("Scan failed: %v", err)
		task.CompletedAt = &now
		s.taskStore.UpdateTask(task)

		LogEvent("scan_failed", fmt.Sprintf("Scan failed for task %s: %v", taskID, err), nil)
		return
	}

	// Update task with scan results
	task.Result = &Result{
		Vulnerabilities: scanResult.Vulnerabilities,
		Summary:         scanResult.Summary,
		Report:          "Initial scan report generated",
	}

	// Update task status to completed
	task.Status = TaskCompleted
	task.CompletedAt = &now
	if err := s.taskStore.UpdateTask(task); err != nil {
		LogEvent("error", fmt.Sprintf("Failed to update task %s with results: %v", taskID, err), nil)
		return
	}

	// Log the event
	LogEvent("scan_completed", "Scan completed", map[string]interface{}{
		"task_id": task.ID,
		"url":     task.URL,
		"vulnerability_count": len(scanResult.Vulnerabilities),
	})

	// Step 2: Call LLM service to generate detailed report
	go s.generateDetailedReport(task.ID)
}

// callPythonWorker simulates calling the Python worker
// In a real implementation, this would make an HTTP call to the Python worker service
func (s *Scanner) callPythonWorker(url string) (*PythonWorkerResult, error) {
	// Simulate calling the Python worker service
	// In a real implementation, this would be an HTTP request to the Python worker

	// For demonstration, we'll simulate the response
	time.Sleep(3 * time.Second) // Simulate scan time

	result := &PythonWorkerResult{
		URL: url,
		Vulnerabilities: []Vulnerability{
			{
				ID:          "vuln-001",
				Type:        "SQL Injection",
				Severity:    "High",
				Description: "Potential SQL injection vulnerability detected",
				URL:         url,
				Details:     "Input validation is not properly implemented for user inputs",
			},
			{
				ID:          "vuln-002",
				Type:        "XSS",
				Severity:    "Medium",
				Description: "Cross-site scripting vulnerability detected",
				URL:         url,
				Details:     "Unsanitized user input in output context",
			},
			{
				ID:          "vuln-003",
				Type:        "Information Disclosure",
				Severity:    "Low",
				Description: "Sensitive information disclosed in error messages",
				URL:         url,
				Details:     "Application reveals internal information in error responses",
			},
		},
		Summary:      "Found 3 vulnerabilities: 1 High, 1 Medium, 1 Low severity",
		Timestamp:    time.Now().Format(time.RFC3339),
		ScanDuration: 3.0,
	}

	return result, nil
}

// PythonWorkerResult represents the result from the Python worker
type PythonWorkerResult struct {
	URL            string         `json:"url"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary        string         `json:"summary"`
	Timestamp      string         `json:"timestamp"`
	ScanDuration   float64        `json:"scan_duration"`
}

// generateDetailedReport generates a detailed report using the LLM service
func (s *Scanner) generateDetailedReport(taskID string) {
	// Get the task
	task, err := s.taskStore.GetTask(taskID)
	if err != nil {
		LogEvent("error", fmt.Sprintf("Failed to get task %s for report generation: %v", taskID, err), nil)
		return
	}

	// Generate report using LLM service
	err = s.reportClient.IntegrationWithLLM(task)
	if err != nil {
		// Log error but don't fail the task since it already completed
		LogEvent("warning", fmt.Sprintf("Failed to generate LLM report for task %s: %v", taskID, err), nil)
		return
	}

	// Update task with the generated report
	if err := s.taskStore.UpdateTask(task); err != nil {
		LogEvent("error", fmt.Sprintf("Failed to update task %s with LLM report: %v", taskID, err), nil)
		return
	}

	// Log the event
	LogEvent("report_generated", "LLM report generated", map[string]interface{}{
		"task_id": task.ID,
		"url":     task.URL,
	})
}

// Update the handlers to use the complete scan flow
func (h *Handlers) SubmitCompleteScanTask(c *gin.Context) {
	var req SubmitScanTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Create a new scanner instance
	scanner := NewScanner(h.TaskStore)

	task, err := scanner.CompleteScanFlow(req.URL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to start scan",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, SubmitScanTaskResponse{
		TaskID: task.ID,
		Status: string(task.Status),
		URL:    task.URL,
	})
}

// Add an endpoint to trigger the complete scan flow
func (h *Handlers) RegisterCompleteScanRoutes(r *gin.Engine) {
	authMiddleware := NewAuthMiddleware()

	completeScanGroup := r.Group("/api/complete-scan")
	completeScanGroup.Use(authMiddleware.AuthRequired())
	{
		completeScanGroup.POST("", h.SubmitCompleteScanTask)
	}
}

// Example of how to initialize the complete system
func InitializeCompleteSystem() *gin.Engine {
	// Initialize task store
	taskStorePath := os.Getenv("TASK_STORE_PATH")
	if taskStorePath == "" {
		taskStorePath = "./data/tasks/tasks.json"
	}
	
	// Ensure data directory exists
	os.MkdirAll("./data/tasks", 0755)
	os.MkdirAll("./data/results", 0755)
	os.MkdirAll("./data/reports", 0755)
	os.MkdirAll("./logs", 0755)
	
	taskStore := NewFileTaskStore(taskStorePath)

	// Create handlers
	handlers := NewHandlers(taskStore)

	// Create Gin router
	r := gin.New()

	// Add custom logging middleware
	r.Use(LoggerToFile())

	// Add recovery middleware
	r.Use(gin.Recovery())

	// Health check endpoint (no auth required)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "dawn-scanner-complete-system",
			"components": map[string]string{
				"go_backend": "operational",
				"python_worker": "pending",
				"llm_service": "pending",
			},
		})
	})

	// Register complete scan routes
	handlers.RegisterCompleteScanRoutes(r)

	// Task management API routes (with auth)
	tasks := r.Group("/api/tasks")
	authMiddleware := NewAuthMiddleware()
	tasks.Use(authMiddleware.AuthRequired())
	{
		tasks.POST("", handlers.SubmitScanTask)
		tasks.GET("", handlers.ListScanTasks)
		tasks.GET("/:id", handlers.GetScanTask)
		tasks.DELETE("/:id", handlers.DeleteScanTask)
	}

	return r
}

// Main function demonstrating the complete system
func RunCompleteSystem() {
	// Set Gin mode based on environment
	if os.Getenv("GO_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize the complete system
	r := InitializeCompleteSystem()

	// Get port from environment, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Dawn Scanner complete system on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

// This would be called from main.go instead of the original main function
// Uncomment the next line if using this as the main entry point
// func main() { RunCompleteSystem() }