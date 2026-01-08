package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// TaskStatus 定义任务状态
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
)

// Task 扫描任务结构
type Task struct {
	ID          string     `json:"id"`
	URL         string     `json:"url"`
	Status      TaskStatus `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Result      *Result    `json:"result,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Result 扫描结果结构
type Result struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         string          `json:"summary"`
	Report          string          `json:"report"`
}

// Vulnerability 漏洞信息结构
type Vulnerability struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Details     string `json:"details"`
}

// TaskStore 任务存储接口
type TaskStore interface {
	CreateTask(url string) (*Task, error)
	GetTask(id string) (*Task, error)
	UpdateTask(task *Task) error
	ListTasks() ([]*Task, error)
	DeleteTask(id string) error
}

// InMemoryTaskStore 内存任务存储实现
type InMemoryTaskStore struct {
	tasks map[string]*Task
	mutex sync.RWMutex
}

// NewInMemoryTaskStore 创建新的内存任务存储
func NewInMemoryTaskStore() *InMemoryTaskStore {
	return &InMemoryTaskStore{
		tasks: make(map[string]*Task),
	}
}

// CreateTask 创建新任务
func (s *InMemoryTaskStore) CreateTask(url string) (*Task, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	taskID := generateTaskID()
	task := &Task{
		ID:        taskID,
		URL:       url,
		Status:    TaskPending,
		CreatedAt: time.Now(),
	}

	s.tasks[taskID] = task
	return task, nil
}

// GetTask 获取任务
func (s *InMemoryTaskStore) GetTask(id string) (*Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	task, exists := s.tasks[id]
	if !exists {
		return nil, fmt.Errorf("task with id %s not found", id)
	}

	return task, nil
}

// UpdateTask 更新任务
func (s *InMemoryTaskStore) UpdateTask(task *Task) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.tasks[task.ID]; !exists {
		return fmt.Errorf("task with id %s not found", task.ID)
	}

	s.tasks[task.ID] = task
	return nil
}

// ListTasks 列出所有任务
func (s *InMemoryTaskStore) ListTasks() ([]*Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// DeleteTask 删除任务
func (s *InMemoryTaskStore) DeleteTask(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.tasks[id]; !exists {
		return fmt.Errorf("task with id %s not found", id)
	}

	delete(s.tasks, id)
	return nil
}

// FileTaskStore 基于文件的任务存储实现
type FileTaskStore struct {
	filePath string
	mutex    sync.RWMutex
}

// NewFileTaskStore 创建新的文件任务存储
func NewFileTaskStore(filePath string) *FileTaskStore {
	return &FileTaskStore{
		filePath: filePath,
	}
}

// CreateTask 创建新任务
func (s *FileTaskStore) CreateTask(url string) (*Task, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tasks, err := s.loadTasks()
	if err != nil {
		return nil, err
	}

	taskID := generateTaskID()
	task := &Task{
		ID:        taskID,
		URL:       url,
		Status:    TaskPending,
		CreatedAt: time.Now(),
	}

	tasks[taskID] = task

	err = s.saveTasks(tasks)
	if err != nil {
		return nil, err
	}

	return task, nil
}

// GetTask 获取任务
func (s *FileTaskStore) GetTask(id string) (*Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tasks, err := s.loadTasks()
	if err != nil {
		return nil, err
	}

	task, exists := tasks[id]
	if !exists {
		return nil, fmt.Errorf("task with id %s not found", id)
	}

	return task, nil
}

// UpdateTask 更新任务
func (s *FileTaskStore) UpdateTask(task *Task) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tasks, err := s.loadTasks()
	if err != nil {
		return err
	}

	if _, exists := tasks[task.ID]; !exists {
		return fmt.Errorf("task with id %s not found", task.ID)
	}

	tasks[task.ID] = task

	return s.saveTasks(tasks)
}

// ListTasks 列出所有任务
func (s *FileTaskStore) ListTasks() ([]*Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	tasks, err := s.loadTasks()
	if err != nil {
		return nil, err
	}

	taskList := make([]*Task, 0, len(tasks))
	for _, task := range tasks {
		taskList = append(taskList, task)
	}

	return taskList, nil
}

// DeleteTask 删除任务
func (s *FileTaskStore) DeleteTask(id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tasks, err := s.loadTasks()
	if err != nil {
		return err
	}

	if _, exists := tasks[id]; !exists {
		return fmt.Errorf("task with id %s not found", id)
	}

	delete(tasks, id)

	return s.saveTasks(tasks)
}

// loadTasks 从文件加载任务
func (s *FileTaskStore) loadTasks() (map[string]*Task, error) {
	tasks := make(map[string]*Task)

	// 检查文件是否存在
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		// 文件不存在，返回空映射
		return tasks, nil
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read tasks file: %w", err)
	}

	if len(data) == 0 {
		// 文件为空，返回空映射
		return tasks, nil
	}

	err = json.Unmarshal(data, &tasks)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tasks: %w", err)
	}

	return tasks, nil
}

// saveTasks 保存任务到文件
func (s *FileTaskStore) saveTasks(tasks map[string]*Task) error {
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tasks: %w", err)
	}

	err = os.WriteFile(s.filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write tasks file: %w", err)
	}

	return nil
}

// generateTaskID 生成任务ID
func generateTaskID() string {
	return fmt.Sprintf("task_%d", time.Now().UnixNano())
}