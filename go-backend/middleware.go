package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 鉴权中间件
type AuthMiddleware struct {
	ValidTokens map[string]bool
}

// NewAuthMiddleware 创建新的鉴权中间件
func NewAuthMiddleware() *AuthMiddleware {
	// 从环境变量读取有效令牌，或者使用默认值
	authTokensStr := os.Getenv("AUTH_TOKENS")
	authTokens := make(map[string]bool)
	
	if authTokensStr != "" {
		// 支持多个令牌，用逗号分隔
		tokens := strings.Split(authTokensStr, ",")
		for _, token := range tokens {
			authTokens[strings.TrimSpace(token)] = true
		}
	} else {
		// 默认令牌，仅用于开发环境
		defaultToken := os.Getenv("DEFAULT_AUTH_TOKEN")
		if defaultToken == "" {
			defaultToken = "dawn_scanner_dev_token"
		}
		authTokens[defaultToken] = true
	}

	return &AuthMiddleware{
		ValidTokens: authTokens,
	}
}

// AuthRequired 鉴权中间件函数
func (am *AuthMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		
		if authHeader == "" {
			c.JSON(401, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// 检查是否以 "Bearer " 开头
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(401, gin.H{
				"error": "Authorization header must be in the format 'Bearer <token>'",
			})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		if !am.ValidTokens[token] {
			c.JSON(401, gin.H{
				"error": "Invalid authorization token",
			})
			c.Abort()
			return
		}

		// 将用户信息添加到上下文（如果需要的话）
		c.Set("user_id", "authenticated_user")
		c.Next()
	}
}

// LoggerToFile 自定义日志记录到文件
func LoggerToFile() gin.HandlerFunc {
	logFilePath := "./logs/"
	logFileName := "dawn_scanner.log"
	filePath := logFilePath + logFileName

	// 检查日志目录是否存在，不存在则创建
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		err := os.MkdirAll(logFilePath, 0755)
		if err != nil {
			log.Printf("Failed to create log directory: %v", err)
			// 如果无法创建目录，则记录到标准输出
			return gin.Logger()
		}
	}

	// 打开日志文件
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		// 如果无法打开文件，则记录到标准输出
		return gin.Logger()
	}

	logger := log.New(f, "", log.LstdFlags)

	return func(c *gin.Context) {
		startTime := time.Now()

		// 处理请求
		c.Next()

		endTime := time.Now()
		latencyTime := endTime.Sub(startTime)
		reqMethod := c.Request.Method
		reqUri := c.Request.RequestURI
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()

		// 记录日志
		logger.Printf("| %3d | %13v | %15s | %s | %s",
			statusCode,
			latencyTime,
			clientIP,
			reqMethod,
			reqUri,
		)

		// 同时输出到控制台（在开发环境中很有用）
		if os.Getenv("GO_ENV") != "production" {
			fmt.Printf("| %3d | %13v | %15s | %s | %s\n",
				statusCode,
				latencyTime,
				clientIP,
				reqMethod,
				reqUri,
			)
		}
	}
}

// LogEvent 记录特定事件
func LogEvent(eventType, message string, data map[string]interface{}) {
	logEntry := fmt.Sprintf("[%s] %s: %s, Data: %+v", 
		time.Now().Format("2006-01-02 15:04:05"), 
		eventType, 
		message, 
		data)
	
	// 输出到日志文件
	log.Println(logEntry)
	
	// 在开发环境中也输出到控制台
	if os.Getenv("GO_ENV") != "production" {
		fmt.Println(logEntry)
	}
}