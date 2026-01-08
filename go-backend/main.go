package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// 设置Gin模式
	if os.Getenv("GO_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// 初始化完整的扫描系统
	r := InitializeCompleteSystem()

	// 从环境变量获取端口，默认为8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Dawn Scanner backend on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}