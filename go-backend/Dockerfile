# 使用官方Go镜像作为构建环境
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dawn-scanner .

# 使用轻量级镜像作为运行环境
FROM alpine:latest

# 安装ca-certificates，以便应用可以连接到HTTPS端点
RUN apk --no-cache add ca-certificates

# 创建非root用户
RUN adduser -D -s /bin/sh dawnuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/dawn-scanner .

# 更改文件所有权给非root用户
RUN chown dawnuser:dawnuser dawn-scanner

# 创建数据和日志目录
RUN mkdir -p /app/data/tasks /app/data/results /app/data/reports /app/logs && \
    chown -R dawnuser:dawnuser /app/data /app/logs

# 切换到非root用户
USER dawnuser

# 暴露端口
EXPOSE 8080

# 运行二进制文件
CMD ["./dawn-scanner"]