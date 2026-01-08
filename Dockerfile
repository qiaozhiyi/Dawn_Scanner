# Dockerfile for Dawn Scanner - Multi-component application
FROM ubuntu:22.04

LABEL authors="qiaozhiyi"
LABEL description="Dawn Scanner - Vulnerability Scanner with LLM Integration"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    GO_VERSION=1.21 \
    NODE_VERSION=20

WORKDIR /app

# 安装系统依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl build-essential git wget vim unzip \
        python3 python3-pip python3-dev libpq-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 安装官方 Go
RUN wget -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

ENV PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

# 验证 Go 安装
RUN go version

# 安装 Python 依赖
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt

# 创建应用目录结构
RUN mkdir -p /app/data/tasks /app/data/results /app/data/reports /app/logs

# 复制 Go 后端源码
COPY go-backend/ /app/go-backend/

# 构建 Go 后端
WORKDIR /app/go-backend
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o dawn-scanner .

# 返回到主目录
WORKDIR /app

# 复制其他组件源码
COPY python-worker/ /app/python-worker/
COPY llm-service/ /app/llm-service/

EXPOSE 8080

CMD ["bash"]