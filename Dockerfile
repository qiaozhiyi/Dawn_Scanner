# Dockerfile
FROM ubuntu:22.04

LABEL authors="qiaozhiyi"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    GO_VERSION=1.25.5 \
    NODE_VERSION=20

WORKDIR /app

# 安装系统依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl build-essential git wget vim unzip \
        python3 python3-pip python3-dev libpq-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 安装官方 Go（1.25.5 是当前最新稳定版）
RUN wget -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# 安装 Node.js 20 LTS（最新稳定版本）
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

# 验证安装
RUN node -v && npm -v

# 安装 Python 依赖
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt

# 复制代码（实际运行时会被 volume 覆盖，此处用于离线构建依赖）
COPY . /app

EXPOSE 5000

CMD ["bash"]