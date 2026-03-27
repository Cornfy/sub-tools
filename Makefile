# ==========================================
# 变量定义
# ==========================================
BINARY_NAME=sub-tool
BIN_DIR=bin
BUILD_DIR=builds

# 获取版本信息
GIT_TAG=$(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)
DEV_VERSION=$(GIT_TAG)-dev-$(GIT_COMMIT)

# 编译参数
# CGO_ENABLED=0 确保静态编译，-trimpath 移除本地路径
GO_BUILD_VARS=CGO_ENABLED=0
GO_BUILD_FLAGS=-trimpath

# -s -w 压缩体积，-X 注入版本号
LDFLAGS_COMMON=-s -w
LDFLAGS_DEV=$(LDFLAGS_COMMON) -X 'main.version=$(DEV_VERSION)'
LDFLAGS_RELEASE=$(LDFLAGS_COMMON) -X 'main.version=$(GIT_TAG)'

# ==========================================
# 指令目标
# ==========================================

.PHONY: all build run release clean help

all: build

## build: 构建本地开发版本
build:
	@echo "Building local developer version: $(DEV_VERSION)"
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD_VARS) go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_DEV)" -o $(BIN_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: ./$(BIN_DIR)/$(BINARY_NAME)"

## run: 构建并运行
run: build
	./$(BIN_DIR)/$(BINARY_NAME)

## release: 交叉编译全平台发布包 (含 Android)
release:
	@echo "Building release version: $(GIT_TAG)"
	@mkdir -p $(BUILD_DIR)
	
	@# Linux
	@echo " -> Linux AMD64..."
	@$(GO_BUILD_VARS) GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_RELEASE)" -o $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64
	
	@# Windows
	@echo " -> Windows AMD64..."
	@$(GO_BUILD_VARS) GOOS=windows GOARCH=amd64 go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_RELEASE)" -o $(BUILD_DIR)/$(BINARY_NAME)_windows_amd64.exe
	
	@# macOS
	@echo " -> macOS AMD64..."
	@$(GO_BUILD_VARS) GOOS=darwin GOARCH=amd64 go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_RELEASE)" -o $(BUILD_DIR)/$(BINARY_NAME)_macos_amd64
	@echo " -> macOS ARM64..."
	@$(GO_BUILD_VARS) GOOS=darwin GOARCH=arm64 go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_RELEASE)" -o $(BUILD_DIR)/$(BINARY_NAME)_macos_arm64

	@# Android
	@echo " -> Android ARM64..."
	@$(GO_BUILD_VARS) GOOS=android GOARCH=arm64 go build $(GO_BUILD_FLAGS) -ldflags="$(LDFLAGS_RELEASE)" -o $(BUILD_DIR)/$(BINARY_NAME)_android_arm64
	
	@echo "Release binaries are ready in ./$(BUILD_DIR)"

## clean: 清理构建目录
clean:
	@rm -rf $(BIN_DIR)
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned up all build artifacts."

## help: 显示帮助信息
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## .*' $(MAKEFILE_LIST) | sed -e 's/## //' | awk 'BEGIN {FS = ": "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
