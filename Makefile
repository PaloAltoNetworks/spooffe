# Spooffe Makefile
# SPIFFE SVID Extractor by Cgroup Spoofing

BINARY_NAME=spooffe
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build targets
.PHONY: all build build-linux build-linux-arm64 clean test deps tidy fmt vet help

all: clean build

## build: Build the binary for current OS/arch (static)
build:
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .

## build-debug: Build with debug symbols
build-debug:
	$(GOBUILD) -gcflags="all=-N -l" -o $(BINARY_NAME) .

## build-linux: Build for Linux AMD64 (static)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .

## build-linux-arm64: Build for Linux ARM64 (static)
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 .

## build-all: Build for all supported platforms
build-all: build-linux build-linux-arm64

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux-amd64
	rm -f $(BINARY_NAME)-linux-arm64
	rm -f $(BINARY_NAME).exe

## test: Run tests
test:
	$(GOTEST) -v ./...

## deps: Download dependencies
deps:
	$(GOMOD) download

## tidy: Tidy dependencies
tidy:
	$(GOMOD) tidy

## verify: Verify dependencies
verify:
	$(GOMOD) verify

## fmt: Format code
fmt:
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	$(GOCMD) vet ./...

## lint: Run all linters (fmt + vet)
lint: fmt vet

## version: Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"

## help: Show this help message
help:
	@echo "Spooffe - SPIFFE SVID Extractor"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
