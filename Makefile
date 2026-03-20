BINARY := graphrunner
BUILD_DIR := build
VERSION := 0.2.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build clean test lint

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/graphrunner/

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -v ./...

lint:
	go vet ./...

run:
	go run ./cmd/graphrunner/ $(ARGS)

cross:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/graphrunner/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/graphrunner/
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/graphrunner/
