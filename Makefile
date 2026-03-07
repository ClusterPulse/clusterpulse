SHELL := /bin/bash

.PHONY: test lint build

test:
	set -o pipefail && go test -race -coverprofile=coverage.out ./... 2>&1 | tee test-output.txt

lint:
	golangci-lint run ./...

build:
	go build -o /dev/null ./cmd/api
	go build -o /dev/null ./cmd/collector
	go build -o /dev/null ./cmd/manager
