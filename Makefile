.DEFAULT: all

all: build test fmt lint

build:
	go build -v ./...

test:
	go test -v ./...

imports goimports:
	goimports -local github.com/jahkeup/testca-go -w ./.

fmt: imports

lint:
	golangci-lint run ./...
