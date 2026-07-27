.PHONY: build test race docker-build

build:
	go build -o fakessh ./cmd/fakessh

test:
	go test ./...

race:
	go test -race ./...

docker-build:
	docker build -t fakessh:local .
