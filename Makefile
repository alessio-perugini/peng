build:
	@CGO_ENABLED=1 go build -a -trimpath -ldflags "-s -w -X main.version=${APP_VERSION}" -o bin/app ./cmd/main.go
.PHONY: build

test:
	CGO_ENABLED=1 go test -v ./...
.PHONY: test

fmt:
	goimports -w -local github.com/alessio-perugini/peng .
.PHONY: format

lint:
	golangci-lint run ./...
.PHONY: lint

mod-upgrade:
	@go get -u ./... && go mod tidy
.PHONY: mod-upgrade
