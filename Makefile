VERSION ?= dev
LDFLAGS := -s -w
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build install test vet lint fmt ci dist clean

build:
	go build -ldflags '$(LDFLAGS)' -o bin/diary .

install:
	go install -ldflags '$(LDFLAGS)' .

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: files above need formatting"; exit 1; }
	golangci-lint run

fmt:
	gofmt -w .

ci: vet lint test build

dist:
	@rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/diary-$$os-$$arch . || exit 1; \
	done
	cd dist && sha256sum diary-* > SHA256SUMS

clean:
	rm -rf bin dist
