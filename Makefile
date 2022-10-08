BUILD_DIR ?= ./artifacts


.PHONY: build
build:
	$(shell mkdir -p $(BUILD_DIR))
	$(MAKE) build-linux_amd64
	$(MAKE) build-darwin_amd64
	$(MAKE) build-windows_amd64
	$(MAKE) build-server-xdp-linux_amd64

.PHONY: build-server-xdp-linux_amd64
build-server-xdp-linux_amd64:
	GOOS=linux GOARCH=amd64 go build -tags xdp -o $(BUILD_DIR)/openspa_xdp_linux_amd64 ./cli/openspa

.PHONY: build-linux_amd64
build-linux_amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/openspa_linux_amd64 ./cli/openspa

.PHONY: build-darwin_amd64
build-darwin_amd64:
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/openspa_darwin_amd64 ./cli/openspa

.PHONY: build-windows_amd64
build-windows_amd64:
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/openspa_windows_amd64 ./cli/openspa

.PHONY: test
test:
	go test ./...
	cd ./examples && $(MAKE) test

.PHONY: bench
bench:
	go test -bench=. ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: clean
clean:
	$(RM) -drf "$(BUILD_DIR)"

.PHONY: coverage
coverage:
	$(shell mkdir -p $(BUILD_DIR))
	go test $(shell go list ./... | grep -v internal/xdp) -covermode=count -coverprofile=$(BUILD_DIR)/coverage_raw.out
	cat $(BUILD_DIR)/coverage_raw.out | grep -v "mock" | grep -v "stub" > $(BUILD_DIR)/coverage_filtered.out
	go tool cover -func=$(BUILD_DIR)/coverage_filtered.out
