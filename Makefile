BUILD_DIR ?= ./artifacts


.PHONY: build
build:
	$(shell mkdir -p $(BUILD_DIR))
	$(MAKE) build-linux_amd64
	$(MAKE) build-darwin_amd64
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
