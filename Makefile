.PHONY: test
test:
	go test ./...
	cd ./examples && $(MAKE) test

.PHONY: lint
lint:
	golangci-lint run