BINARY  = asm-engine
TARGET ?= example.com

.PHONY: build test run lint clean

build:
	go build -o $(BINARY) ./cmd/asm

test:
	go test -race -v ./...

run: build
	./$(BINARY) --target $(TARGET)

lint:
	go vet ./...

clean:
	rm -f $(BINARY)
