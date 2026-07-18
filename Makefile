GO ?= go
BINARY ?= xray
PACKAGE ?= ./main

BUILD_FLAGS := -trimpath -buildvcs=false
LINK_FLAGS := -s -w -buildid=

.PHONY: all build test clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -o $(BINARY) $(BUILD_FLAGS) -ldflags="$(LINK_FLAGS)" -v $(PACKAGE)

test:
	$(GO) test -timeout 1h -v ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
