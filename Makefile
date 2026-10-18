GO ?= go
BINARY ?= xray
PACKAGE ?= ./main
BUILD_TAGS ?=
TEST_PACKAGES ?= ./...

BUILD_FLAGS := -trimpath -buildvcs=false
LINK_FLAGS := -s -w -buildid=
TAG_FLAGS := $(if $(strip $(BUILD_TAGS)),-tags="$(BUILD_TAGS)")

.PHONY: all build test clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -o $(BINARY) $(BUILD_FLAGS) $(TAG_FLAGS) -ldflags="$(LINK_FLAGS)" -v $(PACKAGE)

test:
	$(GO) test $(TAG_FLAGS) -timeout 1h -v $(TEST_PACKAGES)

clean:
	rm -f $(BINARY) $(BINARY).exe
