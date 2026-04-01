VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := surplies
DIST := dist

.PHONY: build clean all test release package-macos checksums update-formula

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

test:
	go test ./...

all: clean
	mkdir -p $(DIST)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-darwin-arm64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-windows-arm64.exe .

package-macos: all
	cd $(DIST) && tar czf $(BIN)-$(VERSION)-darwin-arm64.tar.gz $(BIN)-darwin-arm64
	cd $(DIST) && tar czf $(BIN)-$(VERSION)-darwin-amd64.tar.gz $(BIN)-darwin-amd64

checksums: package-macos
	cd $(DIST) && shasum -a 256 $(BIN)-$(VERSION)-darwin-arm64.tar.gz $(BIN)-$(VERSION)-darwin-amd64.tar.gz | tee checksums.txt

update-formula: checksums
	$(eval ARM64_SHA := $(shell grep darwin-arm64 $(DIST)/checksums.txt | awk '{print $$1}'))
	$(eval AMD64_SHA := $(shell grep darwin-amd64 $(DIST)/checksums.txt | awk '{print $$1}'))
	sed -i '' 's|version ".*"|version "$(VERSION)"|g' Formula/$(BIN).rb
	sed -i '' 's|releases/download/v[^/]*/$(BIN)-v[^-]*-darwin-arm64|releases/download/$(VERSION)/$(BIN)-$(VERSION)-darwin-arm64|g' Formula/$(BIN).rb
	sed -i '' 's|releases/download/v[^/]*/$(BIN)-v[^-]*-darwin-amd64|releases/download/$(VERSION)/$(BIN)-$(VERSION)-darwin-amd64|g' Formula/$(BIN).rb
	@ARM64_LINE=$$(grep -n "darwin-arm64" Formula/$(BIN).rb | grep sha256 | cut -d: -f1); \
	AMD64_LINE=$$(grep -n "darwin-amd64" Formula/$(BIN).rb | grep sha256 | cut -d: -f1); \
	sed -i '' "$${ARM64_LINE}s/sha256 \"[^\"]*\"/sha256 \"$(ARM64_SHA)\"/" Formula/$(BIN).rb; \
	sed -i '' "$${AMD64_LINE}s/sha256 \"[^\"]*\"/sha256 \"$(AMD64_SHA)\"/" Formula/$(BIN).rb

# Full release flow: make release VERSION=v1.2.3
# Then: git tag v1.2.3 && git push origin v1.2.3
# Then upload dist/ tarballs to the GitHub release
release: update-formula
	@echo "Formula updated for $(VERSION). Next steps:"
	@echo "  1. git add Formula/$(BIN).rb && git commit -m 'Release $(VERSION)'"
	@echo "  2. git tag $(VERSION) && git push origin main $(VERSION)"
	@echo "  3. Upload $(DIST)/$(BIN)-$(VERSION)-darwin-*.tar.gz to the GitHub release"

clean:
	rm -rf $(BIN) $(DIST)
