VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := surplies
DIST := dist

.PHONY: build clean all test lint fmt release package-macos checksums update-formula

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

fmt:
	go fix ./...
	gofmt -s -w .

lint:
	@out=$$(go fix -diff ./... 2>&1); [ -z "$$out" ] || { echo "go fix issues:"; echo "$$out"; exit 1; }
	@out=$$(gofmt -s -l .); [ -z "$$out" ] || { echo "gofmt -s issues in: $$out"; exit 1; }
	@test -f LICENSE || { echo "LICENSE file missing"; exit 1; }
	go vet ./...

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
	awk '/darwin-arm64/{found_arm64=1} found_arm64 && /sha256/ && !done_arm64{sub(/sha256 "[^"]*"/, "sha256 \"$(ARM64_SHA)\""); done_arm64=1} /darwin-amd64/{found_amd64=1} found_amd64 && /sha256/ && !done_amd64{sub(/sha256 "[^"]*"/, "sha256 \"$(AMD64_SHA)\""); done_amd64=1} {print}' Formula/$(BIN).rb > Formula/$(BIN).rb.tmp && mv Formula/$(BIN).rb.tmp Formula/$(BIN).rb

# Full release flow: make release VERSION=v1.2.3
# Then: git tag v1.2.3 && git push origin v1.2.3
# Then upload dist/ tarballs to the GitHub release
release: lint update-formula
	@echo "Formula updated for $(VERSION). Next steps:"
	@echo "  1. git add Formula/$(BIN).rb && git commit -m 'Release $(VERSION)'"
	@echo "  2. git tag $(VERSION) && git push origin main $(VERSION)"
	@echo "  3. Upload $(DIST)/$(BIN)-$(VERSION)-darwin-*.tar.gz to the GitHub release"

clean:
	rm -rf $(BIN) $(DIST)
