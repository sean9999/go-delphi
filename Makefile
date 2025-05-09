MODULE=github.com/sean9999/go-delphi
SEMVER := $$(git tag --sort=-version:refname | head -n 1)
BRANCH := $$(git branch --show-current)
REF := $$(git describe --dirty --tags --always)
GOPROXY=proxy.golang.org

info:
	@printf "MODULE:\t%s\nSEMVER:\t%s\nBRANCH:\t%s\nREF:\t%s\n" $(MODULE) $(SEMVER) $(BRANCH) $(REF)

tidy:
	go mod tidy

clean:
	go clean
	go clean -modcache
	rm -f ./bin/*

pkgsite:
	if [ -z "$$(command -v pkgsite)" ]; then go install golang.org/x/pkgsite/cmd/pkgsite@latest; fi

docs: pkgsite
	pkgsite -open .

publish:
	GOPROXY=https://${GOPROXY},direct go list -m ${MODULE}@${SEMVER}

bin/delphi:
	go build -o bin/delphi ./cmd/delphi

install:
	go install ./cmd/delphi

# if tests mutate the contents of ./testadata, let's mitigate the problem
test:
	git restore testdata
	go test ./...
	git restore testdata

.PHONY: test

