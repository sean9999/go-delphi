MODULE=github.com/sean9999/go-delphi
CONTAINER_IMAGE=docker.io/codemonk9999/delphi
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

docker:
	docker build -t ${CONTAINER_IMAGE}:${REF} -t ${CONTAINER_IMAGE}:${BRANCH} -t ${CONTAINER_IMAGE}:latest .

push:
	docker push ${CONTAINER_IMAGE}:${REF}
	ifeq ($(BRANCH), "main") 
		docker push ${CONTAINER_IMAGE}:latest
	endif

test:
	go test -race ./...

.PHONY: test

