VERSION_VAR := main.VERSION
REPO_VERSION := $(shell git describe --always --dirty --tags)
GOBUILD_VERSION_ARGS := -ldflags "-X $(VERSION_VAR)=$(REPO_VERSION)"
GIT_HASH := $(shell git rev-parse --short HEAD)
BINARY_NAME := docker-auth
IMAGE_NAME := jtblin/$(BINARY_NAME)

ARCH := linux darwin windows freebsd

setup:
	go get -v
	go get -v -u github.com/githubnemo/CompileDaemon
	go get -v -u github.com/alecthomas/gometalinter
	gometalinter --install --update

build: *.go
	gofmt -w=true .
	goimports -w=true .
	go build -o build/bin/$(BINARY_NAME) -x $(GOBUILD_VERSION_ARGS) github.com/$(IMAGE_NAME)

test: build
	go test

junit-test: build
	go get github.com/jstemmer/go-junit-report
	go test -v | go-junit-report > test-report.xml

check: build
	gometalinter ./...

watch:
	CompileDaemon -color=true -build "make test check"

commit-hook:
	cp dev/commit-hook.sh .git/hooks/pre-commit

cross:
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/bin/$(BINARY_NAME)-linux .

docker: cross
	cd build && docker build -t $(IMAGE_NAME):$(GIT_HASH) .

release:
	docker push $(IMAGE_NAME):$(GIT_HASH)
	docker tag -f $(IMAGE_NAME):$(GIT_HASH) $(IMAGE_NAME):latest
	docker push $(IMAGE_NAME):latest

run:
	./build/bin/docker-auth --audience=buildstep --issuer=buildstep --public-key-file=`pwd`/dev/certs/public.pem \
		--signing-key-file=`pwd`/dev/certs/private.pem --verbose --authn-backend=ldap --authn-config-file=examples/ldap.ini

run-docker:
	docker run --rm -it -p 5001:5001 -v `pwd`/dev/certs:/etc/ssl/certs:ro -v `pwd`/examples/ldap.ini:/etc/docker-auth/ldap.ini:ro \
		-v $(HOME)/.pwd:/etc/docker-auth/.ldap_password:ro $(IMAGE_NAME):$(GIT_HASH) --audience=buildstep \
		--issuer=buildstep --public-key-file=/etc/ssl/certs/public.pem --signing-key-file=/etc/ssl/certs/private.pem --verbose \
		--authn-backend=ldap --authn-config-file=/etc/docker-auth/ldap.ini

version:
	@echo $(REPO_VERSION)

clean:
	rm -f build/bin/*
	-docker rm $(docker ps -a -f 'status=exited' -q)
	-docker rmi $(docker images -f 'dangling=true' -q)

.PHONY: build
