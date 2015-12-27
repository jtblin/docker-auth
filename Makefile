VERSION_VAR := main.VERSION
REPO_VERSION := $(shell git describe --always --dirty --tags)
GOBUILD_VERSION_ARGS := -ldflags "-X $(VERSION_VAR)=$(REPO_VERSION)"
GIT_HASH := $(shell git rev-parse --short HEAD)
BINARY_NAME := docker-auth
IMAGE_NAME := jtblin/$(BINARY_NAME)
MACHINE_NAME := buildstep
REGISTRY_DOMAIN := docker-registry.default.svc.cluster.local

ARCH := linux darwin windows freebsd

setup:
	go get -v
	go get -v -u github.com/githubnemo/CompileDaemon
	go get -v -u github.com/alecthomas/gometalinter
	go get -v -u github.com/jtblin/conf2kube
	go install github.com/jtblin/conf2kube
	gometalinter --install --update

docker-setup:
	docker-machine scp dev/certs/domain.crt $(MACHINE_NAME):~/
	docker-machine ssh $(MACHINE_NAME) 'sh -c "sudo mkdir -p /etc/docker/certs.d/$(REGISTRY_DOMAIN):30500/"'
	docker-machine ssh $(MACHINE_NAME) 'sh -c "sudo mv domain.crt /etc/docker/certs.d/$(REGISTRY_DOMAIN):30500/ca.crt"'
	docker-machine ssh $(MACHINE_NAME) 'sh -c "sudo sh -c \"echo 127.0.0.1 $(REGISTRY_DOMAIN) >> /etc/hosts\""'

fmt:
	gofmt -w=true $(shell find . -type f -name '*.go' -not -path "./vendor/*")
	goimports -w=true -d $(shell find . -type f -name '*.go' -not -path "./vendor/*")

build: *.go fmt
	go build -o build/bin/$(BINARY_NAME) $(GOBUILD_VERSION_ARGS) github.com/$(IMAGE_NAME)

check: build
	gometalinter --deadline=30s --cyclo-over=20 ./...

test: check
	go test

junit-test: build
	go get github.com/jstemmer/go-junit-report
	go test -v | go-junit-report > test-report.xml

watch:
	CompileDaemon -color=true -build "make test"

commit-hook:
	cp dev/commit-hook.sh .git/hooks/pre-commit

cross:
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/bin/$(BINARY_NAME)-linux .

docker: cross
	cd build && docker build -t $(IMAGE_NAME):$(GIT_HASH) .

release: docker
	docker push $(IMAGE_NAME):$(GIT_HASH)
	docker tag -f $(IMAGE_NAME):$(GIT_HASH) $(IMAGE_NAME):latest
	docker push $(IMAGE_NAME):latest

run: build
	./build/bin/docker-auth --audience=$(REGISTRY_DOMAIN) --issuer=$(REGISTRY_DOMAIN) --public-key-file=`pwd`/dev/certs/public.pem \
		--signing-key-file=`pwd`/dev/certs/private.pem --verbose #--authn-backend=ldap --authn-config-file=examples/ldap.private.ini

run-docker: docker
	docker-compose -f build/docker-compose.yml build
	REGISTRY_DOMAIN=$(REGISTRY_DOMAIN) docker-compose -f build/docker-compose.yml up --force-recreate

run-docker-local:
	docker run --rm -it -p 5001:5001 -v `pwd`/dev/certs:/etc/ssl/certs:ro -v `pwd`/examples/ldap.private.ini:/etc/docker-auth/ldap.ini:ro \
		-v $(HOME)/.pwd:/etc/docker-auth/.ldap_password:ro $(IMAGE_NAME):$(GIT_HASH) --audience=$(REGISTRY_DOMAIN) \
		--issuer=$(REGISTRY_DOMAIN) --public-key-file=/etc/ssl/certs/public.pem --signing-key-file=/etc/ssl/certs/private.pem --verbose \
		#--authn-backend=ldap --authn-config-file=/etc/docker-auth/ldap.ini

secrets:
	conf2kube -n docker-registry-certs -f dev/certs/server.pem | kubectl create -f -
	kubectl patch secret docker-registry-certs -p `conf2kube -n docker-registry-certs -f dev/certs/domain.crt`
	kubectl patch secret docker-registry-certs -p `conf2kube -n docker-registry-certs -f dev/certs/domain.key`
	kubectl patch secret docker-registry-certs -p `conf2kube -n docker-registry-certs -f dev/certs/private.pem`
	kubectl patch secret docker-registry-certs -p `conf2kube -n docker-registry-certs -f dev/certs/public.pem`

version:
	@echo $(REPO_VERSION)

clean:
	rm -f build/bin/*
	-docker rm $(shell docker ps -a -f 'status=exited' -q)
	-docker rmi $(shell docker images -f 'dangling=true' -q)
	-docker rmi -f $(shell docker images | grep build_ | tr -s ' ' | cut -d ' ' -f 3)

.PHONY: build
