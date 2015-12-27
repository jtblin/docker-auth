# docker-auth

***WARNING: experimental***

Docker auth token service provides authentication and authorization pluggable backends
for [docker registry token auth](https://docs.docker.com/registry/spec/auth/token/).

## Authentication plugins

* Dummy
* LDAP

## Authorization plugins

* Dummy

## Usage

    docker run --rm -it -p 5001:5001 -v `pwd`/dev/certs:/etc/ssl/certs:ro -v `pwd`/examples/ldap.private.ini:/etc/docker-auth/ldap.ini:ro \
    		-v $(HOME)/.password:/etc/docker-auth/.ldap_password:ro $(IMAGE_NAME):$(GIT_HASH) --audience=$(REGISTRY_DOMAIN) \
    		--issuer=$(REGISTRY_DOMAIN) --public-key-file=/etc/ssl/certs/public.pem --signing-key-file=/etc/ssl/certs/private.pem --verbose \
    		--authn-backend=ldap --authn-config-file=/etc/docker-auth/ldap.ini

### Config

##### LDAP

```ini
[global]
host = ldap.example.com
port = 389
tls = false
base = dc=example,dc=com
attribute = sn
attribute = givenName
attribute = mail
attribute = uid

[bind]
dn = uid=readonlyuser,ou=People,dc=example,dc=com
passwordFile = /Users/username/.pwd

[filter]
user = (uid=%s)
groups = (memberUid=%s)
```

# Development    

Run locally:

    make run

## Docker environment setup (Mac)

Requirements: `docker-machine`. Create a VM called `buildstep` or change the `MACHINE_NAME` in Makefile.

You need to point to the DNS name of your local registry to your `docker-machine` VM on Mac OSX 
or `localhost` on linux, and add the ca certificate for the docker daemon 
or tell docker to use insecure registry for this domain in docker daemon options.

    make docker-setup

## Run

Run in docker with a registry

    make run-docker
    docker login docker-registry.default.svc.cluster.local:30500

## Kubernetes

You pretty much need to follow the same step as docker (see [Makefile](./Makefile)) 
but instead of pointing `/etc/hosts` to localhost, point in to your k8s cluster. 
For [kube-solo](https://github.com/TheNewNormal/kube-solo-osx), I use _192.168.64.2_.

    make secrets
    kubectl create -f build/docker-auth-k8s.yaml

# Contributions

PR welcome!

Hack away. Make sure you run the following before submitting a PR:

        make setup
        make test
        
