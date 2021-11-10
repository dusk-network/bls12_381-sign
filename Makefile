OS := $(shell sh -c 'uname -s 2>/dev/null || echo linux' | tr "[:upper:]" "[:lower:]")
PROTOC := $(shell which protoc)

# Protobuf compiler (aka Protoc)
ifeq ($(OS), linux)
protoc=protoc-3.14.0-linux-x86_64.zip
endif
ifeq ($(OS), darwin)
protoc = protoc-3.14.0-osx-x86_64.zip
endif

all: goprotos servicebinaries build test

goprotos:
ifeq (,$(wildcard ./usr/local/bin/protoc))
	make installprotoc
endif
	./usr/local/bin/protoc --proto_path=./proto ./proto/bls12381sig.proto \
		--go_opt=paths=source_relative \
		--go_out=plugins=grpc:./bls/; \

servicebinaries:
	cargo build --release \
	&& cp target/release/bls12381svc ./bls/bls12381svc_$(OS) \
	&& cp target/release/libdusk_bls12_381_sign.a ./bls/libdusk_bls12_381_sign_$(OS).a;

build: goprotos servicebinaries
	go build ./...

test: build
	go test -v ./...

bench: build
	go test -v -bench=. ./...

clean:
	rm -fv /tmp/bls12381svc*
	rm -rf ./usr

installprotoc:
	curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/$(protoc)
	mkdir -p ./usr/local
	unzip -o $(protoc) -d ./usr/local bin/protoc
	unzip -o $(protoc) -d ./usr/local 'include/*'
	rm -f $(protoc)
	go install google.golang.org/grpc
	go install github.com/golang/protobuf/protoc-gen-go

memprofile:
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem -cpuprofile=cpu.out -memprofile=mem.out -trace=trace.out ./... | tee bench.txt
	go tool pprof -http :8081 mem.out

benchmem: build test
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem ./...
	cargo bench;
	#cd bls/bls12_381-sign;
