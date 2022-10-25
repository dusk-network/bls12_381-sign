ifeq ($(OS),Windows_NT)
    # MACHINE = WIN32
    # ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
    #     MACHINE += AMD64
    # endif
    # ifeq ($(PROCESSOR_ARCHITECTURE),x86)
    #     MACHINE += IA32
    # endif
else
    # UNAME_S := $(shell uname -s)
    # ifeq ($(UNAME_S),Linux)
    #     MACHINE = LINUX
    # endif
    # ifeq ($(UNAME_S),Darwin)
    #     MACHINE = OSX
    # endif
    UNAME_P := $(shell uname -p)
    # ifeq ($(UNAME_P),x86_64)
    #     MACHINE += AMD64
    # endif
    # ifneq ($(filter %86,$(UNAME_P)),)
    #     arch += IA32
    # endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        arch += _arm
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        arg += CGO_ENABLED=1 GOARCH=arm64
    endif
endif


OS := $(shell sh -c 'uname -s 2>/dev/null || echo linux' | tr "[:upper:]" "[:lower:]")
PROTOC := $(shell which protoc)
platform = ubuntu-latest

# Protobuf compiler (aka Protoc)
ifeq ($(OS), linux)
protoc=protoc-3.14.0-linux-x86_64.zip
endif
ifeq ($(OS), darwin)
protoc = protoc-3.14.0-osx-x86_64.zip
platform = macos-latest
endif

all: schema lib build test

schema:
ifeq (,$(wildcard ./tmp/protoc/bin/protoc))
	make protoc
endif
	./tmp/protoc/bin/protoc --proto_path=./schema ./schema/bls12381sig.proto \
		--go_opt=paths=source_relative \
		--go_out=plugins=grpc:./go/grpc/bls/; \

lib:
	cargo build --workspace --manifest-path rust/Cargo.toml --exclude dusk-bls12_381-sign-ipc --release
	cp rust/target/release/libdusk_bls12_381_sign_ffi.a ./go/cgo/bls/libdusk_bls12_381_sign_ffi_$(platform)${arch}.a

grpc:
	cargo build --workspace --manifest-path rust/Cargo.toml --release
	cp rust/target/release/bls12381svc ./go/grpc/bls/bls12381svc_$(platform)

build: schema lib grpc
	(cd go/cgo/bls && $(arg) go build)
	(cd go/grpc/bls && $(arg) go build)

test: build
	(cd go/cgo/bls && $(arg) go test)
	(cd go/grpc/bls && $(arg) go test)

bench: build
	(cd go/cgo/bls && $(arg) go test -v -bench=.)
	(cd go/grpc/bls && $(arg) go test -v -bench=.)

clean:
	rm -fv /tmp/bls12381svc*
	rm -rf ./tmp

protoc:
	curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/$(protoc)
	mkdir -p ./tmp/protoc
	unzip -o $(protoc) -d ./tmp/protoc bin/protoc
	unzip -o $(protoc) -d ./tmp/protoc 'include/*'
	rm -f $(protoc)
	go install google.golang.org/grpc@v1.42.0
	go install github.com/golang/protobuf/protoc-gen-go@latest

memprofile:
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem -cpuprofile=cpu.out -memprofile=mem.out -trace=trace.out ./... | tee bench.txt
	go tool pprof -http :8081 mem.out

benchmem: build test
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem ./...
	cargo bench;
	#cd bls/bls12_381-sign;
