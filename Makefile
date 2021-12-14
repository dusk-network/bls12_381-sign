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

all: schemas lib build test

schemas:
ifeq (,$(wildcard ./tmp/protoc/bin/protoc))
	make protoc
endif
	./tmp/protoc/bin/protoc --proto_path=./schema ./schema/bls12381sig.proto --go-grpc_opt=paths=source_relative \
		--go-grpc_out=require_unimplemented_servers=false:./go/grpc/bls --go_opt=paths=source_relative \
		--go_out=./go/grpc/bls/

lib:
	cargo build --workspace --manifest-path rust/Cargo.toml --exclude dusk-bls12_381-sign-ipc --release
	cp rust/target/release/libdusk_bls12_381_sign.a ./go/cgo/bls/libdusk_bls12_381_sign_$(platform).a

grpc:
	cargo build --workspace --manifest-path rust/Cargo.toml --release
	cp rust/target/release/bls12381svc ./go/grpc/bls/bls12381svc_$(platform)

build: schemas lib grpc
	(cd go/cgo/bls && go build)
	(cd go/grpc/bls && go build)

test: build
	(cd go/cgo/bls && go test)
	(cd go/grpc/bls && go test)

bench: build
	(cd go/cgo/bls && go test -v -bench=.)
	(cd go/grpc/bls && go test -v -bench=.)

clean:
	rm -fv /tmp/bls12381svc*
	rm -rf ./tmp
	cargo clean --manifest-path rust/Cargo.toml --release
	(cd go/cgo/bls && go clean)
	(cd go/grpc/bls && go clean)

protoc:
	curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/$(protoc)
	mkdir -p ./tmp/protoc
	unzip -o $(protoc) -d ./tmp/protoc bin/protoc
	unzip -o $(protoc) -d ./tmp/protoc 'include/*'
	rm -f $(protoc)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1

memprofile:
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem -cpuprofile=cpu.out -memprofile=mem.out -trace=trace.out ./... | tee bench.txt
	go tool pprof -http :8081 mem.out

benchmem: build test
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem ./...
	cargo bench;
	#cd bls/bls12_381-sign;
