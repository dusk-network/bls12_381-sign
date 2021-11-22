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

all: schema lib grpc build test

schema:
ifeq (,$(wildcard ./tmp/protoc/bin/protoc))
	make protoc
endif
	./tmp/protoc/bin/protoc --proto_path=./schema ./schema/bls12381sig.proto \
		--go_opt=paths=source_relative \
		--go_out=plugins=grpc:./go/bls/grpc/; \

lib:
	(cd rust/bls12_381-sign && cargo build --release)
	cp rust/bls12_381-sign/target/release/libdusk_bls12_381_sign.a ./go/bls/cgo/libdusk_bls12_381_sign_$(platform)

grpc:
	(cd rust/grpc-server && cargo build --release)
	cp rust/grpc-server/target/release/bls12381svc ./go/bls/cgo/bls12381svc_$(platform)

build: schema lib grpc
	(cd go/bls/cgo && go build)
	(cd go/bls/grpc && go build)

test: build
	(cd go/bls/cgo && go test)
	(cd go/bls/grpc && go test)

bench: build
	(cd go/bls/cgo && go test -v -bench=.)
	(cd go/bls/grpc && go test -v -bench=.)

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
