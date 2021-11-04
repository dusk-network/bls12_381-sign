all: installprotoc goprotos servicebinaries build test

goprotos:
	if [ $(shell uname -o) = "GNU/Linux" ]; \
	then \
		protoc --proto_path=./proto ./proto/bls12381sig.proto \
			--go_opt=paths=source_relative \
			--go_out=plugins=grpc:./bls/; \
	else \
		echo "not implemented yet for mac or windows"; exit; \
	fi; \

servicebinaries:
		cargo build --release \
		&& cp target/release/bls12381svc ../bls12381svc_ubuntu-latest \
		&& cp target/release/libdusk_bls12_381_sign.a ../libdusk_bls12_381_sign_ubuntu-latest.a;

build: goprotos servicebinaries
	go build ./...

test: build
	go test -v ./...

bench: build
	go test -v -bench=. ./...

clean:
	rm -fv /tmp/bls12381svc*

installprotoc: installprotocubuntu

installprotocubuntu: # like it says on the tin
	sudo apt install -y protobuf-compiler
	go install google.golang.org/grpc
	go install github.com/golang/protobuf/protoc-gen-go

memprofile:
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem -cpuprofile=cpu.out -memprofile=mem.out -trace=trace.out ./... | tee bench.txt
	go tool pprof -http :8081 mem.out

benchmem: build test
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem ./...
	cargo bench;
	#cd bls/bls12_381-sign;
