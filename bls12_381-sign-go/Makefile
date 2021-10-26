build:
	if [ -d bls/bls12_381-sign ]; \
	then \
		cd bls/bls12_381-sign \
		&& git pull; \
	else \
  		cd bls \
  		&& git clone https://github.com/dusk-network/bls12_381-sign \
  		&& cd bls12_381-sign \
		&& git checkout microservice; \
	fi; \
	if [ $(shell uname -o) = "GNU/Linux" ]; \
	then \
		protoc --proto_path=proto proto/bls12381sig.proto \
			--go_opt=paths=source_relative \
			--go_out=plugins=grpc:../proto \
		&& cargo build --release \
		&& cp target/release/bls12381svc ../../bls12381svc_ubuntu-latest \
		&& cp target/release/libdusk_bls12_381_sign.a ../..libdusk_bls12_381_sign_ubuntu-latest.a; \
	else \
		echo "not implemented yet for mac or windows"; \
	fi; \
	go build ../../...

test: build
	rm -fv /tmp/bls12381svc*
	go test -v ./...

bench: build
	rm -fv /tmp/bls12381svc*
	go test -v -bench=. ./...
	rm -fv /tmp/bls12381svc*

clean:
	rm -fv /tmp/bls12381svc*
	rm -rfv bls/bls12_381-sign

installprotocubuntu: # like it says on the tin
	sudo apt install -y protobuf-compiler
	go install google.golang.org/grpc
	go install github.com/golang/protobuf/protoc-gen-go

memprofile:
	rm /tmp/bls12381svc*; \
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem -cpuprofile=cpu.out -memprofile=mem.out -trace=trace.out ./... | tee bench.txt
	go tool pprof -http :8081 mem.out
	rm -fv /tmp/bls12381svc*

benchmem: build test
	rm /tmp/bls12381svc*; \
	go test -run=. -bench=. -benchtime=5s -count 1 -benchmem ./...
	cd bls/bls12_381-sign; \
	cargo bench; \
	rm /tmp/bls12381svc*
