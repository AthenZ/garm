GO_VERSION:=$(shell go version)

.PHONY: all clean bench bench-all profile lint test contributors update install

all: clean install lint test bench

clean:
	go clean ./...
	go clean -modcache
	rm -rf ./*.log
	rm -rf ./*.svg
	rm -rf ./go.mod
	rm -rf ./go.sum
	rm -rf bench
	rm -rf pprof
	rm -rf vendor

bench: clean init
	go test -count=5 -run=NONE -bench . -benchmem

profile: clean
	mkdir pprof
	mkdir bench
	go test -count=10 -run=NONE -bench . -benchmem -o pprof/test.bin -cpuprofile pprof/cpu.out -memprofile pprof/mem.out
	go tool pprof --svg pprof/test.bin pprof/mem.out > bench/mem.svg
	go tool pprof --svg pprof/test.bin pprof/cpu.out > bench/cpu.svg

init:
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	sleep 3

deps: clean
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	rm -rf vendor

lint:
	gometalinter --enable-all . | rg -v comment

test: clean init
	GO111MODULE=on go test --race -v ./...

contributors:
	git log --format='%aN <%aE>' | sort -fu > CONTRIBUTORS

docker-push:
	sudo docker build --pull=true --file=Dockerfile -t docker.io/athenz/garm:latest .
	sudo docker push docker.io/athenz/garm:latest

coverage:
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm -f coverage.out

check-license-header:
	# go install github.com/apache/skywalking-eyes/cmd/license-eye@latest
	license-eye -c .licenserc.yaml header check
	# license-eye -c .licenserc.yaml header fix
