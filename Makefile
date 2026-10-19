.DEFAULT_GOAL := help

.PHONY: help all build clean bench bench-all profile init deps lint lint-fix test contributors update install docker-push coverage check-license-header

help: ## List available targets and required tools
	@printf 'Usage: make [target]\n\nTargets:\n'
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9_-]+:.*## / { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '\nRequired tools:\n'
	@printf '  %-22s %s\n' \
		'Go' 'Version declared in go.mod' \
		'golangci-lint' 'v2.15.0 (lint, lint-fix)' \
		'license-eye' 'check-license-header' \
		'Docker' 'docker-push' \
		'Graphviz (dot)' 'profile SVG output' \
		'Git' 'contributors'

all: build ## Build Garm (alias for build)

build: ## Build the Garm binary
	go build

clean: ## Delete go.mod/go.sum, the module cache, and generated files
	go clean ./...
	go clean -modcache
	rm -rf ./*.log
	rm -rf ./*.svg
	rm -rf ./go.mod
	rm -rf ./go.sum
	rm -rf bench
	rm -rf pprof
	rm -rf vendor

bench: clean init ## Run benchmarks five times after clean and init
	go test -count=5 -run=NONE -bench . -benchmem

profile: clean ## Generate CPU and memory profiles after clean
	mkdir pprof
	mkdir bench
	go test -count=10 -run=NONE -bench . -benchmem -o pprof/test.bin -cpuprofile pprof/cpu.out -memprofile pprof/mem.out
	go tool pprof --svg pprof/test.bin pprof/mem.out > bench/mem.svg
	go tool pprof --svg pprof/test.bin pprof/cpu.out > bench/cpu.svg

init: ## Initialize go.mod and vendor dependencies
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	sleep 3

deps: clean ## Recreate module files after clean and remove vendor
	GO111MODULE=on go mod init
	GO111MODULE=on go mod vendor
	rm -rf vendor

lint: ## Run golangci-lint using .golangci.yml
	golangci-lint run -c ./.golangci.yml

lint-fix: ## Apply automatic fixes supported by golangci-lint
	golangci-lint run -c ./.golangci.yml --fix

test: ## Run all Go tests with the race detector
	go test -race -v ./...

contributors: ## Regenerate CONTRIBUTORS from Git history
	git log --format='%aN <%aE>' | sort -fu > CONTRIBUTORS

docker-push: ## Build and push docker.io/athenz/garm:latest
	sudo docker build --pull=true --file=Dockerfile -t docker.io/athenz/garm:latest .
	sudo docker push docker.io/athenz/garm:latest

coverage: ## Run race-enabled tests and generate coverage reports
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

check-license-header: ## Check source license headers with license-eye
	# go install github.com/apache/skywalking-eyes/cmd/license-eye@latest
	license-eye -c .licenserc.yaml header check
	# license-eye -c .licenserc.yaml header fix
