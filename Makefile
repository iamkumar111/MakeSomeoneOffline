.PHONY: all build test clean run

all: test build

build-ui:
	@echo "Building frontend dashboard..."
	npm --prefix web run build

build: build-ui
	@echo "Building control-plane..."
	go build -o bin/control-plane ./cmd/control-plane
	@echo "Building sim-lab..."
	go build -o bin/sim-lab ./cmd/sim-lab
	@echo "Building netcut-cli..."
	go build -o bin/netcut-cli ./cmd/netcut-cli

build-win:
	@echo "Cross-compiling Windows binaries..."
	GOOS=windows GOARCH=amd64 go build -o bin/control-plane.exe ./cmd/control-plane
	GOOS=windows GOARCH=amd64 go build -o bin/win-tool.exe ./cmd/win-tool

test:
	@echo "Running tests..."
	go test -v ./pkg/... ./test/e2e/...

run: build
	@echo "Starting control plane (L2 ARP side-host mode + JSON DB)..."
	sudo ENABLE_L2_ARP=1 ./bin/control-plane -port 8080 -db ./netcut.json

# Gateway mode: kernel enforcement only, no ARP spoofing.
run-gateway: build
	@echo "Starting control plane (gateway mode)..."
	sudo ./bin/control-plane -port 8080 -db ./netcut.json

clean:
	rm -rf bin/
