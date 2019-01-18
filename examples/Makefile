writer: clean fmt vet lint build

get-dependencies:
	@echo "Downloading dependencies"
	go get -u github.com/vijayviji/simplehttpparser

fmt:
	@echo "Running formatting"
	go fmt

vet:
	@echo "Running go vet"
	go vet

lint:
	@echo "Running lint"
	golint --set_exit_status ./...

build:
	go build

clean:
	rm -f examples