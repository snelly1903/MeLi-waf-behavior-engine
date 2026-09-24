.PHONY: test fmt vet

# Runs every test in the module with the race detector enabled.
test:
	go test -race ./...

# Formats all Go source files in place.
fmt:
	go fmt ./...

# Runs Go's static analysis checks.
vet:
	go vet ./...
