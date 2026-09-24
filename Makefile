.PHONY: test fmt vet data-0 data-10 data-30 data-all

# Runs every test in the module with the race detector enabled.
test:
	go test -race ./...

# Formats all Go source files in place.
fmt:
	go fmt ./...

# Runs Go's static analysis checks.
vet:
	go vet ./...

# Generates the three test scenarios (0%, 10%, 30% malicious traffic)
# required by the challenge. Output goes to data/ (gitignored) and is
# fully reproducible: the same --seed always produces the same files.
data-0:
	go run ./cmd/datagen --seed 42 --ratio 0

data-10:
	go run ./cmd/datagen --seed 42 --ratio 10

data-30:
	go run ./cmd/datagen --seed 42 --ratio 30

data-all: data-0 data-10 data-30
