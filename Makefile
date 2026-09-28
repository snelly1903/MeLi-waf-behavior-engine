.PHONY: test fmt vet data-0 data-10 data-30 data-all eval baseline tune-baseline

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

# Runs cmd/eval against a scenario folder that already has a
# decisions.jsonl next to its events.jsonl/labels.jsonl (produced by a
# real or toy engine — no real engine exists yet, see
# docs/decisiones.md, tarea 0.8). Override SCENARIO/OUT as needed:
#   make eval SCENARIO=data/scenario-10 OUT=reports/scenario-10.md
SCENARIO ?= data/scenario-0
OUT ?= reports/$(notdir $(SCENARIO)).md
eval:
	go run ./cmd/eval --scenario $(SCENARIO) --out $(OUT)

# Runs the rate-limit baseline (internal/baseline, tarea 0.9) against
# a scenario folder's events.jsonl and writes decisions.jsonl next to
# it. Override SCENARIO/MODE/MAX_REQUESTS/WINDOW/BASELINE_OUT as
# needed:
#   make baseline SCENARIO=data/scenario-10 MODE=auth MAX_REQUESTS=20 WINDOW=60s
# By default BASELINE_OUT is left empty so cmd/baseline picks its own
# collision-safe name; pass BASELINE_OUT=$(SCENARIO)/decisions.jsonl
# explicitly to produce the file cmd/eval expects.
MODE ?= all
MAX_REQUESTS ?= 100
WINDOW ?= 60s
BASELINE_OUT ?=
baseline:
	go run ./cmd/baseline --scenario $(SCENARIO) --mode $(MODE) --max-requests $(MAX_REQUESTS) --window $(WINDOW) --out "$(BASELINE_OUT)"

# Corre el motor conductual REAL (internal/engine.BehavioralDecider,
# con los mismos defaults que cmd/engine — ver internal/engine/defaults.go)
# sobre los escenarios de tuning (seeds 101/102/103, ratios 0/10/30%
# por defecto) y escribe el reporte baseline en reports/tuning/
# (tarea 1.9, Punto de Control 1). Los escenarios se generan en
# data/tuning/ (gitignored). Override TUNE_SEEDS/TUNE_RATIOS/TUNE_OUT
# si hace falta.
TUNE_SEEDS ?= 101,102,103
TUNE_RATIOS ?= 0,10,30
TUNE_OUT ?= reports/tuning/baseline
tune-baseline:
	go run ./cmd/tune --seeds $(TUNE_SEEDS) --ratios $(TUNE_RATIOS) --data-dir data/tuning --out $(TUNE_OUT)
