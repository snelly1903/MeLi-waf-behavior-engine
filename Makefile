.PHONY: test fmt vet data-0 data-10 data-30 data-all eval baseline tune-baseline perf-bench perf-load perf-load-otel perf

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

# Performance / load testing (tarea 1.10). Detector layer, Policy y
# ScoreFloor son los congelados tras el holdout (tarea 1.9) — estos
# targets solo MIDEN, nunca los modifican.
PERF_OUT ?= reports/performance

# Microbenchmark de BehavioralDecider.Decide() (go test -bench,
# ns/op, B/op, allocs/op) — perfiles normal/mixed/attack-heavy. Salida
# cruda guardada en $(PERF_OUT)/microbench.txt.
perf-bench:
	mkdir -p $(PERF_OUT)
	go test -run '^$$' -bench=. -benchmem ./internal/engine/... | tee $(PERF_OUT)/microbench.txt

# Load test HTTP end-to-end (POST /v1/events) — matriz perfil x
# concurrencia, 3 repeticiones cada una con servidor fresco. Escribe
# $(PERF_OUT)/loadtest.csv, loadtest.json y summary.md. Sin
# --otel-endpoint: solo la matriz principal, con OTel deshabilitado.
perf-load:
	go run ./cmd/loadtest --out $(PERF_OUT)

# Igual que perf-load, pero además corre el comparativo chico OTel
# ON/OFF contra un Collector local — requiere
# "docker-compose up -d otel-collector" corriendo antes.
perf-load-otel:
	go run ./cmd/loadtest --out $(PERF_OUT) --otel-endpoint localhost:4317

# Corre el microbenchmark y la matriz de load test completa, en ese
# orden — el comando único, reproducible, para toda la tarea 1.10.
perf: perf-bench perf-load
