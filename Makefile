.PHONY: test fmt vet data-0 data-10 data-30 data-all eval baseline tune-baseline holdout run perf-bench perf-load perf-load-otel perf

# Corre todos los tests del módulo con el detector de carreras (race) habilitado.
test:
	go test -race ./...

# Formatea todos los archivos fuente Go in place.
fmt:
	go fmt ./...

# Corre los checks de análisis estático de Go.
vet:
	go vet ./...

# Genera los tres escenarios de prueba (0%, 10%, 30% de tráfico
# malicioso). La salida va a data/ (gitignored) y es completamente
# reproducible: el mismo --seed siempre produce los mismos archivos.
data-0:
	go run ./cmd/datagen --seed 42 --ratio 0

data-10:
	go run ./cmd/datagen --seed 42 --ratio 10

data-30:
	go run ./cmd/datagen --seed 42 --ratio 30

data-all: data-0 data-10 data-30

# Corre cmd/eval contra una carpeta de escenario que ya tiene un
# decisions.jsonl junto a su events.jsonl/labels.jsonl (producido por
# el motor real o por el baseline). Override SCENARIO/OUT si hace falta:
#   make eval SCENARIO=data/scenario-10 OUT=reports/scenario-10.md
SCENARIO ?= data/scenario-0
OUT ?= reports/$(notdir $(SCENARIO)).md
eval:
	mkdir -p $(dir $(OUT))
	go run ./cmd/eval --scenario $(SCENARIO) --out $(OUT)

# Corre el baseline de rate limiting (internal/baseline) contra el
# events.jsonl de una carpeta de escenario y escribe decisions.jsonl
# junto a él. Override SCENARIO/MODE/MAX_REQUESTS/WINDOW/BASELINE_OUT
# si hace falta:
#   make baseline SCENARIO=data/scenario-10 MODE=auth MAX_REQUESTS=20 WINDOW=60s
# By default BASELINE_OUT is left empty so cmd/baseline picks its own
# collision-safe name; pass BASELINE_OUT=$(SCENARIO)/decisions.jsonl
# explicitly to produce the file cmd/eval expects.
MODE ?= all
MAX_REQUESTS ?= 2
WINDOW ?= 5m
BASELINE_OUT ?=
baseline:
	go run ./cmd/baseline --scenario $(SCENARIO) --mode $(MODE) --max-requests $(MAX_REQUESTS) --window $(WINDOW) --out "$(BASELINE_OUT)"

# Corre el motor conductual REAL (internal/engine.BehavioralDecider,
# con los mismos defaults que cmd/engine — ver internal/engine/defaults.go)
# sobre los escenarios de tuning (seeds 101/102/103, ratios 0/10/30%
# por defecto) y escribe el reporte baseline en reports/tuning/. Los
# escenarios se generan en data/tuning/ (gitignored). Override
# TUNE_SEEDS/TUNE_RATIOS/TUNE_OUT si hace falta.
TUNE_SEEDS ?= 101,102,103
TUNE_RATIOS ?= 0,10,30
TUNE_OUT ?= reports/tuning/baseline
tune-baseline:
	go run ./cmd/tune --seeds $(TUNE_SEEDS) --ratios $(TUNE_RATIOS) --data-dir data/tuning --out $(TUNE_OUT)

# Evaluación final: baseline original vs. configuración final congelada,
# sobre seeds de holdout (201/202/203) y de tuning. Seeds y configuración
# fijas en cmd/holdout — escribe reports/holdout/baseline-vs-final.md.
holdout:
	go run ./cmd/holdout

# Levanta el servicio HTTP del Behavioral WAF (cmd/engine). Flags extra:
#   go run ./cmd/engine --help
run:
	go run ./cmd/engine

# Performance / load testing. Detector layer, Policy y ScoreFloor son
# la configuración final congelada — estos targets solo MIDEN, nunca
# los modifican.
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
# orden — el comando único y reproducible para medir performance.
perf: perf-bench perf-load
