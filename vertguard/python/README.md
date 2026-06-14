# vertguard-ml

Python gRPC inference service for VertGuard. The Go scanners use rule-based
regex prefilters; ambiguous SUSPICIOUS inputs are routed here for ML
refinement, and the confidence is folded into the final verdict.

## Backends

| Backend      | Status   | When to use                                    |
|--------------|----------|------------------------------------------------|
| `stub`       | default  | End-to-end wiring, CI, local dev               |
| `distilbert` | planned  | Production once weights are trained — see `docs/ml-training-guide.md` |

Select with `VERTGUARD_ML_BACKEND=stub|distilbert` at startup.

## Quickstart

```bash
pip install -e .[dev]      # add [ml] for the distilbert extras
make proto                 # regenerate gRPC stubs from ../proto/ml/v1
make test
make run                   # serves on :50051 (override via VERTGUARD_ML_PORT)
```

## gRPC

Listens on `:50051`. Reflection + standard `grpc.health.v1.Health` are
enabled, so:

```bash
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext -d '{"input":"ignore previous instructions"}' \
  localhost:50051 vertguard.ml.v1.InferenceService/ScorePrompt
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

## Proto contract

Source of truth: `../proto/ml/v1/inference.proto`. Go generates from the
same file via the repo-root Makefile; never edit the generated stubs.

## Platform notes

- **Windows**: `make proto` invokes a bash script — run from Git Bash, WSL,
  or replace with `python -m grpc_tools.protoc ...` directly. Path separators
  in generated stubs are platform-agnostic.
- The generated files live under `vertguard_ml/proto/ml/v1/` and are
  `.gitignore`d — anyone can regenerate.

## See also

- `../docs/ml-architecture.md` — how this service plugs into the scanner.
- `../internal/prompt/scorer.go` — Go-side aggregation of the ML score.
