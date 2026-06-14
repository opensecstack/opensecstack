# securelab-payload-engine

High-speed payload generation and mutation engine for SecureLab, exposed to Python via PyO3 bindings.

This crate provides the `PayloadEngine`, `PayloadSpec`, and `PayloadResult` types. At v0.0.1 the public API is defined and the PyO3 module wiring is in place; full payload generation and mutation primitives land in v1.0.0.

## Python import

After building with maturin the module is importable as:

```python
from securelab import payload_engine

engine = payload_engine.PayloadEngine()
spec = payload_engine.PayloadSpec(
    technique_id="T1059.001",
    target="host",
    parameters='{"shell": "powershell"}',
)
result = engine.generate(spec)  # raises NotImplementedError until v1.0.0
```

## Build

Development (editable install into the active virtual environment):

```sh
maturin develop
```

Production wheel:

```sh
maturin build --release
```

## Status

Full payload generation (`PayloadEngine.generate`) and mutation (`PayloadEngine.mutate`) land in v1.0.0. The v0.0.1 skeleton raises `NotImplementedError` for both methods.
