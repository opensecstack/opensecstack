#!/usr/bin/env bash
# Regenerate the Python gRPC stubs from the proto contract.
# The proto contract lives one level up from the python service so Go
# and Python consume the same source-of-truth.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PROTO_ROOT="$(cd "$ROOT/../proto" && pwd)"
OUT_DIR="$ROOT/vertguard_ml/proto"

mkdir -p "$OUT_DIR"
touch "$OUT_DIR/__init__.py"

# WHY: --proto_path rooted at vertguard/proto so the generated import
# path is `ml.v1.inference_pb2`, mirroring the proto package layout.
python -m grpc_tools.protoc \
    --proto_path="$PROTO_ROOT" \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    "$PROTO_ROOT/ml/v1/inference.proto"

# WHY: grpc_tools emits absolute imports rooted at the proto_path; we
# rewrite them to relative-from-package so the generated module works
# when imported as `vertguard_ml.proto.ml.v1.inference_pb2_grpc`.
GRPC_PY="$OUT_DIR/ml/v1/inference_pb2_grpc.py"
if [[ -f "$GRPC_PY" ]]; then
    # Cross-platform sed: write to a temp then move.
    sed 's|from ml.v1 import inference_pb2|from vertguard_ml.proto.ml.v1 import inference_pb2|' \
        "$GRPC_PY" > "$GRPC_PY.tmp" && mv "$GRPC_PY.tmp" "$GRPC_PY"
fi

# Ensure every intermediate package has __init__.py.
touch "$OUT_DIR/ml/__init__.py" "$OUT_DIR/ml/v1/__init__.py"

echo "Generated proto stubs in $OUT_DIR"
