<!--
Copyright 2024 The OpenSecStack Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# VertGuard gRPC ML Service

## Overview

VertGuard delegates threat scoring and anomaly detection to a dedicated ML service exposed over gRPC. This separation keeps the Go service stateless with respect to model state and allows the ML component to be scaled, replaced, or retrained independently.

The ML service performs two core functions:

- **Real-time threat scoring**: each incoming event is assigned a risk score between 0.0 (benign) and 1.0 (critical threat).
- **Anomaly classification**: the service labels the event with a human-readable category (e.g., `port_scan`, `brute_force`, `data_exfiltration`, `normal`) and reports a confidence value for that label.

## gRPC Service Definition

The service contract is defined in `proto/ml/scoring.proto`:

```proto
syntax = "proto3";

package ml.scoring.v1;

service ScoringService {
  rpc Score(ScoreRequest) returns (ScoreResponse);
  rpc ScoreBatch(ScoreBatchRequest) returns (ScoreBatchResponse);
}

message ScoreRequest {
  bytes  payload    = 1; // raw event payload (JSON-encoded)
  string source_ip  = 2;
  string event_type = 3;
}

message ScoreResponse {
  float  score      = 1; // 0.0 (benign) – 1.0 (critical)
  string label      = 2; // anomaly class label
  float  confidence = 3; // label confidence, 0.0 – 1.0
}

message ScoreBatchRequest {
  repeated ScoreRequest requests = 1;
}

message ScoreBatchResponse {
  repeated ScoreResponse responses = 1;
}
```

## Calling the Service from Go

VertGuard calls the ML service through a thin client wrapper located at `internal/ml/client.go`. The client is initialized once at startup and reused across requests:

```go
conn, err := grpc.Dial(cfg.MLServiceAddr, grpc.WithTransportCredentials(...))
client := pb.NewScoringServiceClient(conn)

resp, err := client.Score(ctx, &pb.ScoreRequest{
    Payload:   eventJSON,
    SourceIp:  event.SourceIP,
    EventType: event.Type,
})
```

A configurable timeout (default 200 ms) is applied via `context.WithTimeout` on every call. Failures fall back to a conservative score of `1.0` to avoid silently dropping threats.

## Deployment

The ML service runs as a separate container alongside VertGuard. It is built on Python with FastAPI for the management HTTP plane and grpcio for the gRPC plane.

Compose service name: `vertguard-ml`

```yaml
vertguard-ml:
  build: ./ml
  environment:
    - MODEL_PATH=/models/scoring_model.pkl
    - GRPC_PORT=50051
  volumes:
    - model-artifacts:/models
  ports:
    - "50051"
```

The VertGuard API container references this service via `ML_SERVICE_ADDR=vertguard-ml:50051`.

## Model

The scoring model is a scikit-learn pipeline (gradient boosting classifier) or a PyTorch neural network, depending on the deployment configuration. The active model is loaded from the path specified by `MODEL_PATH` at container startup.

## Retraining and Hot-Reload

To retrain, export a new model artifact to the mounted `model-artifacts` volume, then send a `POST /admin/reload` request to the ML service's HTTP management API. The service loads the new artifact in a background thread without dropping active gRPC connections.

## Health Check

The service implements the standard [gRPC health checking protocol](https://grpc.github.io/grpc/core/md_doc_health-checking.html). VertGuard's liveness probe calls `grpc.health.v1.Health/Check` before routing traffic.

## Performance

| Metric | Target |
|---|---|
| p99 latency (single score) | < 15 ms |
| p99 latency (batch, 50 items) | < 80 ms |
| Throughput (single replica) | ~2000 RPS |

Use `ScoreBatch` for bulk ingestion pipelines to amortize gRPC connection overhead.
