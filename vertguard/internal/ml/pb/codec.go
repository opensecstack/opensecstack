// Custom gRPC codec for the hand-written mlpb messages.
//
// WHY: the standard "proto" codec uses google.golang.org/protobuf
// which requires a full protoreflect.Message implementation. Our
// hand-written messages instead expose simple MarshalVT/UnmarshalVT
// pairs. We register a codec named "proto" but only on a private
// dial so we never override the global default. Callers force this
// codec per-call via grpc.ForceCodec.

package mlpb

import (
	"fmt"

	"google.golang.org/grpc/encoding"
)

// CodecName identifies the wire codec used by the VertGuard ML client.
// Stays "proto" so the Python service (using grpcio's standard
// protobuf codec) parses the bytes without negotiation.
const CodecName = "proto"

// vtMessage is what our generated messages implement.
type vtMessage interface {
	MarshalVT() ([]byte, error)
	UnmarshalVT([]byte) error
}

// Codec implements grpc/encoding.Codec for the hand-written messages.
// It MUST live behind grpc.ForceCodec — registering it globally would
// break every other proto-using gRPC client in the binary.
type Codec struct{}

// Marshal serialises a vtMessage; rejects anything else.
func (Codec) Marshal(v interface{}) ([]byte, error) {
	m, ok := v.(vtMessage)
	if !ok {
		return nil, fmt.Errorf("mlpb codec: cannot marshal %T (need MarshalVT)", v)
	}
	return m.MarshalVT()
}

// Unmarshal mutates v from proto3 wire bytes; rejects anything else.
func (Codec) Unmarshal(data []byte, v interface{}) error {
	m, ok := v.(vtMessage)
	if !ok {
		return fmt.Errorf("mlpb codec: cannot unmarshal into %T (need UnmarshalVT)", v)
	}
	return m.UnmarshalVT(data)
}

// Name returns the wire content-subtype the codec answers to.
func (Codec) Name() string { return CodecName }

// CallOption returns the grpc.CallOption that forces this codec on a
// single RPC. Use with grpc.NewClient / Dial via grpc.WithDefaultCallOptions.
//
// Returns the codec instance (used by ForceCodec); the caller wraps it
// with grpc.ForceCodec at the client level.
var _ encoding.Codec = Codec{}
