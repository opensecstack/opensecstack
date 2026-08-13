package mlpb

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ─── fake grpc.ClientConnInterface ──────────────────────────────────

// fakeClientConn is a minimal grpc.ClientConnInterface that records the
// invoked method and echoes canned data into the reply, letting us drive
// the generated client wrappers without a real network connection.
type fakeClientConn struct {
	lastMethod string
	invokeErr  error
	// populate is called with the reply pointer so the test can fill it in.
	populate     func(reply interface{})
	newStream    grpc.ClientStream
	newStreamErr error
}

func (f *fakeClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	f.lastMethod = method
	if f.invokeErr != nil {
		return f.invokeErr
	}
	if f.populate != nil {
		f.populate(reply)
	}
	return nil
}

func (f *fakeClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	f.lastMethod = method
	if f.newStreamErr != nil {
		return nil, f.newStreamErr
	}
	return f.newStream, nil
}

func TestNewInferenceServiceClient_ScorePrompt(t *testing.T) {
	fc := &fakeClientConn{
		populate: func(reply interface{}) {
			out := reply.(*ScoreResponse)
			out.Verdict = "benign"
			out.Confidence = 0.1
		},
	}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ScorePrompt(context.Background(), &PromptScoreRequest{Input: "hi"})
	if err != nil {
		t.Fatalf("ScorePrompt: %v", err)
	}
	if resp.Verdict != "benign" || resp.Confidence != 0.1 {
		t.Errorf("ScorePrompt response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ScorePrompt_FullMethodName {
		t.Errorf("lastMethod = %q, want %q", fc.lastMethod, InferenceService_ScorePrompt_FullMethodName)
	}
}

func TestNewInferenceServiceClient_ScorePrompt_Error(t *testing.T) {
	fc := &fakeClientConn{invokeErr: errors.New("boom")}
	client := NewInferenceServiceClient(fc)
	_, err := client.ScorePrompt(context.Background(), &PromptScoreRequest{})
	if err == nil {
		t.Fatal("expected error from ScorePrompt")
	}
}

func TestNewInferenceServiceClient_ScorePhishing(t *testing.T) {
	fc := &fakeClientConn{populate: func(reply interface{}) {
		reply.(*ScoreResponse).Verdict = "phish"
	}}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ScorePhishing(context.Background(), &PhishingScoreRequest{Kind: "url"})
	if err != nil {
		t.Fatalf("ScorePhishing: %v", err)
	}
	if resp.Verdict != "phish" {
		t.Errorf("ScorePhishing response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ScorePhishing_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}
}

func TestNewInferenceServiceClient_ScoreMedia(t *testing.T) {
	fc := &fakeClientConn{populate: func(reply interface{}) {
		reply.(*ScoreResponse).ModelVersion = "media-v1"
	}}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ScoreMedia(context.Background(), &MediaScoreRequest{FileHash: "h"})
	if err != nil {
		t.Fatalf("ScoreMedia: %v", err)
	}
	if resp.ModelVersion != "media-v1" {
		t.Errorf("ScoreMedia response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ScoreMedia_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}
}

func TestNewInferenceServiceClient_ScoreIdentity(t *testing.T) {
	fc := &fakeClientConn{populate: func(reply interface{}) {
		reply.(*ScoreResponse).Verdict = "valid"
	}}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ScoreIdentity(context.Background(), &IdentityScoreRequest{ClaimType: "passport"})
	if err != nil {
		t.Fatalf("ScoreIdentity: %v", err)
	}
	if resp.Verdict != "valid" {
		t.Errorf("ScoreIdentity response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ScoreIdentity_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}
}

func TestNewInferenceServiceClient_ScoreAudio(t *testing.T) {
	fc := &fakeClientConn{populate: func(reply interface{}) {
		reply.(*ScoreResponse).Verdict = "voice-clone"
	}}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ScoreAudio(context.Background(), &AudioScoreRequest{SessionId: "s1"})
	if err != nil {
		t.Fatalf("ScoreAudio: %v", err)
	}
	if resp.Verdict != "voice-clone" {
		t.Errorf("ScoreAudio response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ScoreAudio_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}
}

func TestNewInferenceServiceClient_ModelInfo(t *testing.T) {
	fc := &fakeClientConn{populate: func(reply interface{}) {
		reply.(*ModelInfoResponse).Name = "detector"
	}}
	client := NewInferenceServiceClient(fc)
	resp, err := client.ModelInfo(context.Background(), &ModelInfoRequest{})
	if err != nil {
		t.Fatalf("ModelInfo: %v", err)
	}
	if resp.Name != "detector" {
		t.Errorf("ModelInfo response = %+v", resp)
	}
	if fc.lastMethod != InferenceService_ModelInfo_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}
}

// ─── streaming client ────────────────────────────────────────────────

// fakeClientStream implements grpc.ClientStream via embedding (nil) and
// overrides only SendMsg/RecvMsg, which is all inferenceServiceScoreVideoStreamClient
// exercises.
type fakeClientStream struct {
	grpc.ClientStream
	sentMsgs []interface{}
	sendErr  error
	recvMsg  *VideoScoreEvent
	recvErr  error
}

func (f *fakeClientStream) SendMsg(m interface{}) error {
	f.sentMsgs = append(f.sentMsgs, m)
	return f.sendErr
}

func (f *fakeClientStream) RecvMsg(m interface{}) error {
	if f.recvErr != nil {
		return f.recvErr
	}
	out := m.(*VideoScoreEvent)
	if f.recvMsg != nil {
		*out = *f.recvMsg
	}
	return nil
}

func TestScoreVideoStream_SendRecv(t *testing.T) {
	fs := &fakeClientStream{recvMsg: &VideoScoreEvent{SessionId: "s1", Verdict: "clean"}}
	fc := &fakeClientConn{newStream: fs}
	client := NewInferenceServiceClient(fc)

	stream, err := client.ScoreVideoStream(context.Background())
	if err != nil {
		t.Fatalf("ScoreVideoStream: %v", err)
	}
	if fc.lastMethod != InferenceService_ScoreVideoStream_FullMethodName {
		t.Errorf("lastMethod = %q", fc.lastMethod)
	}

	frame := &VideoFrameRequest{SessionId: "s1", FrameSeq: 1}
	if err := stream.Send(frame); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(fs.sentMsgs) != 1 || fs.sentMsgs[0] != frame {
		t.Errorf("sentMsgs = %+v, want [%+v]", fs.sentMsgs, frame)
	}

	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if event.SessionId != "s1" || event.Verdict != "clean" {
		t.Errorf("Recv() = %+v", event)
	}
}

func TestScoreVideoStream_SendRecv_Errors(t *testing.T) {
	fs := &fakeClientStream{sendErr: errors.New("send fail"), recvErr: errors.New("recv fail")}
	fc := &fakeClientConn{newStream: fs}
	client := NewInferenceServiceClient(fc)

	stream, err := client.ScoreVideoStream(context.Background())
	if err != nil {
		t.Fatalf("ScoreVideoStream: %v", err)
	}
	if err := stream.Send(&VideoFrameRequest{}); err == nil {
		t.Error("expected Send error")
	}
	if _, err := stream.Recv(); err == nil {
		t.Error("expected Recv error")
	}
}

func TestScoreVideoStream_NewStreamError(t *testing.T) {
	fc := &fakeClientConn{newStreamErr: errors.New("dial fail")}
	client := NewInferenceServiceClient(fc)
	if _, err := client.ScoreVideoStream(context.Background()); err == nil {
		t.Error("expected error when NewStream fails")
	}
}

// ─── UnimplementedInferenceServiceServer ────────────────────────────

func TestUnimplementedInferenceServiceServer_AllUnimplemented(t *testing.T) {
	var s UnimplementedInferenceServiceServer

	if _, err := s.ScorePrompt(context.Background(), &PromptScoreRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScorePrompt code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ScorePhishing(context.Background(), &PhishingScoreRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScorePhishing code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ScoreMedia(context.Background(), &MediaScoreRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScoreMedia code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ScoreIdentity(context.Background(), &IdentityScoreRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScoreIdentity code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ScoreAudio(context.Background(), &AudioScoreRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScoreAudio code = %v, want Unimplemented", status.Code(err))
	}
	if err := s.ScoreVideoStream(nil); status.Code(err) != codes.Unimplemented {
		t.Errorf("ScoreVideoStream code = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ModelInfo(context.Background(), &ModelInfoRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ModelInfo code = %v, want Unimplemented", status.Code(err))
	}
	// no-op marker method must not panic
	s.mustEmbedUnimplementedInferenceServiceServer()
}

// ─── fake server implementation for handler + registration tests ───

type fakeServer struct {
	UnimplementedInferenceServiceServer
	scorePromptResp   *ScoreResponse
	scorePromptErr    error
	scorePhishingResp *ScoreResponse
	scoreMediaResp    *ScoreResponse
	scoreIdentityResp *ScoreResponse
	scoreAudioResp    *ScoreResponse
	modelInfoResp     *ModelInfoResponse
	videoStreamErr    error
	videoStreamCalled bool
}

func (f *fakeServer) ScorePrompt(ctx context.Context, in *PromptScoreRequest) (*ScoreResponse, error) {
	return f.scorePromptResp, f.scorePromptErr
}
func (f *fakeServer) ScorePhishing(ctx context.Context, in *PhishingScoreRequest) (*ScoreResponse, error) {
	return f.scorePhishingResp, nil
}
func (f *fakeServer) ScoreMedia(ctx context.Context, in *MediaScoreRequest) (*ScoreResponse, error) {
	return f.scoreMediaResp, nil
}
func (f *fakeServer) ScoreIdentity(ctx context.Context, in *IdentityScoreRequest) (*ScoreResponse, error) {
	return f.scoreIdentityResp, nil
}
func (f *fakeServer) ScoreAudio(ctx context.Context, in *AudioScoreRequest) (*ScoreResponse, error) {
	return f.scoreAudioResp, nil
}
func (f *fakeServer) ScoreVideoStream(stream InferenceService_ScoreVideoStreamServer) error {
	f.videoStreamCalled = true
	return f.videoStreamErr
}
func (f *fakeServer) ModelInfo(ctx context.Context, in *ModelInfoRequest) (*ModelInfoResponse, error) {
	return f.modelInfoResp, nil
}

func TestHandler_ScorePrompt_NoInterceptor(t *testing.T) {
	srv := &fakeServer{scorePromptResp: &ScoreResponse{Verdict: "ok"}}
	dec := func(v interface{}) error {
		v.(*PromptScoreRequest).Input = "hi"
		return nil
	}
	resp, err := _InferenceService_ScorePrompt_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ScoreResponse).Verdict != "ok" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ScorePrompt_DecError(t *testing.T) {
	srv := &fakeServer{}
	dec := func(v interface{}) error { return errors.New("dec fail") }
	_, err := _InferenceService_ScorePrompt_Handler(srv, context.Background(), dec, nil)
	if err == nil {
		t.Fatal("expected dec error to propagate")
	}
}

func TestHandler_ScorePrompt_WithInterceptor(t *testing.T) {
	srv := &fakeServer{scorePromptResp: &ScoreResponse{Verdict: "intercepted"}}
	dec := func(v interface{}) error { return nil }
	called := false
	interceptor := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		called = true
		if info.FullMethod != InferenceService_ScorePrompt_FullMethodName {
			t.Errorf("info.FullMethod = %q", info.FullMethod)
		}
		return handler(ctx, req)
	}
	resp, err := _InferenceService_ScorePrompt_Handler(srv, context.Background(), dec, interceptor)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !called {
		t.Error("interceptor not invoked")
	}
	if resp.(*ScoreResponse).Verdict != "intercepted" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ScorePhishing(t *testing.T) {
	srv := &fakeServer{scorePhishingResp: &ScoreResponse{Verdict: "phish"}}
	dec := func(v interface{}) error { return nil }
	resp, err := _InferenceService_ScorePhishing_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ScoreResponse).Verdict != "phish" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ScoreMedia(t *testing.T) {
	srv := &fakeServer{scoreMediaResp: &ScoreResponse{Verdict: "media-ok"}}
	dec := func(v interface{}) error { return nil }
	resp, err := _InferenceService_ScoreMedia_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ScoreResponse).Verdict != "media-ok" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ScoreIdentity(t *testing.T) {
	srv := &fakeServer{scoreIdentityResp: &ScoreResponse{Verdict: "identity-ok"}}
	dec := func(v interface{}) error { return nil }
	resp, err := _InferenceService_ScoreIdentity_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ScoreResponse).Verdict != "identity-ok" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ScoreAudio(t *testing.T) {
	srv := &fakeServer{scoreAudioResp: &ScoreResponse{Verdict: "audio-ok"}}
	dec := func(v interface{}) error { return nil }
	resp, err := _InferenceService_ScoreAudio_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ScoreResponse).Verdict != "audio-ok" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ModelInfo(t *testing.T) {
	srv := &fakeServer{modelInfoResp: &ModelInfoResponse{Name: "m1"}}
	dec := func(v interface{}) error { return nil }
	resp, err := _InferenceService_ModelInfo_Handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if resp.(*ModelInfoResponse).Name != "m1" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestHandler_ModelInfo_DecError(t *testing.T) {
	srv := &fakeServer{}
	dec := func(v interface{}) error { return errors.New("dec fail") }
	_, err := _InferenceService_ModelInfo_Handler(srv, context.Background(), dec, nil)
	if err == nil {
		t.Fatal("expected dec error to propagate")
	}
}

// fakeServerStream is a minimal grpc.ServerStream stand-in — the handler
// under test only forwards it into inferenceServiceScoreVideoStreamServer,
// it does not call any of its methods directly.
type fakeServerStream struct {
	grpc.ServerStream
}

func TestHandler_ScoreVideoStream(t *testing.T) {
	srv := &fakeServer{}
	err := _InferenceService_ScoreVideoStream_Handler(srv, &fakeServerStream{})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !srv.videoStreamCalled {
		t.Error("ScoreVideoStream not called by handler")
	}
}

// ─── server-side stream wrapper Send/Recv ───────────────────────────

type fakeServerStreamMsg struct {
	grpc.ServerStream
	sentMsgs []interface{}
	sendErr  error
	recvMsg  *VideoFrameRequest
	recvErr  error
}

func (f *fakeServerStreamMsg) SendMsg(m interface{}) error {
	f.sentMsgs = append(f.sentMsgs, m)
	return f.sendErr
}

func (f *fakeServerStreamMsg) RecvMsg(m interface{}) error {
	if f.recvErr != nil {
		return f.recvErr
	}
	out := m.(*VideoFrameRequest)
	if f.recvMsg != nil {
		*out = *f.recvMsg
	}
	return nil
}

func TestServerStreamWrapper_SendRecv(t *testing.T) {
	fs := &fakeServerStreamMsg{recvMsg: &VideoFrameRequest{SessionId: "s1", FrameSeq: 3}}
	wrapped := &inferenceServiceScoreVideoStreamServer{fs}

	event := &VideoScoreEvent{SessionId: "s1", Verdict: "clean"}
	if err := wrapped.Send(event); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(fs.sentMsgs) != 1 || fs.sentMsgs[0] != event {
		t.Errorf("sentMsgs = %+v", fs.sentMsgs)
	}

	frame, err := wrapped.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if frame.SessionId != "s1" || frame.FrameSeq != 3 {
		t.Errorf("Recv() = %+v", frame)
	}
}

func TestServerStreamWrapper_SendRecv_Errors(t *testing.T) {
	fs := &fakeServerStreamMsg{sendErr: errors.New("send fail"), recvErr: errors.New("recv fail")}
	wrapped := &inferenceServiceScoreVideoStreamServer{fs}

	if err := wrapped.Send(&VideoScoreEvent{}); err == nil {
		t.Error("expected Send error")
	}
	if _, err := wrapped.Recv(); err == nil {
		t.Error("expected Recv error")
	}
}

// ─── RegisterInferenceServiceServer ─────────────────────────────────

type fakeRegistrar struct {
	desc *grpc.ServiceDesc
	impl interface{}
}

func (f *fakeRegistrar) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	f.desc = desc
	f.impl = impl
}

func TestRegisterInferenceServiceServer(t *testing.T) {
	reg := &fakeRegistrar{}
	srv := &fakeServer{}
	RegisterInferenceServiceServer(reg, srv)
	if reg.desc != &InferenceService_ServiceDesc {
		t.Error("RegisterService did not receive InferenceService_ServiceDesc")
	}
	if reg.impl != srv {
		t.Error("RegisterService did not receive the server implementation")
	}
	if reg.desc.ServiceName != "vertguard.ml.v1.InferenceService" {
		t.Errorf("ServiceName = %q", reg.desc.ServiceName)
	}
	if len(reg.desc.Methods) != 6 {
		t.Errorf("len(Methods) = %d, want 6", len(reg.desc.Methods))
	}
	if len(reg.desc.Streams) != 1 {
		t.Errorf("len(Streams) = %d, want 1", len(reg.desc.Streams))
	}
}

// TestServiceDesc_MethodNamesMatchFullMethodConstants cross-checks the
// ServiceDesc method table against the FullMethodName constants so a
// future edit can't silently desync the two.
func TestServiceDesc_MethodNamesMatchFullMethodConstants(t *testing.T) {
	want := map[string]bool{
		"ScorePrompt":   true,
		"ScorePhishing": true,
		"ScoreMedia":    true,
		"ScoreIdentity": true,
		"ScoreAudio":    true,
		"ModelInfo":     true,
	}
	got := map[string]bool{}
	for _, m := range InferenceService_ServiceDesc.Methods {
		got[m.MethodName] = true
		if m.Handler == nil {
			t.Errorf("method %q has nil handler", m.MethodName)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got methods %v, want %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing method %q in ServiceDesc", name)
		}
	}
	stream := InferenceService_ServiceDesc.Streams[0]
	if stream.StreamName != "ScoreVideoStream" || !stream.ServerStreams || !stream.ClientStreams {
		t.Errorf("unexpected stream desc: %+v", stream)
	}
}
