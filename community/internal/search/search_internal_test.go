package search

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/meilisearch/meilisearch-go"
	"github.com/meilisearch/meilisearch-go/mocks"
	"github.com/stretchr/testify/mock"
)

// This file lives in package search (not search_test) specifically so it
// can construct a Client directly with a mocked meilisearch.IndexManager —
// the idx field is unexported and Client is otherwise only buildable via
// New(), which requires a live Meilisearch instance to configure the
// index. The generated mock (github.com/meilisearch/meilisearch-go/mocks)
// lets IndexPost/DeletePost/Search be exercised without one.

// TestIndexPost_TruncatesLongBodyAndSendsPrimaryKeyID verifies the 5000-byte
// body truncation guard and that AddDocuments is called with primary key
// "id" (so Meilisearch can upsert by post ID).
func TestIndexPost_TruncatesLongBodyAndSendsPrimaryKeyID(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	longBody := strings.Repeat("a", 6000)
	var capturedBody string
	var capturedPK *string
	idx.EXPECT().
		AddDocuments(mock.Anything, mock.Anything).
		Run(func(docsPtr interface{}, opts *meilisearch.DocumentOptions) {
			docs, ok := docsPtr.([]PostDocument)
			if !ok || len(docs) != 1 {
				t.Fatalf("expected AddDocuments to receive []PostDocument of length 1, got %#v", docsPtr)
			}
			capturedBody = docs[0].Body
			capturedPK = opts.PrimaryKey
		}).
		Return(&meilisearch.TaskInfo{}, nil)

	if err := c.IndexPost(PostDocument{ID: "post-1", Body: longBody}); err != nil {
		t.Fatalf("IndexPost: %v", err)
	}

	if len(capturedBody) != 5000 {
		t.Errorf("expected body truncated to 5000 bytes, got %d", len(capturedBody))
	}
	if capturedPK == nil || *capturedPK != "id" {
		t.Errorf("expected primary key \"id\", got %v", capturedPK)
	}
}

// TestIndexPost_ShortBody_NotTruncated verifies bodies under the 5000-byte
// limit pass through unmodified.
func TestIndexPost_ShortBody_NotTruncated(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	var capturedBody string
	idx.EXPECT().
		AddDocuments(mock.Anything, mock.Anything).
		Run(func(docsPtr interface{}, opts *meilisearch.DocumentOptions) {
			docs := docsPtr.([]PostDocument)
			capturedBody = docs[0].Body
		}).
		Return(&meilisearch.TaskInfo{}, nil)

	if err := c.IndexPost(PostDocument{ID: "post-2", Body: "short body"}); err != nil {
		t.Fatalf("IndexPost: %v", err)
	}
	if capturedBody != "short body" {
		t.Errorf("expected body unmodified, got %q", capturedBody)
	}
}

// TestIndexPost_AddDocumentsError_Propagates verifies IndexPost surfaces
// errors from the underlying Meilisearch call rather than swallowing them.
func TestIndexPost_AddDocumentsError_Propagates(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	wantErr := errors.New("meilisearch unavailable")
	idx.EXPECT().AddDocuments(mock.Anything, mock.Anything).Return(nil, wantErr)

	if err := c.IndexPost(PostDocument{ID: "post-3"}); !errors.Is(err, wantErr) {
		t.Fatalf("expected IndexPost to propagate the AddDocuments error, got %v", err)
	}
}

// TestDeletePost_CallsDeleteDocumentWithID verifies DeletePost forwards the
// post ID to DeleteDocument and propagates any error.
func TestDeletePost_CallsDeleteDocumentWithID(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	idx.EXPECT().DeleteDocument("post-42", (*meilisearch.DocumentOptions)(nil)).Return(&meilisearch.TaskInfo{}, nil)

	if err := c.DeletePost("post-42"); err != nil {
		t.Fatalf("DeletePost: %v", err)
	}
}

func TestDeletePost_DeleteDocumentError_Propagates(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	wantErr := errors.New("delete failed")
	idx.EXPECT().DeleteDocument("post-42", (*meilisearch.DocumentOptions)(nil)).Return(nil, wantErr)

	if err := c.DeletePost("post-42"); !errors.Is(err, wantErr) {
		t.Fatalf("expected DeletePost to propagate the error, got %v", err)
	}
}

// TestSearch_DecodesHitIDsAndSkipsEmptyOrUndecodable verifies Search
// extracts the "id" field from each hit, in order, while skipping hits
// whose id is missing/empty — matching the `doc.ID != ""` guard in
// search.go's Search.
func TestSearch_DecodesHitIDsAndSkipsEmptyOrUndecodable(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	hits := meilisearch.Hits{
		{"id": json.RawMessage(`"post-a"`)},
		{"id": json.RawMessage(`""`)},               // empty id -> skipped
		{"title": json.RawMessage(`"no id field"`)}, // no id -> skipped
		{"id": json.RawMessage(`"post-b"`)},
	}

	idx.EXPECT().
		Search("kubernetes", mock.MatchedBy(func(req *meilisearch.SearchRequest) bool {
			return req.Limit == 10 && req.Offset == 20
		})).
		Return(&meilisearch.SearchResponse{Hits: hits}, nil)

	ids, err := c.Search("kubernetes", 10, 20)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	want := []string{"post-a", "post-b"}
	if len(ids) != len(want) {
		t.Fatalf("expected %v, got %v", want, ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("index %d: expected %q, got %q", i, want[i], ids[i])
		}
	}
}

// TestSearch_UnderlyingSearchError_Propagates verifies Search surfaces
// errors from the Meilisearch call as (nil, err) rather than returning a
// partial/empty result silently.
func TestSearch_UnderlyingSearchError_Propagates(t *testing.T) {
	idx := mocks.NewMockmeilisearchIndexManager(t)
	c := &Client{idx: idx}

	wantErr := errors.New("search backend down")
	idx.EXPECT().Search("query", mock.Anything).Return(nil, wantErr)

	ids, err := c.Search("query", 10, 0)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected Search to propagate the error, got %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil ids on error, got %v", ids)
	}
}
