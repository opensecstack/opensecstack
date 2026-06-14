// Wire: add Search field to Deps and pass search.New(cfg) in server.go
// After adding to server.go, run: go get github.com/meilisearch/meilisearch-go
package search

import (
	"fmt"

	"github.com/meilisearch/meilisearch-go"
	"github.com/opensecstack/community/internal/config"
)

const indexName = "posts"

type PostDocument struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Body              string   `json:"body"`
	AuthorUsername    string   `json:"author_username"`
	AuthorDisplayName string   `json:"author_display_name"`
	Tags              []string `json:"tags"`
	PublishedAt       string   `json:"published_at"`
	Slug              string   `json:"slug"`
}

type Client struct {
	idx meilisearch.IndexManager
}

func New(cfg *config.Config) (*Client, error) {
	mc := meilisearch.New(cfg.MeilisearchURL, meilisearch.WithAPIKey(cfg.MeilisearchKey))

	if _, err := mc.CreateIndex(&meilisearch.IndexConfig{
		Uid:        indexName,
		PrimaryKey: "id",
	}); err != nil {
		// index may already exist — non-fatal
		_ = err
	}

	idx := mc.Index(indexName)

	if _, err := idx.UpdateSearchableAttributes(&[]string{
		"title", "body", "tags", "author_username",
	}); err != nil {
		return nil, fmt.Errorf("search: set searchable attributes: %w", err)
	}

	if _, err := idx.UpdateDisplayedAttributes(&[]string{
		"id", "title", "body", "author_username", "author_display_name", "tags", "published_at", "slug",
	}); err != nil {
		return nil, fmt.Errorf("search: set displayed attributes: %w", err)
	}

	return &Client{idx: idx}, nil
}

func (c *Client) IndexPost(doc PostDocument) error {
	if len(doc.Body) > 5000 {
		doc.Body = doc.Body[:5000]
	}
	pk := "id"
	_, err := c.idx.AddDocuments([]PostDocument{doc}, &meilisearch.DocumentOptions{PrimaryKey: &pk})
	return err
}

func (c *Client) DeletePost(id string) error {
	_, err := c.idx.DeleteDocument(id, nil)
	return err
}

func (c *Client) Search(q string, limit, offset int) ([]string, error) {
	res, err := c.idx.Search(q, &meilisearch.SearchRequest{
		Limit:  int64(limit),
		Offset: int64(offset),
	})
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(res.Hits))
	for _, hit := range res.Hits {
		var doc struct {
			ID string `json:"id"`
		}
		if err := hit.DecodeInto(&doc); err == nil && doc.ID != "" {
			ids = append(ids, doc.ID)
		}
	}
	return ids, nil
}
