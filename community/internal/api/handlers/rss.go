package handlers

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

const baseURL = "https://sin.to"

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	Author      string `xml:"author"`
	GUID        string `xml:"guid"`
}

type rssChannel struct {
	XMLName     xml.Name  `xml:"channel"`
	Title       string    `xml:"title"`
	Link        string    `xml:"link"`
	Description string    `xml:"description"`
	Items       []rssItem `xml:"item"`
}

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel rssChannel `xml:"channel"`
}

func parsePubDate(s string) string {
	t, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", s)
	if err != nil {
		t = time.Now()
	}
	return t.Format(time.RFC1123Z)
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func writeRSS(w http.ResponseWriter, feed rssFeed) {
	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	fmt.Fprint(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(feed)
}

func GetFeedRSS(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.title, p.slug, p.body, p.published_at::text, u.username, u.display_name
			FROM posts p
			JOIN users u ON u.id = p.author_id
			WHERE p.state = 'published'
			ORDER BY p.published_at DESC
			LIMIT 20`)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var items []rssItem
		for rows.Next() {
			var title, slug, body, pubAt, authorUsername, authorName string
			if err := rows.Scan(&title, &slug, &body, &pubAt, &authorUsername, &authorName); err != nil {
				continue
			}
			link := baseURL + "/posts/" + slug
			items = append(items, rssItem{
				Title:       title,
				Link:        link,
				Description: truncate(body, 500),
				PubDate:     parsePubDate(pubAt),
				Author:      authorName,
				GUID:        link,
			})
		}
		if items == nil {
			items = []rssItem{}
		}

		feed := rssFeed{
			Version: "2.0",
			Channel: rssChannel{
				Title:       "SIN Feed",
				Link:        baseURL,
				Description: "Latest posts from SIN community",
				Items:       items,
			},
		}
		writeRSS(w, feed)
	}
}

func GetUserFeedRSS(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.title, p.slug, p.body, p.published_at::text, u.username, u.display_name
			FROM posts p
			JOIN users u ON u.id = p.author_id
			WHERE p.state = 'published' AND u.username = $1
			ORDER BY p.published_at DESC
			LIMIT 20`, username)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var displayName string
		var items []rssItem
		for rows.Next() {
			var title, slug, body, pubAt, authorUsername, authorName string
			if err := rows.Scan(&title, &slug, &body, &pubAt, &authorUsername, &authorName); err != nil {
				continue
			}
			if displayName == "" {
				displayName = authorName
			}
			link := baseURL + "/posts/" + slug
			items = append(items, rssItem{
				Title:       title,
				Link:        link,
				Description: truncate(body, 500),
				PubDate:     parsePubDate(pubAt),
				Author:      authorName,
				GUID:        link,
			})
		}
		if items == nil {
			items = []rssItem{}
		}
		if displayName == "" {
			displayName = username
		}

		feed := rssFeed{
			Version: "2.0",
			Channel: rssChannel{
				Title:       displayName + "'s posts on SIN",
				Link:        baseURL + "/users/" + username,
				Description: "Posts by " + displayName + " on SIN",
				Items:       items,
			},
		}
		writeRSS(w, feed)
	}
}

func GetTagFeedRSS(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.title, p.slug, p.body, p.published_at::text, u.username, u.display_name
			FROM posts p
			JOIN users u ON u.id = p.author_id
			JOIN post_tags pt ON pt.post_id = p.id
			JOIN tags t ON t.id = pt.tag_id
			WHERE p.state = 'published' AND t.slug = $1
			ORDER BY p.published_at DESC
			LIMIT 20`, slug)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var items []rssItem
		for rows.Next() {
			var title, postSlug, body, pubAt, authorUsername, authorName string
			if err := rows.Scan(&title, &postSlug, &body, &pubAt, &authorUsername, &authorName); err != nil {
				continue
			}
			link := baseURL + "/posts/" + postSlug
			items = append(items, rssItem{
				Title:       title,
				Link:        link,
				Description: truncate(body, 500),
				PubDate:     parsePubDate(pubAt),
				Author:      authorName,
				GUID:        link,
			})
		}
		if items == nil {
			items = []rssItem{}
		}

		feed := rssFeed{
			Version: "2.0",
			Channel: rssChannel{
				Title:       "#" + slug + " posts on SIN",
				Link:        baseURL + "/tags/" + slug,
				Description: "Posts tagged #" + slug + " on SIN",
				Items:       items,
			},
		}
		writeRSS(w, feed)
	}
}
