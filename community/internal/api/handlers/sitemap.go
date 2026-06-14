package handlers

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

type sitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty"`
}

type sitemap struct {
	XMLName xml.Name     `xml:"urlset"`
	Xmlns   string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

func GetSitemap(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		base := d.Cfg.SiteURL // e.g. "https://sin.to"

		var urls []sitemapURL

		// Static pages
		urls = append(urls,
			sitemapURL{Loc: base + "/", ChangeFreq: "hourly", Priority: "1.0"},
			sitemapURL{Loc: base + "/trending", ChangeFreq: "hourly", Priority: "0.9"},
			sitemapURL{Loc: base + "/users", ChangeFreq: "daily", Priority: "0.7"},
			sitemapURL{Loc: base + "/leaderboard", ChangeFreq: "daily", Priority: "0.6"},
		)

		// Published posts
		rows, err := d.Pool.Query(ctx,
			`SELECT slug, published_at FROM posts WHERE state = 'published' ORDER BY published_at DESC LIMIT 10000`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var slug string
				var publishedAt time.Time
				if err := rows.Scan(&slug, &publishedAt); err == nil {
					urls = append(urls, sitemapURL{
						Loc:        base + "/posts/" + slug,
						LastMod:    publishedAt.Format("2006-01-02"),
						ChangeFreq: "weekly",
						Priority:   "0.8",
					})
				}
			}
		}

		// Tags
		tagRows, err := d.Pool.Query(ctx, `SELECT slug FROM tags ORDER BY name LIMIT 1000`)
		if err == nil {
			defer tagRows.Close()
			for tagRows.Next() {
				var slug string
				if err := tagRows.Scan(&slug); err == nil {
					urls = append(urls, sitemapURL{
						Loc:        base + "/tags/" + slug,
						ChangeFreq: "daily",
						Priority:   "0.6",
					})
				}
			}
		}

		// Users
		userRows, err := d.Pool.Query(ctx, `SELECT username FROM users ORDER BY username LIMIT 5000`)
		if err == nil {
			defer userRows.Close()
			for userRows.Next() {
				var username string
				if err := userRows.Scan(&username); err == nil {
					urls = append(urls, sitemapURL{
						Loc:        base + "/users/" + username,
						ChangeFreq: "weekly",
						Priority:   "0.5",
					})
				}
			}
		}

		sm := sitemap{
			Xmlns: "http://www.sitemaps.org/schemas/sitemap/0.9",
			URLs:  urls,
		}

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xml.Header))
		_ = xml.NewEncoder(w).Encode(sm)
	}
}

func GetRobotsTxt(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := d.Cfg.SiteURL
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "User-agent: *\nAllow: /\nSitemap: %s/sitemap.xml\n", base)
	}
}
