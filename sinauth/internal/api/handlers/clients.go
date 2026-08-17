package handlers

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/opensecstack/sinauth/internal/client"
)

func ListClients(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := d.ClientSvc.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		type clientView struct {
			ID             string   `json:"id"`
			ClientID       string   `json:"client_id"`
			Name           string   `json:"name"`
			LogoURL        string   `json:"logo_url"`
			RedirectURIs   []string `json:"redirect_uris"`
			AllowedScopes  []string `json:"allowed_scopes"`
			GrantTypes     []string `json:"grant_types"`
			RequirePKCE    bool     `json:"require_pkce"`
			IsConfidential bool     `json:"is_confidential"`
		}
		out := make([]clientView, len(clients))
		for i, c := range clients {
			out[i] = clientView{
				ID:             c.ID,
				ClientID:       c.ClientID,
				Name:           c.Name,
				LogoURL:        c.LogoURL,
				RedirectURIs:   c.RedirectURIs,
				AllowedScopes:  c.AllowedScopes,
				GrantTypes:     c.GrantTypes,
				RequirePKCE:    c.RequirePKCE,
				IsConfidential: c.IsConfidential,
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func CreateClient(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ClientID       string   `json:"client_id"`
			Name           string   `json:"name"`
			LogoURL        string   `json:"logo_url"`
			RedirectURIs   []string `json:"redirect_uris"`
			AllowedScopes  []string `json:"allowed_scopes"`
			GrantTypes     []string `json:"grant_types"`
			RequirePKCE    bool     `json:"require_pkce"`
			IsConfidential bool     `json:"is_confidential"`
			ClientSecret   string   `json:"client_secret"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if body.ClientID == "" || len(body.RedirectURIs) == 0 || len(body.AllowedScopes) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id, at least one redirect_uri, and at least one allowed_scope are required"})
			return
		}
		var secretHash string
		if body.IsConfidential && body.ClientSecret != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(body.ClientSecret), 12)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			secretHash = string(hash)
		}
		c := client.Client{
			ClientID:       body.ClientID,
			Name:           body.Name,
			LogoURL:        body.LogoURL,
			ClientSecret:   secretHash,
			RedirectURIs:   body.RedirectURIs,
			AllowedScopes:  body.AllowedScopes,
			GrantTypes:     body.GrantTypes,
			RequirePKCE:    body.RequirePKCE,
			IsConfidential: body.IsConfidential,
		}
		if err := d.ClientSvc.Create(r.Context(), &c); err != nil {
			// Do not echo the raw store/driver error (e.g. a Postgres
			// constraint violation message) back to the caller — it can leak
			// schema/internal details. A generic message is sufficient; the
			// most common cause is a duplicate client_id.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unable to create client (client_id may already be in use, or a field is invalid)"})
			return
		}
		if d.Audit != nil {
			d.Audit.Log("client.created", "", body.ClientID, r.RemoteAddr, r.UserAgent(), nil)
		}
		writeJSON(w, http.StatusCreated, map[string]string{"client_id": c.ClientID, "message": "client created"})
	}
}

func DeleteClient(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.ClientSvc.Delete(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if d.Audit != nil {
			d.Audit.Log("client.deleted", "", id, r.RemoteAddr, r.UserAgent(), nil)
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "client deleted"})
	}
}
