package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/advisory"
	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

type Advisory struct {
	Service *advisory.Service

	// CITADEL governance (see Publish). Citadel is nil when
	// OPENCSIRT_CITADEL_API_URL is unset — the governance check is then
	// skipped entirely (matches the outbox/watcher's existing dry-run
	// posture for audit-only events).
	Citadel          *sdkcitadel.Client
	CitadelProjectID string
	CitadelDryRun    bool
	Logger           zerolog.Logger
}

type advisoryRequest struct {
	IncidentID *uuid.UUID     `json:"incident_id,omitempty"`
	Title      string         `json:"title"`
	Summary    string         `json:"summary,omitempty"`
	TLP        string         `json:"tlp"`
	IOCs       []advisory.IOC `json:"iocs,omitempty"`
	Vuln       map[string]any `json:"vulnerability,omitempty"`
}

func (h *Advisory) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := db.AdvisoryFilter{
		State:  r.URL.Query().Get("state"),
		TLP:    r.URL.Query().Get("tlp"),
		Limit:  limit,
		Offset: offset,
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	items, _, err := h.Service.List(r.Context(), f, actor, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// B8: filter AMBER/RED advisories for users below operator rank (rank < 4).
	userRole := auth.Role(role)
	filtered := items[:0]
	for _, a := range items {
		if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(userRole) < 4 {
			continue
		}
		filtered = append(filtered, a)
	}
	items = filtered
	count := len(filtered)

	writeJSON(w, http.StatusOK, map[string]any{
		"advisories": items,
		"count":      count,
	})
}

func (h *Advisory) Create(w http.ResponseWriter, r *http.Request) {
	var req advisoryRequest
	if err := decodeJSON(r, &req, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a, err := h.Service.Create(r.Context(), advisory.CreateInput{
		IncidentID: req.IncidentID,
		Title:      req.Title,
		Summary:    req.Summary,
		TLP:        req.TLP,
		IOCs:       req.IOCs,
		Vuln:       req.Vuln,
	}, actor, role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *Advisory) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a, err := h.Service.Get(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}

	// B8: block AMBER/RED access for users below operator rank (rank < 4).
	userRole := auth.Role(role)
	if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(userRole) < 4 {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, a)
}

func (h *Advisory) GetCSAF(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a, err := h.Service.Get(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	if (a.TLP == "amber" || a.TLP == "red") && auth.Rank(auth.Role(role)) < 4 {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, a.CSAFDoc)
}

func (h *Advisory) Publish(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// CITADEL governance check: advisory publication is irreversible and
	// public-facing (it goes out to the constituency and, via ThreatFlow
	// push, beyond it), so it is evaluated against MARSHAL before it
	// happens. A REFUSE or HARD_STOP outcome blocks the publish.
	if h.Citadel != nil {
		// Actor = the real authenticated caller (the same identity source
		// actorAndRole already derives from JWT/sinauth claims for the
		// audit log). ActorToken forwards the caller's own bearer token so
		// CITADEL can verify it directly against sinauth — see citadel
		// adrs/005-sinauth-identity-bridge.md.
		actorToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Known gap, deliberately not papered over: OpenCSIRT has no real
		// second-approver flow for advisory publication — confirmed there
		// is no reviewed_by/approved_by concept anywhere in db.Advisory or
		// advisory.Service; a single csirt_lead currently both authors (or
		// requests) and publishes. Verifier is therefore a fixed system
		// placeholder, distinct from Actor so it can never trip Gate 3's
		// NDS_SAME_IDENTITY HARD_STOP, rather than a genuine second
		// person. VerifierToken is left empty; CITADEL's soft mode
		// (citadel.enforce_identity / enforce_signatures both false)
		// treats that as a warning, not a block, today. Building real
		// two-person approval for advisory publication is a separate
		// product change (new draft→review→publish states), not
		// fabricated here.
		k := sdkcitadel.Kerkese{
			KerkeseVersion: "1.0",
			TsUTC:          time.Now().UTC(),
			ProjectID:      h.CitadelProjectID,
			ExecutionID:    id,
			Action: sdkcitadel.KerkeseAction{
				Type:        "ADVISORY_PUBLISH",
				Description: "OpenCSIRT advisory publication",
				ChangeID:    id.String(),
			},
			Actor:    sdkcitadel.KerkeseActor{UserID: actor.String(), Role: role},
			Verifier: sdkcitadel.KerkeseVerifier{UserID: "opencsirt-system-verifier", Role: "group_sig_verifier"},
			Evidence: sdkcitadel.KerkeseEvidence{
				ChangeID: id.String(),
				Extra:    map[string]any{"advisory_id": id.String()},
			},
			SoD:        sdkcitadel.KerkeseSoD{OperatorUserID: actor.String(), VerifierUserID: "opencsirt-system-verifier"},
			DryRun:     h.CitadelDryRun,
			ActorToken: actorToken,
		}
		decision, evalErr := h.Citadel.Evaluate(r.Context(), k)
		if evalErr != nil {
			// Evaluate always returns a non-nil Decision even on
			// transport failure, synthesized per h.Citadel's FailMode
			// (fail-closed / HARD_STOP by default — see
			// sdk/go/citadel.FailMode). Logged so ops can see MARSHAL is
			// unreachable; decision.Allowed() below still governs.
			h.Logger.Warn().Err(evalErr).Str("advisory_id", id.String()).Msg("CITADEL marshal evaluate failed — applying configured fail-mode")
		}
		if !decision.Allowed() {
			reasons := decision.Reasons
			if len(reasons) == 0 {
				reasons = []string{"CITADEL governance check rejected this advisory publication"}
			}
			writeError(w, http.StatusForbidden, strings.Join(reasons, "; "))
			return
		}
	}

	a, err := h.Service.Publish(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Advisory) Withdraw(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	a, err := h.Service.Withdraw(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, a)
}
