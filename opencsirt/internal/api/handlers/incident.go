package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
	"github.com/opensecstack/opencsirt/internal/incident"
	"github.com/opensecstack/opencsirt/internal/integrations"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

type Incident struct {
	Service *incident.Service
	NIS2    *integrations.NIS2Client

	// CITADEL governance (see Close). Citadel is nil when
	// OPENCSIRT_CITADEL_API_URL is unset — the governance check is then
	// skipped entirely.
	Citadel          *sdkcitadel.Client
	CitadelProjectID string
	CitadelDryRun    bool
	Logger           zerolog.Logger
}

type incidentRequest struct {
	ConstituencyID *uuid.UUID     `json:"constituency_id,omitempty"`
	Source         string         `json:"source"`
	Severity       string         `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

func (h *Incident) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, err := parseLimitOffset(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := db.IncidentFilter{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		Limit:    limit,
		Offset:   offset,
	}
	items, total, err := h.Service.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incidents": items,
		"count":     total,
	})
}

func (h *Incident) Create(w http.ResponseWriter, r *http.Request) {
	var req incidentRequest
	if err := decodeJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, role, err := actorAndRole(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	inc, err := h.Service.Create(r.Context(), incident.CreateInput{
		ConstituencyID: req.ConstituencyID,
		Source:         req.Source,
		Severity:       req.Severity,
		Title:          req.Title,
		Description:    req.Description,
		Metadata:       req.Metadata,
	}, actor, role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Article 23 NIS2 notification (best-effort, never fails the API call).
	if h.NIS2 != nil && (req.Severity == "high" || req.Severity == "critical") {
		go func(snap *db.Incident) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = h.NIS2.Notify(ctx, integrations.NIS2Notification{
				IncidentID:     snap.ID,
				ConstituencyID: snap.ConstituencyID,
				Severity:       snap.Severity,
				Title:          snap.Title,
				OpenedAt:       snap.OpenedAt,
				Source:         snap.Source,
			})
		}(inc)
	}

	writeJSON(w, http.StatusCreated, inc)
}

func (h *Incident) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	inc, err := h.Service.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (h *Incident) Escalate(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Service.UpdateStatus(r.Context(), id, "triaged", actor, role); err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	inc, err := h.Service.Get(r.Context(), id)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (h *Incident) Close(w http.ResponseWriter, r *http.Request) {
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

	// CITADEL governance check: closing an incident determines whether
	// NIS2 reporting obligations are considered satisfied, so it is
	// evaluated against MARSHAL before it happens. A REFUSE or HARD_STOP
	// outcome blocks the close.
	if h.Citadel != nil {
		// Actor = the real authenticated caller — same identity source
		// actorAndRole already derives from JWT/sinauth claims for the
		// audit log. ActorToken forwards the caller's own bearer token so
		// CITADEL can verify it directly against sinauth — see citadel
		// adrs/005-sinauth-identity-bridge.md.
		actorToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Known gap, deliberately not papered over: OpenCSIRT has no real
		// second-approver flow for incident closure — confirmed there is
		// no reviewed_by/approved_by/closed_by-distinct-from-opener
		// concept anywhere in db.Incident or incident.Service. Verifier is
		// therefore a fixed system placeholder, distinct from Actor so it
		// can never trip Gate 3's NDS_SAME_IDENTITY HARD_STOP, rather than
		// a genuine second person. VerifierToken is left empty; CITADEL's
		// soft mode (citadel.enforce_identity / enforce_signatures both
		// false) treats that as a warning, not a block, today. Building
		// real two-person approval for incident closure is a separate
		// product change, not fabricated here.
		k := sdkcitadel.Kerkese{
			KerkeseVersion: "1.0",
			TsUTC:          time.Now().UTC(),
			ProjectID:      h.CitadelProjectID,
			ExecutionID:    id,
			Action: sdkcitadel.KerkeseAction{
				Type:        "INCIDENT_CLOSE",
				Description: "OpenCSIRT incident closure",
				IncidentID:  id.String(),
			},
			Actor:    sdkcitadel.KerkeseActor{UserID: actor.String(), Role: role},
			Verifier: sdkcitadel.KerkeseVerifier{UserID: "opencsirt-system-verifier", Role: "group_sig_verifier"},
			Evidence: sdkcitadel.KerkeseEvidence{
				Extra: map[string]any{"incident_id": id.String()},
			},
			SoD:        sdkcitadel.KerkeseSoD{OperatorUserID: actor.String(), VerifierUserID: "opencsirt-system-verifier"},
			DryRun:     h.CitadelDryRun,
			ActorToken: actorToken,
		}
		decision, evalErr := h.Citadel.Evaluate(r.Context(), k)
		if evalErr != nil {
			h.Logger.Warn().Err(evalErr).Str("incident_id", id.String()).Msg("CITADEL marshal evaluate failed — proceeding with close")
		} else if decision != nil && (decision.Outcome == sdkcitadel.OutcomeRefuse || decision.Outcome == sdkcitadel.OutcomeHardStop) {
			reasons := decision.Reasons
			if len(reasons) == 0 {
				reasons = []string{"CITADEL governance check rejected this incident closure"}
			}
			writeError(w, http.StatusForbidden, strings.Join(reasons, "; "))
			return
		}
	}

	inc, err := h.Service.Close(r.Context(), id, actor, role)
	if err != nil {
		code, msg := mapDBError(err)
		writeError(w, code, msg)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}
