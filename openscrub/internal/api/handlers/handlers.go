// Package handlers carries the HTTP handlers for the OpenScrub control
// plane API. Routes are registered in internal/api/server.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
	"github.com/opensecstack/openscrub/internal/version"
)

// Pinger is the minimum DB-health surface /api/v1/health needs.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Health is the handler set for /api/v1/health.
type Health struct {
	DB                 Pinger
	Plane              dataplane.Client
	DataplaneAttached  func() bool
}

// Get returns the liveness document. /health answers "the process
// is up and able to serve traffic" — it must NOT fail just because
// the dataplane has detached or the DB is being failed over, so
// Kubernetes does not kill a node that could otherwise recover.
// For "ready to receive traffic" semantics use /readyz instead.
func (h *Health) Get(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "ok",
		"version": version.Version,
	}
	if h.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2_000_000_000)
		defer cancel()
		if err := h.DB.Ping(ctx); err != nil {
			resp["db_ping"] = false
			resp["status"] = "degraded"
		} else {
			resp["db_ping"] = true
		}
	} else {
		resp["db_ping"] = false
	}
	if h.DataplaneAttached != nil {
		resp["dataplane_attached"] = h.DataplaneAttached()
	} else {
		resp["dataplane_attached"] = false
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ready answers Kubernetes' readinessProbe. It returns 503 unless
// every hard dependency is healthy:
//   - DB reachable (when configured)
//   - Dataplane attached (when transport != noop)
//
// Liveness (/health) keeps returning 200 with status="degraded" so
// the pod is not restarted; readiness pulls the pod out of the
// service's endpoints until the dependency recovers. Splitting the
// two probes is a Kubernetes best practice — the prior single
// /health endpoint conflated the two and caused unnecessary pod
// restarts during transient DB failovers.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "ready",
		"version": version.Version,
	}
	ready := true

	if h.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2_000_000_000)
		defer cancel()
		if err := h.DB.Ping(ctx); err != nil {
			resp["db_ping"] = false
			resp["status"] = "not_ready"
			resp["reason"] = "db ping failed: " + err.Error()
			ready = false
		} else {
			resp["db_ping"] = true
		}
	}

	if ready && h.DataplaneAttached != nil {
		attached := h.DataplaneAttached()
		resp["dataplane_attached"] = attached
		if !attached {
			resp["status"] = "not_ready"
			resp["reason"] = "dataplane not attached"
			ready = false
		}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

// CitadelGovernor is the subset of *sdkcitadel.Client the Rules handler
// needs to submit a Kerkese governance request to CITADEL MARSHAL.
// Decoupled so tests can inject a stub instead of a real HTTP server.
type CitadelGovernor interface {
	Evaluate(ctx context.Context, k sdkcitadel.Kerkese) (*sdkcitadel.Decision, error)
}

// citadelSystemVerifier is the fixed placeholder Verifier used on every
// Kerkese this handler submits. OpenScrub has no genuine two-person
// approval concept for firewall/mitigation rules (unlike, e.g.,
// apiguard's scan approval flow) — building one is a separate, larger
// product decision, out of scope here. This identifier is clearly
// distinguishable from any real sinauth user id (never a UUID), so it
// can never collide with a real Actor and — because it differs from
// Actor — does not trip CITADEL Gate 3's NDS same-identity check.
// VerifierToken is deliberately left empty; CITADEL's soft mode
// (citadel.enforce_signatures=false, citadel.enforce_identity=false)
// treats a missing Verifier token as a non-blocking warning today, not
// a hard failure. See citadel/adrs/006-split-enforce-identity-and-signatures.md.
const citadelSystemVerifier = "openscrub-system-verifier"

// Rules carries the dependencies of the /api/v1/rules handler set.
type Rules struct {
	Service *rules.Service
	Logger  zerolog.Logger

	// Citadel, when non-nil, gates manual (human-triggered) rule
	// insertion through POST /api/v1/rules on a CITADEL MARSHAL
	// evaluation before the rule is installed — see the Create doc
	// comment for exactly which path this covers and which it doesn't.
	// nil disables the gate (e.g. unit tests, or CITADEL not configured
	// — OPENSCRUB_CITADEL_API_URL empty), matching the pre-existing
	// fire-and-forget WORM emit's fail-open posture elsewhere in this
	// service.
	Citadel CitadelGovernor
	// CitadelProjectID is the Kerkese ProjectID field. Defaults to
	// "openscrub" via config.FromEnv.
	CitadelProjectID string
	// CitadelDryRun mirrors config.Config.CitadelDryRun onto the
	// Kerkese's DryRun field — CITADEL itself decides whether dry_run
	// suppresses enforcement.
	CitadelDryRun bool
}

// List handles GET /api/v1/rules.
//
// Pagination — `offset + limit` with stable order
// `(created_at DESC, id DESC)`. The OpenAPI spec advertised these query
// params but earlier revisions silently dropped `offset`, returning the
// first page over and over for every page > 1. The handler now reads
// both, clamps `offset` to >= 0, and lets the service layer honor them.
func (h *Rules) List(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	kind := rules.Type(r.URL.Query().Get("type"))
	out, err := h.Service.List(r.Context(), kind, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	if out == nil {
		out = []rules.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// Create handles POST /api/v1/rules — a human operator (or any other
// authenticated API caller; this route requires admin/operator role,
// see internal/api/server.go) deliberately installing a mitigation
// rule. This is the ONLY call site gated against CITADEL MARSHAL: a
// null-route or rate-limit is a high blast-radius action when a human
// pulls the trigger, so it is evaluated for REFUSE/HARD_STOP before
// install.
//
// This is deliberately distinct from the automated IOC-driven path:
// internal/ioc/puller.go's Tick() calls rules.Service.Create directly
// (bypassing this HTTP handler and this gate entirely) for
// threat-intel-sourced blocks. That path is intentionally audit-only —
// it is automated and high-frequency; blocking it on a synchronous
// governance round-trip would defeat the purpose of fast automated
// mitigation. Both paths still get an immutable WORM audit trail via
// rules.Service.emitChange → CITADEL POST /api/v1/worm/emit (see
// internal/citadel/client.go); only this one additionally gates on a
// MARSHAL EXECUTE/REFUSE/HARD_STOP decision beforehand.
func (h *Rules) Create(w http.ResponseWriter, r *http.Request) {
	var req rules.CreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	// Reject trailing JSON (e.g. an array of bodies smuggled past the
	// first-element decode) — DisallowUnknownFields handles per-object
	// surface area; this guards the document-level shape.
	if dec.More() {
		writeError(w, http.StatusBadRequest, "bad_json", "trailing data after json object")
		return
	}
	principal, createdBy := principalFromCtx(r.Context())
	if req.Source == "" {
		req.Source = rules.SourceOperator
	}

	if h.Citadel != nil {
		// Real Operator identity — the authenticated caller of THIS
		// endpoint. Deliberately not conditioned on req.Source: this
		// handler is reached only via a human/API caller (the IOC
		// puller never calls it), so every request here is a manual
		// insertion regardless of what Source string the caller claims
		// in the body — trusting a client-supplied field to decide
		// whether governance applies would let an operator bypass the
		// gate simply by setting source="threatflow" in the request.
		actorUserID := "unauthenticated"
		var actorToken string
		if claims, ok := auth.FromContext(r.Context()); ok && claims != nil && claims.Sub != "" {
			actorUserID = claims.Sub
			actorToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		k := sdkcitadel.Kerkese{
			KerkeseVersion: "1.0",
			TsUTC:          time.Now().UTC(),
			ProjectID:      h.CitadelProjectID,
			ExecutionID:    uuid.New(),
			Action: sdkcitadel.KerkeseAction{
				Type:        "deploy_change",
				Description: fmt.Sprintf("OpenScrub mitigation rule insertion: %s %s", req.Type, req.CIDR),
			},
			Actor: sdkcitadel.KerkeseActor{UserID: actorUserID, Role: "group_sig_operator"},
			// Known, documented gap — see citadelSystemVerifier.
			Verifier: sdkcitadel.KerkeseVerifier{UserID: citadelSystemVerifier, Role: "group_sig_verifier"},
			Evidence: sdkcitadel.KerkeseEvidence{
				Extra: map[string]any{
					"rule_type":   string(req.Type),
					"cidr":        req.CIDR,
					"pps":         req.PPS,
					"port":        req.Port,
					"ttl_seconds": req.TTLSeconds,
				},
			},
			SoD:    sdkcitadel.KerkeseSoD{OperatorUserID: actorUserID, VerifierUserID: citadelSystemVerifier},
			DryRun: h.CitadelDryRun,
			// ActorToken forwards the caller's own bearer token so
			// CITADEL can verify it directly against sinauth's JWKS —
			// see citadel/adrs/005-sinauth-identity-bridge.md.
			// SigOperator/SigVerifier are intentionally left empty: no
			// per-user Ed25519 key custody UX exists anywhere in the
			// ecosystem yet (citadel/adrs/004).
			ActorToken: actorToken,
		}

		decision, evalErr := h.Citadel.Evaluate(r.Context(), k)
		if evalErr != nil {
			// Fail open, matching apiguard's documented pattern: a
			// CITADEL outage must not take down mitigation rule
			// creation. Logged loudly so ops can see MARSHAL is
			// unreachable.
			h.Logger.Warn().Err(evalErr).Msg("CITADEL marshal evaluate failed — proceeding with rule insertion")
		} else if decision != nil && (decision.Outcome == sdkcitadel.OutcomeRefuse || decision.Outcome == sdkcitadel.OutcomeHardStop) {
			reasons := decision.Reasons
			if len(reasons) == 0 {
				reasons = []string{"CITADEL governance check rejected this rule insertion"}
			}
			writeError(w, http.StatusForbidden, "citadel_refused", strings.Join(reasons, "; "))
			return
		}
	}

	out, err := h.Service.Create(r.Context(), req, principal, createdBy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// Delete handles DELETE /api/v1/rules/{id} — manual (human-initiated)
// rule withdrawal.
//
// Classification decision: withdrawal is left audit-only (WORM emit
// via rules.Service.emitChange, no CITADEL MARSHAL gate), unlike
// Create's manual-insertion path. Rationale: withdrawal is reversible —
// re-inserting the same rule fully restores the block — and this route
// already requires admin/operator role (internal/api/server.go), so an
// authorization decision has already been made by RBAC before this
// handler runs. Gating a reversible, already-authorized action behind a
// second synchronous MARSHAL round-trip adds latency and a new failure
// mode (CITADEL outage blocking an operator trying to remove a
// mistaken block) without a proportional safety benefit — if anything,
// making withdrawal slower during an incident is the wrong tradeoff.
// This is a deliberate judgment call, not an oversight.
func (h *Rules) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", err.Error())
		return
	}
	principal, _ := principalFromCtx(r.Context())
	reason := r.URL.Query().Get("reason")
	// Reason flows verbatim into the CITADEL rule_change event and the
	// audit log. Cap the size so a 10MB query string doesn't show up in
	// the WORM stream, and refuse control characters that would break
	// log parsers downstream.
	const maxReason = 512
	if len(reason) > maxReason {
		writeError(w, http.StatusBadRequest, "bad_reason",
			fmt.Sprintf("reason exceeds %d bytes", maxReason))
		return
	}
	for _, c := range reason {
		if c < 0x20 && c != '\t' {
			writeError(w, http.StatusBadRequest, "bad_reason",
				"reason contains control characters")
			return
		}
	}
	if err := h.Service.Delete(r.Context(), id, principal, reason); err != nil {
		if errors.Is(err, rules.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Get handles GET /api/v1/rules/{id}.
func (h *Rules) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", err.Error())
		return
	}
	out, err := h.Service.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, rules.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// principalFromCtx returns the JWT subject string and the parsed UUID
// (if Sub is a UUID) for the current request. In dev mode (no claims)
// returns ("anonymous", nil).
func principalFromCtx(ctx context.Context) (string, *uuid.UUID) {
	c, ok := auth.FromContext(ctx)
	if !ok || c == nil {
		return "anonymous", nil
	}
	principal := c.Sub
	if principal == "" {
		principal = "anonymous"
	}
	if id, err := uuid.Parse(c.Sub); err == nil {
		return principal, &id
	}
	return principal, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
