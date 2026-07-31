use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// SecurityEvent
// ---------------------------------------------------------------------------

/// A structured security audit event delivered to the CITADEL governance
/// platform by `APIGuard` or NIS2 Compass.
///
/// Events are chained together via SHA-256 hash links to form a tamper-evident
/// WORM audit log.  The ``chain_hash`` of event *N* is computed as:
///
/// ```text
/// SHA-256(events[N-1].chain_hash || events[N].payload_bytes)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier (UUID string).
    pub id: String,

    /// Dot-separated event type, e.g. ``"apiguard.scan.completed"``.
    pub event_type: String,

    /// Originating platform: ``"apiguard"`` or ``"nis2compass"``.
    pub source: String,

    /// Identity of the actor that caused the event.
    pub actor_id: String,

    /// Class of actor: ``"api_key"`` or ``"system"``.
    pub actor_type: String,

    /// Kind of resource the event relates to (e.g. ``"scan"``, ``"control"``).
    pub resource_type: String,

    /// Identifier of the specific resource instance.
    pub resource_id: String,

    /// Event severity: ``"info"``, ``"warning"``, or ``"critical"``.
    pub severity: String,

    /// Arbitrary structured payload specific to the event type.
    pub payload: Value,

    /// Chain hash of the immediately preceding event in the WORM log.
    /// ``None`` for the first event in the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,

    /// SHA-256 hash linking this event into the audit chain.
    pub chain_hash: String,

    /// UTC timestamp at which the event was produced.
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// GetEventsOptions
// ---------------------------------------------------------------------------

/// Optional filter and pagination parameters for
/// [`CITADELClient::get_events`](super::CITADELClient::get_events).
#[derive(Debug, Clone, Default)]
pub struct GetEventsOptions {
    /// Filter by originating platform (``"apiguard"`` or ``"nis2compass"``).
    pub source: Option<String>,

    /// Filter by event type string (e.g. ``"apiguard.scan.completed"``).
    pub event_type: Option<String>,

    /// Return only events at or after this timestamp.
    pub since: Option<DateTime<Utc>>,

    /// Return only events at or before this timestamp.
    pub until: Option<DateTime<Utc>>,

    /// Maximum number of events to return (server default when ``None``).
    pub limit: Option<u32>,

    /// 1-based page number (server default 1 when ``None``).
    pub page: Option<u32>,
}

impl GetEventsOptions {
    /// Convert to query-parameter key/value pairs.
    pub(super) fn to_query_params(&self) -> Vec<(&'static str, String)> {
        let mut params = Vec::new();
        if let Some(ref s) = self.source {
            params.push(("source", s.clone()));
        }
        if let Some(ref et) = self.event_type {
            params.push(("event_type", et.clone()));
        }
        if let Some(since) = self.since {
            params.push(("since", since.to_rfc3339()));
        }
        if let Some(until) = self.until {
            params.push(("until", until.to_rfc3339()));
        }
        if let Some(limit) = self.limit {
            params.push(("limit", limit.to_string()));
        }
        if let Some(page) = self.page {
            params.push(("page", page.to_string()));
        }
        params
    }
}

// ---------------------------------------------------------------------------
// Paginated response envelope (internal)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum EventsResponse {
    /// Plain JSON array: ``[{...}, ...]``
    Array(Vec<SecurityEvent>),
    /// Paginated envelope: ``{"items": [...]}`` or ``{"data": [...]}``
    Envelope(EventsEnvelope),
}

#[derive(Debug, Deserialize)]
pub(super) struct EventsEnvelope {
    #[serde(alias = "data")]
    pub items: Vec<SecurityEvent>,
}
