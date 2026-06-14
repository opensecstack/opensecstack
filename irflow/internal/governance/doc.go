// Package governance contains HTTP clients for IRFlow's outbound governance
// integrations: CITADEL (MARSHAL dual-control evaluation and WORM audit
// chain) and NIS2 Compass (Article 23 incident notification).
//
// Each client satisfies an interface defined in the incident package, so the
// incident Service can accept real clients in production and in-memory mocks
// in tests without depending on this package directly.
package governance
