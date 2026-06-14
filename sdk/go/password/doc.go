// Package password is the OpenSecStack reference implementation of
// password and API-key hashing. It combines:
//
//   - Argon2id (RFC 9106, current PHC winner) as the memory-hard KDF
//   - An HMAC-SHA256 server-side "pepper" applied before Argon2id, so a
//     stolen database alone cannot be brute-forced offline
//   - The standard PHC string format on the wire
//     ($argon2id$v=19$m=N,t=N,p=N$<salt>$<hash>), making stored hashes
//     directly interoperable with libraries in other languages
//
// # Why this and not bcrypt
//
// bcrypt pre-dates GPU-grade brute forcing and is not memory-hard; in 2026
// an off-the-shelf consumer GPU clears a bcrypt(cost=10) dictionary of
// 10^9 words in hours. Argon2id at 64 MiB / t=3 raises the same attack to
// tens of thousands of dollars per password, which is what modern password
// storage should target.
//
// # Why the HMAC pepper
//
// Salting protects users against rainbow-table attacks; the pepper
// protects the whole corpus against offline attacks when the database is
// stolen but the application secret is not (the common real-world breach
// shape). The pepper must be stored outside the database — a secret
// manager, an environment variable with file-mode 0600, or an HSM. Losing
// the pepper invalidates every stored hash, so rotate carefully.
//
// # Basic usage
//
//	h, err := password.NewHasher(os.Getenv("APIKEY_PEPPER"))
//	if err != nil { log.Fatal(err) }
//
//	encoded, err := h.Hash("alice-s3cr3t")
//	// store `encoded` in the DB
//
//	ok, err := h.Verify("alice-s3cr3t", encoded)
//	// ok == true when the password matches
//
//	if ok && h.NeedsRehash(encoded) {
//	    // params were weaker than current config — rewrite the stored hash
//	    newEncoded, _ := h.Hash("alice-s3cr3t")
//	    _ = db.UpdateAPIKeyHash(userID, newEncoded)
//	}
//
// # Cost tuning
//
// Default() returns the OWASP 2024 recommended profile (64 MiB, t=3, p=1),
// which costs ~50 ms on a modern server CPU. Most API servers running
// Argon2id only on authentication paths can absorb this without trouble.
// Call Benchmark() at startup in your own test harness if you need to
// validate the cost on a specific host.
package password
