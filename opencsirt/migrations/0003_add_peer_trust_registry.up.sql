-- OpenCSIRT v1.0.0 — add trust, registry, and ed25519_fingerprint to peer_csirts.

ALTER TABLE peer_csirts
    ADD COLUMN registry text NOT NULL DEFAULT 'other'
        CHECK (registry IN ('first', 'tf-csirt', 'csirts-network', 'other')),
    ADD COLUMN trust text NOT NULL DEFAULT 'pending'
        CHECK (trust IN ('verified', 'pending', 'failed', 'expired')),
    ADD COLUMN ed25519_fingerprint text NOT NULL DEFAULT '';
