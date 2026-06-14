# SDK Migration Guide

---

## v0.1.x (current)

Initial release. No migration required.

---

## Upcoming: v0.2.0

The following breaking changes are planned for v0.2.0. This section will be updated when v0.2.0 is released.

### APIGuard client — `StartScan` signature change

`StartScanRequest.SpecURL` will become `StartScanRequest.Spec` accepting either a URL or an inline spec string. The `SpecURL` field will remain as an alias until v0.3.0.

### NIS2Compass client — `PatchControl` evidence refs

`PatchControlRequest.EvidenceRefs` will change from `[]string` to `[]EvidenceRef` to support typed evidence references (hash + label). The `[]string` form will remain as a convenience constructor.

### CITADEL client — Kerkese v2.1

Kerkese v2.1 will add an optional `tags` field on the `Action` struct. Existing Kerkese v2.0 submissions will continue to work.

---

## Migrating Between Go Module Versions

```bash
# Update to latest
go get github.com/opensecstack/sdk/go/opensecstack@latest

# Pin to a specific version
go get github.com/opensecstack/sdk/go/opensecstack@v0.1.3
```

## Migrating Between Python Package Versions

```bash
pip install --upgrade opensecstack

# Pin to a specific version
pip install "opensecstack==0.1.3"
```

---

## Contract Compatibility

The SDK follows these compatibility rules:

| Change type | Version bump |
|-------------|-------------|
| New optional field added to a contract | Patch (0.x.y → 0.x.z) |
| New required field added to a contract | Minor (0.x.y → 0.y.0) |
| Field renamed or removed | Major (0.x.y → 1.0.0 or new minor) |
| New event type added | Patch |
| Existing event type payload changed | Minor |

Consumers must handle unknown fields gracefully (ignore extra JSON keys). This is the default behaviour in Go (`json.Unmarshal`) and Python dataclasses with `dacite`.
