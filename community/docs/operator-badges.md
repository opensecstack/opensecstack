# Platform Operator Badges

Users can set a `platform_badge` on their profile to show which opensecstack platform they operate.

Recognised values (displayed as pills on posts):
- `opencsirt` — OpenCSIRT operator
- `apiguard` — APIGuard operator
- `openscrub` — OpenScrub operator
- `securelab` — SecureLab operator
- `threatflow` — ThreatFlow operator
- `irflow` — IRFlow operator
- `nis2compass` — NIS2Compass operator
- `citadel` — CITADEL operator

Set via `PUT /api/v1/users/me` with `{"platform_badge": "opencsirt"}`.
