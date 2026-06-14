# VertGuard API

Authoritative OpenAPI 3.1 spec for the VertGuard HTTP API lives in
[`openapi.yaml`](./openapi.yaml). The TypeScript client at
`web/src/lib/api-generated.ts` is generated from it — do not hand-edit.

## View the spec

Pick whichever you prefer:

```bash
# Swagger UI (Docker)
docker run --rm -p 8080:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v "$PWD/api:/spec" \
  swaggerapi/swagger-ui
# → http://localhost:8080

# Redoc (one-shot static HTML)
npx --yes @redocly/cli@latest preview-docs api/openapi.yaml

# Lint
npx --yes @redocly/cli@latest lint api/openapi.yaml
```

## Regenerate the TypeScript client

The `web/` workspace exposes two scripts:

```bash
cd web
npm run api:generate   # writes web/src/lib/api-generated.ts
npm run api:check      # CI mode: fails if the file would change
```

Both delegate to [`scripts/gen-ts-client.sh`](./scripts/gen-ts-client.sh),
which runs `openapi-typescript` via `npx`. The CI job `openapi-check`
runs `api:check` on every PR, so spec edits without a regenerated client
will fail the build.

## Editing checklist

1. Update `openapi.yaml`.
2. Run `npm run api:generate` from `web/`.
3. Commit both files together.
4. If you added a route, also update the route table in
   `internal/api/server.go` and the role guards in `internal/auth/`.
