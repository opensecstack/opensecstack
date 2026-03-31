# Releasing the TypeScript SDK

## Package information

The npm package is declared in `sdk/typescript/package.json`:

```
@opensecstack/sdk
```

Consumers install as:

```bash
npm install @opensecstack/sdk
```

## Tag format

npm release tags for this mono-repo must be prefixed with `sdk/typescript/` so
that the CI workflow (`sdk-typescript-publish.yml`) fires:

```
sdk/typescript/v0.2.0
```

The version segment (`v0.2.0`) must follow [Semantic Versioning](https://semver.org/).

## Step-by-step release

1. Bump the version in `sdk/typescript/package.json`.
2. Update `CHANGELOG.md` (in `sdk/typescript/` or `sdk/`) with the new version and date.
3. Commit the changes:
   ```sh
   git add sdk/typescript/package.json sdk/CHANGELOG.md
   git commit -m "chore(ts-sdk): prepare release v0.2.0"
   ```
4. Create and push the tag:
   ```sh
   git tag sdk/typescript/v0.2.0
   git push origin sdk/typescript/v0.2.0
   ```
5. The `sdk-typescript-publish.yml` workflow will:
   - Run `npm ci && npm test && npm run typecheck`
   - Build with `npm run build`
   - Publish to npm with `NPM_TOKEN` secret

## Verifying the release

```bash
npm info @opensecstack/sdk versions
npm install @opensecstack/sdk@0.2.0
```

## Patching a past release

Create a patch branch from the tag, apply fixes, then tag a patch version:

```sh
git checkout -b release/ts/v0.2.x sdk/typescript/v0.2.0
# ... apply fixes ...
git tag sdk/typescript/v0.2.1
git push origin sdk/typescript/v0.2.1
```
