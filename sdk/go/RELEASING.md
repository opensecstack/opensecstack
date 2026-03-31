# Releasing the Go SDK

## Module information

The Go module is declared in `sdk/go/go.mod`:

```
module github.com/opensecstack/sdk
```

Consumers import the package as:

```go
import "github.com/opensecstack/sdk/opensecstack"
```

## Tag format

Go module tags for this mono-repo must be prefixed with `sdk/go/` so that the
CI workflow (`sdk-go-publish.yml`) fires and so that the Go module proxy can
resolve the correct version:

```
sdk/go/v0.2.0
```

The version segment (`v0.2.0`) must follow [Semantic Versioning](https://semver.org/).

## Step-by-step release

1. Update `CHANGELOG.md` (in `sdk/go/`) with the new version and date.
2. Commit the changelog update:
   ```sh
   git add sdk/go/CHANGELOG.md
   git commit -m "chore(go-sdk): prepare release v0.2.0"
   ```
3. Create and push the tag:
   ```sh
   git tag sdk/go/v0.2.0
   git push origin sdk/go/v0.2.0
   ```
4. The `sdk-go-publish.yml` workflow will run `go test -race ./...` and
   `go vet ./...` against the tagged commit.
5. Once the tag is visible on GitHub, the Go module proxy (proxy.golang.org)
   will fetch and cache the module automatically. `pkg.go.dev` will index the
   new version within a few minutes.

## Verifying the release

```sh
GONOSUMCHECK=* GOFLAGS=-mod=mod go get github.com/opensecstack/sdk/opensecstack@v0.2.0
```

Or check the proxy directly:

```
https://proxy.golang.org/github.com/opensecstack/sdk/@v/sdk/go/v0.2.0.info
```

## Patching a past release

Create a patch branch from the tag, apply fixes, then tag a patch version:

```sh
git checkout -b release/go/v0.2.x sdk/go/v0.2.0
# ... apply fixes ...
git tag sdk/go/v0.2.1
git push origin sdk/go/v0.2.1
```
