# RFC-0001: Plugin Architecture for OWASP Modules

- **Status**: DRAFT
- **Created**: 2026-03-30
- **Author**: opensecstack contributors

---

## Summary

Proposes a plugin architecture for APIGuard's OWASP scanning modules. The goal is to allow community-contributed modules, enterprise-specific checks, and module updates without recompiling the core binary.

---

## Motivation

Currently all 10 OWASP modules are compiled into the APIGuard binary. This creates three problems:

1. **Community extensions** require forking the repository. There is no way to distribute a custom module as a separate artefact.
2. **Enterprise-specific checks** (e.g. organisation-specific auth patterns, internal API conventions) cannot be added without maintaining a fork.
3. **Module updates** require a full APIGuard release even for changes isolated to a single module.

The custom rules system (YAML-based) partially addresses problem 3 for simple checks, but cannot express the full power of a module (multi-step test logic, stateful HTTP sequences, custom evidence generation).

---

## Proposed Design

### Module Interface

Define a stable Go interface that all modules must implement:

```go
// Module is the interface that all APIGuard OWASP scanning modules implement.
// The interface version is part of the APIGuard compatibility contract.
// Breaking changes to this interface increment the major version.
type Module interface {
    // Name returns the module's unique identifier (e.g. "a1_bola").
    Name() string

    // OWASPCategory returns the OWASP API Top 10 category (e.g. "API1:2023").
    OWASPCategory() string

    // Description returns a one-line human-readable description of what the module tests.
    Description() string

    // Run executes the module against the target and returns findings.
    // ctx carries the scan timeout. The executor handles HTTP transport.
    Run(ctx context.Context, spec *ir.ApiSpec, target string, auth AuthConfig, executor HTTPExecutor) ([]Finding, error)
}
```

### Module Loading

Modules are loaded from three sources, in priority order:

1. **Built-in** — the 10 standard OWASP modules, compiled into the binary. Always present.
2. **External Go plugins** — `.so` shared libraries loaded from `plugins/` directory at startup (Go plugin system).
3. **WASM modules** — `.wasm` files loaded from `plugins/wasm/` directory (future, post-v1.0).

```yaml
# .apiguard.yaml
plugins:
  dir: ./plugins          # loaded at startup
  wasm_dir: ./plugins/wasm
  disabled:
    - a6_business_flow    # disable a built-in if an external module replaces it
```

### Go Plugin Distribution

An external module is a Go plugin compiled with `go build -buildmode=plugin`:

```
plugin-a1-extended/
├── main.go          ← implements Module interface, exports symbol "Module"
├── go.mod           ← pins apiguard-sdk version for the Module interface
└── README.md
```

The exported symbol must be named `Module` and implement the `Module` interface. APIGuard checks the interface version at load time and refuses to load plugins built against an incompatible interface version.

### WASM Module Distribution (Future)

WASM modules enable cross-language plugins and stronger isolation. A WASM module exposes two functions via the WASM component model:

```wit
interface apiguard-module {
  name: func() -> string
  owasp-category: func() -> string
  run: func(spec: string, target: string, auth: string) -> list<finding>
}
```

WASM modules run in a sandboxed runtime (wasmtime) with no filesystem or network access outside the APIGuard executor abstraction. This is a stronger isolation guarantee than Go plugins.

---

## Interface Versioning

The module interface has a version encoded in the `apiguard-sdk` module:

```go
const ModuleInterfaceVersion = 1
```

APIGuard checks that a loaded plugin was compiled against a compatible interface version:

- Same major version → compatible
- Different major version → refuse to load, log error

Plugins must re-compile and re-release when the interface major version changes. Breaking changes to the interface are avoided where possible and announced in advance.

---

## Security Considerations

Go plugins run in the same process as APIGuard with full access to its memory. This is a significant trust decision. Recommended policy: only load plugins from known sources, verify plugin checksums before deployment.

WASM modules (future) address this — they run in an isolated runtime with explicit capability grants. The long-term direction is WASM plugins with Go plugins supported for the transition period.

---

## Open Questions

1. **Distribution mechanism**: Should opensecstack host an official plugin registry, or leave distribution to plugin authors (GitHub releases)?
2. **Go plugin stability**: The Go plugin system has known limitations (plugins must be built with the exact same Go version and module graph as the host). Is this acceptable, or should we move directly to WASM without Go plugin support?
3. **Module signing**: Should APIGuard verify a signature on external plugins before loading? If yes, whose key?
4. **Interface stability guarantee**: How many releases of advance notice before breaking the interface major version?

---

## Alternatives Considered

- **YAML-only custom rules**: Already exists. Not expressive enough for complex multi-step module logic.
- **HTTP sidecar modules**: Modules run as separate HTTP servers, APIGuard calls them via a local API. Strong isolation but adds latency and deployment complexity.
- **Process-per-module**: Spawn a subprocess per module (like the Rust parser). Works but makes module distribution complex (users must install separate binaries for each module).
