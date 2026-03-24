# IDE Setup Guide

## VS Code (Recommended)

### Dev Container (Fastest)

Open the `opensecstack/` folder in VS Code. Click "Reopen in Container" when prompted. All tools are pre-installed. Done.

### Manual Setup

Install these extensions:

| Extension | ID | Purpose |
|-----------|----|---------|
| Go | `golang.go` | Go language support, debugging, testing |
| rust-analyzer | `rust-lang.rust-analyzer` | Rust language support, completion, clippy |
| Python | `ms-python.python` | Python language support |
| ESLint | `dbaeumer.vscode-eslint` | JavaScript/TypeScript linting |
| Prettier | `esbenp.prettier-vscode` | Code formatting (React/TS) |
| Docker | `ms-azuretools.vscode-docker` | Docker file support |
| Even Better TOML | `tamasfe.even-better-toml` | Cargo.toml support |
| CodeLLDB | `vadimcn.vscode-lldb` | Rust debugging |

### Recommended Settings

Add to `.vscode/settings.json`:

```json
{
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "rust-analyzer.check.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "[go]": { "editor.defaultFormatter": "golang.go" },
  "[rust]": { "editor.defaultFormatter": "rust-lang.rust-analyzer" },
  "[typescript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
  "[typescriptreact]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
  "[python]": { "editor.defaultFormatter": "ms-python.python" }
}
```

### Debug Configurations

Add to `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "APIGuard API",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}/apiguard/cmd",
      "envFile": "${workspaceFolder}/apiguard/.env"
    },
    {
      "name": "Rust Parser Tests",
      "type": "lldb",
      "request": "launch",
      "cargo": {
        "args": ["test", "--package", "parser", "--lib"],
        "filter": { "kind": "lib" }
      },
      "cwd": "${workspaceFolder}/apiguard/rust"
    }
  ]
}
```

## JetBrains (RustRover / GoLand)

### RustRover

1. Open `opensecstack/apiguard/rust/` as a Rust project
2. Install the **Go** plugin for Go code support
3. Configure: Settings → Languages & Frameworks → Rust → Clippy → Enable on save
4. External tools: Add `golangci-lint` as an external tool for Go files

### GoLand

1. Open `opensecstack/apiguard/` as a Go project
2. Install the **Rust** plugin
3. Configure: Settings → Go → Linters → Enable golangci-lint
4. Configure: Settings → Rust → Enable clippy

### Shared JetBrains Settings

- Enable "Format on save" for Go and Rust
- Database tool: Connect to `localhost:5432` with credentials from `.env`
- Docker integration: Connect to local Docker daemon
