# Browser Terminal

The browser terminal gives learners shell access to a running lab container directly in their browser. It requires no local tooling — no SSH client, no VPN, no Docker installation.

## How It Works

The connection path is:

```
Browser (xterm.js) → WebSocket → CyberPath backend → lab container (exec)
```

The backend WebSocket handler lives in `internal/labs/terminal.go`. When a user opens the terminal panel for an active lab, the frontend component (`web/src/components/BrowserTerminal.tsx`) opens a WebSocket connection to:

```
wss://<host>/api/labs/{session_id}/terminal
```

The backend authenticates the session token from the WebSocket upgrade handshake, resolves the container ID for the given `session_id`, and then streams I/O between the WebSocket and a `docker exec` shell process spawned inside the container. The shell binary is defined in `lab.yaml` under `shell` (defaults to `/bin/sh` if not set).

The WebSocket carries raw terminal bytes framed with a one-byte type prefix:

- `0x01` — stdin/stdout data
- `0x02` — resize event (cols, rows as uint16 pair)
- `0x03` — ping/pong keepalive

## Frontend Component

`web/src/components/BrowserTerminal.tsx` wraps the `xterm.js` terminal emulator and the `xterm-addon-fit` resize addon. Key behaviours:

- On mount, the component opens the WebSocket and attaches xterm to it.
- Resize events from `xterm-addon-fit` are sent as type `0x02` frames.
- On WebSocket close or error, the component shows a reconnect prompt. Automatic reconnect is attempted twice with a 3-second back-off.
- The terminal is destroyed and the WebSocket is closed when the component unmounts (user navigates away).

## Security Considerations

- Lab containers run on an isolated Docker network with no internet egress. A compromised or malicious learner inside the container cannot reach external services.
- The WebSocket endpoint validates the JWT bearer token and confirms the requesting user owns the lab session. Session tokens are short-lived (1 hour, matching the default lab time limit).
- No host filesystem paths are mounted into lab containers.
- `docker exec` runs the shell as a non-root user defined in the image. CyberPath enforces that published lab images must declare a non-root `USER` in their `Dockerfile`; the validator checks this at content review time.
- The Docker socket is accessible only to the CyberPath backend process, not to lab containers.

## Supported Shell Environments

The default shell is `/bin/sh`. Lab authors can override this in `lab.yaml`:

```yaml
shell: /bin/bash
```

Common shells available in official lab images: `/bin/bash`, `/bin/sh`, `busybox sh`. Python or Node interactive REPLs can be used as the shell if the lab requires it. Wasm labs use a virtual shell provided by the PyramidOS runtime; see `wasm-lab-setup.md`.

## Copy/Paste and Resize

- **Copy**: Select text in the terminal; it is automatically copied to the clipboard via the browser Clipboard API (requires HTTPS and user permission).
- **Paste**: `Ctrl+Shift+V` or right-click → Paste. Standard `Ctrl+V` is passed to the terminal as a literal character.
- **Resize**: The terminal resizes automatically when the browser window or the terminal panel is resized. A resize event is sent to the backend, which calls `docker exec` with the updated `TIOCSWINSZ` ioctl so tools like `vim` and `htop` render correctly.

## Troubleshooting Connection Drops

| Symptom | Likely Cause | Fix |
|---|---|---|
| Terminal shows "Connection lost" immediately | Session token expired or lab expired | Re-launch the lab from the module view |
| Terminal connects then freezes | Container OOM killed | Check lab resource limits; reduce memory usage |
| Reconnect attempts fail repeatedly | Backend pod restarted | Wait 10 seconds; the frontend retries automatically |
| Clipboard paste does not work | Browser blocked Clipboard API | Ensure the site is served over HTTPS and clipboard permission is granted |
| Terminal does not resize correctly | xterm-addon-fit not triggered | Manually drag the terminal panel border to trigger a resize event |

Check backend logs (`internal/labs/terminal.go` log lines tagged `terminal`) for `exec` errors when connection issues are hard to diagnose from the UI alone.
