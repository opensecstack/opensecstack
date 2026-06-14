# ADR-003: Deliver lab terminal access via WebSocket browser terminal

## Status
Accepted

## Context
Students working through CyberPath labs need interactive shell access to their lab containers to run commands, observe output, and complete challenges. The key constraint is that students should not need to install any local tooling — the platform must work from a browser alone. Four approaches were evaluated:

- **SSH client instructions**: requires students to install an SSH client, manage keys or passwords, and configure port forwarding. Incompatible with the zero-install goal and impractical in managed or restricted environments.
- **Wetty / ttyd**: proven open-source browser SSH/terminal proxies. Both work well but introduce an additional process dependency, expose an HTTP service per container, and require integration work to tie session lifecycle to CyberPath's lab model.
- **VS Code Server**: rich editing environment but heavyweight for the typical lab interaction pattern (CLI commands, not file editing). Startup overhead and resource consumption are disproportionate.
- **Custom WebSocket terminal**: a WebSocket endpoint in the CyberPath backend attaches a PTY directly to the running lab container. The browser frontend connects over the existing WebSocket infrastructure. No additional port exposure on containers is needed.

A custom implementation adds development effort but gives CyberPath full control over session lifecycle, authentication, and resize behavior without external process dependencies.

## Decision
CyberPath implements a WebSocket-based browser terminal. The backend component (`internal/labs/terminal.go`) opens a PTY attached to the target lab container via the Docker API and bridges it to the WebSocket connection. Terminal resize events sent by the client are forwarded to the PTY using `TIOCSWINSZ`. The frontend component (`BrowserTerminal.tsx`) renders the terminal using xterm.js and manages WebSocket lifecycle. No SSH daemon runs inside lab containers; there is no externally exposed SSH or terminal port.

## Consequences
- Lab containers do not expose SSH or any additional port, reducing the attack surface of the lab network.
- Terminal session lifetime is coupled to lab lifecycle; when a lab is stopped the WebSocket is closed cleanly by the server, preventing orphaned sessions.
- The reverse proxy in front of CyberPath must support WebSocket upgrades; this is documented as a deployment requirement (nginx `proxy_pass` with `Upgrade` and `Connection` headers).
- PTY management adds implementation complexity: resize events must be correctly forwarded, terminal encoding must be handled consistently, and the backend must detect container exit and propagate it to the client.
- Students access a fully functional terminal in-browser with no local setup, meeting the zero-install goal.
