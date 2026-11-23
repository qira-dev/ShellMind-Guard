# Security Policy & Sandbox Isolation Model

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `1.4.x` | :white_check_mark: |
| `0.4.x` | :white_check_mark: |
| `<= 0.3.x` | :x: |

---

## Security & Isolation Guarantees of ShellMind Guard

ShellMind Guard is designed to analyze untrusted or AI-generated codebases safely on developer workstations and CI runners:

### 1. Offline-First Static Mode (`shellmind-guard index` / `shellmind-guard scan`)
- Static indexing and Guard-Set Lattice analysis operate **100% offline** by default with zero telemetry.
- Dependency and lockfile auditing (`crates/smg-graph/src/deps.rs`) uses an embedded deterministic advisory table offline; outbound OSV advisory sync occurs **only** when explicitly requested via `shellmind-guard deps-sync` or `--online-osv`.
- Live dynamic audit subcommands (`tls`, `idor`, `templates`, `oob`, `sqli`, `dast`, `proxy`, `http-audit`) are opt-in, enforce loopback-only by default (unless `--allow-remote` is explicitly passed), and unconditionally deny cloud metadata / link-local IMDS addresses (`169.254.169.254`, `fe80::/10`, etc.) on final resolved destinations.
- The optional AI patch prompt builder (`crates/smg-ai`) is **disabled by default** and never transmits source code over the network unless explicitly invoked with `--patch` and an operator-configured provider.

### 2. OS-Isolated Bubblewrap Sandbox (`--boot-cmd`)
When `--boot-cmd` is supplied to `shellmind-guard scan`, `shellmind-guard replay`, or `shellmind-guard ui`, ShellMind Guard executes the target server inside `/usr/bin/bwrap` (`crates/smg-sandbox/src/bwrap.rs`) with strict Linux namespace isolation:
- **Namespace Unsharing:** `--unshare-all` (unshares `user`, `ipc`, `pid`, `net`, `uts`, and `cgroup` namespaces).
- **Read-Only Root & Project Mounts:** System libraries (`/usr`, `/lib`, `/lib64`, `/bin`, `/etc/alternatives`) and the target project directory are mounted `--ro-bind` (read-only). Host credentials (`~/.ssh`, `~/.aws`, `~/.config`, host `.env` files outside the target directory) are never mounted inside the namespace.
- **Ephemeral Writable Overlays:** `/tmp` and runtime cache directories are backed by isolated in-memory `--tmpfs` mounts that vanish immediately on teardown.
- **Resource & Process-Group Containment:** Child processes run in a dedicated process group (`process_group(0)`) with `--die-with-parent`, optional virtual-memory ceilings via `--sandbox-mem-mb` (plus optional cgroup v2 limits via `--cgroup-v2`), and deterministic `SIGKILL` process-group reaping (`kill(-pgid, SIGKILL)`) on `Drop` or `SIGINT`.
- **Fail-Closed Default:** If `/usr/bin/bwrap` is unavailable or unprivileged user namespaces are disabled by kernel policy, ShellMind Guard **refuses** to run `--boot-cmd` on the host unless the operator explicitly passes `--unsafe-host-fallback`.

---

## Reporting a Vulnerability

If you discover a security issue in ShellMind Guard itself (for example, a sandbox escape in `smg-sandbox`, a parser memory-safety issue, or a command-injection vector in CLI/MCP argument handling):

1. **Do not open a public GitHub issue** for exploitable vulnerabilities.
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/qira-dev/ShellMind-Guard/security/advisories/new) on `qira-dev/ShellMind-Guard`.
3. Include a minimal reproduction (`shellmind-guard` command, platform/`uname -a`, and sample input).

We aim to acknowledge reports within **48 hours** and publish a verified fix and advisory within **7 days**.
