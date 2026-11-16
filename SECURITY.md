# Security Policy & Sandbox Isolation Model

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `0.1.x` | :white_check_mark: |

---

## Security & Isolation Guarantees of ShellMind Guard

ShellMind Guard is designed to analyze untrusted or AI-generated codebases safely on developer workstations and CI runners:

### 1. Zero Network & Zero Telemetry in Static Mode (`shellmind-guard index` / `shellmind-guard scan`)
- Static indexing and 6-layer Guard-Set Lattice analysis operate **100% offline**.
- Dependency and lockfile auditing (`crates/smg-graph/src/deps.rs`) uses an embedded deterministic advisory table and never makes outbound HTTP requests.
- The optional AI patch prompt builder (`crates/smg-ai`) is **disabled by default** and never transmits source code over the network.

### 2. OS-Isolated Bubblewrap Sandbox (`--boot-cmd`)
When `--boot-cmd` is supplied to `shellmind-guard scan`, `shellmind-guard replay`, or `shellmind-guard ui`, ShellMind Guard executes the target server inside `/usr/bin/bwrap` (`crates/smg-sandbox/src/bwrap.rs`) with strict Linux namespace isolation:
- **Namespace Unsharing:** `--unshare-all` (unshares `user`, `ipc`, `pid`, `net`, `uts`, and `cgroup` namespaces).
- **Read-Only Root & Project Mounts:** System libraries (`/usr`, `/lib`, `/lib64`, `/bin`, `/etc/alternatives`) and the target project directory are mounted `--ro-bind` (read-only). Host credentials (`~/.ssh`, `~/.aws`, `~/.config`, host `.env` files outside the target directory) are never mounted inside the namespace.
- **Ephemeral Writable Overlays:** `/tmp` and runtime cache directories are backed by isolated in-memory `--tmpfs` mounts that vanish immediately on teardown.
- **Resource & Process-Group Containment:** Child processes run in a dedicated process group (`process_group(0)`) with `--die-with-parent`, a 1 GiB virtual memory ceiling (`ulimit -v 1048576`), and deterministic `SIGKILL` process-group reaping (`kill(-pgid, SIGKILL)`) on `Drop` or `SIGINT`.
- **Fail-Closed Default:** If `/usr/bin/bwrap` is unavailable or unprivileged user namespaces are disabled by kernel policy, ShellMind Guard **refuses** to run `--boot-cmd` on the host unless the operator explicitly passes `--unsafe-host-fallback`.

---

## Reporting a Vulnerability

If you discover a security issue in ShellMind Guard itself (for example, a sandbox escape in `smg-sandbox`, a parser memory-safety issue, or a command-injection vector in CLI/MCP argument handling):

1. **Do not open a public GitHub issue** for exploitable vulnerabilities.
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/qira-dev/ShellMind-Guard/security/advisories/new) on `qira-dev/ShellMind-Guard`.
3. Include a minimal reproduction (`shellmind-guard` command, platform/`uname -a`, and sample input).

We aim to acknowledge reports within **48 hours** and publish a verified fix and advisory within **7 days**.
