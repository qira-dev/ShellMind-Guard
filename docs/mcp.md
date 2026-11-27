# ShellMind Guard MCP Server (`smg mcp`)

`smg mcp` exposes ShellMind Guard's deterministic 18-language security verifier to AI coding agents (Claude Code, Cursor, Windsurf, AntiGravity) over stdio JSON-RPC 2.0 (`2024-11-05` & `2025-03-26`).

## Security Defaults (`v1.6.0`)
- **Strictly Read-Only by default:** Only `shellmind_guard_scan` and `shellmind_guard_explain_finding` are exposed, both marked `annotations.readOnlyHint: true`.
- **Explicit write opt-in:** `shellmind_guard_init` requires starting the server with `smg mcp --allow-write`.
- **No executable git hooks over MCP:** Installing `.git/hooks/pre-commit` over MCP is permanently disabled. Run `smg hook install` directly in your terminal.
- **Prompt-injection & token safety:** Returned source snippets are redacted for live credentials (`sk_live_****abcd`), stripped of control/Bidi characters, and wrapped in `<untrusted_source_snippet>` delimiters within a 32 KiB envelope cap.

## Quick Setup (Copy-Paste Config)
Generate a ready-to-use read-only snippet without modifying your home directory:

```bash
smg mcp --print-config claude
smg mcp --print-config cursor
smg mcp --print-config windsurf
smg mcp --print-config antigravity
```
