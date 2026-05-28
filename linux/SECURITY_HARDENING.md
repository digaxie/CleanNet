# Security Hardening Notes

- Keep proxy changes user-scoped; do not add sudo-based system proxy writes.
- Preserve proxy backup/restore behavior whenever backend code changes.
- Keep env-file fallback manual; do not modify shell profiles automatically.
- Keep release archives free of runtime state, virtual environments, bytecode, and generated build output.
- Run `scripts/verify_linux_release.sh` before publishing.
