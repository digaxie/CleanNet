# Linux Release

Build:

```bash
scripts/build_linux_release.sh
```

Verify:

```bash
scripts/verify_linux_release.sh
```

Expected outputs:

- `dist/cleannet-linux-<version>.tar.gz`
- `dist/SHA256SUMS.txt`

Release archives must not contain `.venv`, `build`, cached bytecode, runtime logs/state, Windows scripts, installers, or binaries.
