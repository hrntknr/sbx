# sbx

Run a command inside a configurable sandbox.

- **macOS**: backed by `sandbox-exec` (seatbelt)
- **Linux**: backed by `bwrap` (bubblewrap)
- **Optional**: an in-process Kubernetes API proxy that exposes a filtered kubeconfig to the sandboxed command

## Install

```sh
go install github.com/hrntknr/sbx@latest
```

## Usage

```sh
sbx -- <command> [args...]
sbx --profile k8s -- kubectl get pods
sbx --dump -- <command>          # print the generated sandbox spec and exit
```

Config is loaded from `--config PATH`, `./sbx.yaml`, or `~/.sbx.yaml` (in that order). Profile defaults to `default`. If no config file is found, a built-in default profile is used:

```yaml
name: default
k8s: true
rules:
  - allow(rw, ${WORK_DIR})
  - allow(r, /)
```

The system tmp paths (`/tmp` / `/private/tmp` and `$TMPDIR`) are always allowed read/write — you do not need to list them. A user `deny` rule on those paths still wins.

### Flags

| Flag                 | Description                                      |
| -------------------- | ------------------------------------------------ |
| `-C, --config PATH`  | Config file path                                 |
| `-c, --command CMD`  | Command string to run inside the sandbox         |
| `--profile NAME`     | Profile name (default: `default`)                |
| `--k8s` / `--no-k8s` | Enable/disable the k8s proxy (overrides profile) |
| `--k8s-config PATH`  | Override kubeconfig path                         |
| `--k8s-context CTX`  | Override contexts (comma-separated, repeatable)  |
| `--k8s-mode rw\|ro`  | `ro` rejects POST/PUT/PATCH/DELETE at the proxy  |

## Config

Multi-document YAML; each document is one profile.

```yaml
name: default
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ~/.claude)
  - allow(rw, ~/.claude.json)
  - allow(rw, ~/.codex)
  - allow(r, /)
---
name: k8s
k8s: true # Enable k8s proxy
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ~/.claude)
  - allow(rw, ~/.claude.json)
  - allow(rw, ~/.codex)
  - deny(rw, ~/.kube/config) # Deny Kubernetes secrets
  - allow(r, /)
---
name: hide-secret
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ~/.claude)
  - allow(rw, ~/.claude.json)
  - allow(rw, ~/.codex)
  - deby(rw, ~/.*) # Deny secret files
  - allow(r, /)
```

### Rules

`ACTION(MODE, PATH)` where `ACTION` is `allow` or `deny`, `MODE` is `r`, `w`, or `rw`.

`PATH` supports `~`, `${VAR}`, and the built-ins `${WORK_DIR}` (cwd) and `${HOME}`. Custom variables can be defined under `env:` and are also exported into the sandboxed command's environment.

### k8s

When `k8s` is set on a profile (either `k8s: true` or a mapping), sbx starts a localhost HTTP proxy in front of the upstream Kubernetes API server(s) and writes a kubeconfig pointing at it. `KUBECONFIG` is set inside the sandbox, and the kubeconfig directory is auto-allowed for read.

```yaml
k8s:
  config: ~/.kube/config       # source kubeconfig (default: $KUBECONFIG / ~/.kube/config)
  context: ["prod-*", "stg"]   # context names or globs; empty = all contexts
  mode: ro                     # If set to `ro`, it will be limited to read-only APIs such as `kubectl get`.
```
