# sbx

Run a command inside a configurable sandbox.

- **macOS**: backed by `sandbox-exec` (seatbelt)
- **Linux**: backed by `bwrap` (bubblewrap)
- **Optional**: an in-process Kubernetes API proxy that exposes a filtered kubeconfig to the sandboxed command

## Install

```sh
go install github.com/hrntknr/sbx/cmd/sbx@latest
```

## Usage

```sh
sbx -- <command> [args...]
sbx --profile k8s -- kubectl get pods
sbx --dump -- <command>          # print the generated sandbox spec and exit
```

Config is loaded from `--config PATH`, `./sbx.yaml`, or `~/.sbx.yaml` (in that order). Profile defaults to `default`.

### Flags

| Flag | Description |
| --- | --- |
| `-c, --config PATH` | Config file path |
| `--profile NAME` | Profile name (default: `default`) |
| `--k8s` / `--no-k8s` | Enable/disable the k8s proxy (overrides profile) |
| `--k8s-config PATH` | Override kubeconfig path |
| `--k8s-context CTX` | Override contexts (comma-separated, repeatable) |
| `--k8s-mode rw\|ro` | `ro` rejects POST/PUT/PATCH/DELETE at the proxy |

## Config

Multi-document YAML; each document is one profile.

```yaml
name: default
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ${TMP_DIR})
  - deny(rw, ~/.*)
  - allow(r, /)
---
name: k8s
k8s: true
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ${TMP_DIR})
  - allow(r, ~/.kube/kuberc)
  - deny(rw, ~/.*)
  - allow(r, /)
```

### Rules

`ACTION(MODE, PATH)` where `ACTION` is `allow` or `deny`, `MODE` is `r`, `w`, or `rw`.

`PATH` supports `~`, `${VAR}`, and the built-ins `${WORK_DIR}` (cwd), `${TMP_DIR}`, `${HOME}`. Custom variables can be defined under `env:` and are also exported into the sandboxed command's environment.

### k8s

When `k8s` is set on a profile (either `k8s: true` or a mapping), sbx starts a localhost HTTP proxy in front of the upstream Kubernetes API server(s) and writes a kubeconfig pointing at it. `KUBECONFIG` is set inside the sandbox, and the kubeconfig directory is auto-allowed for read.

```yaml
k8s:
  config: ~/.kube/config       # source kubeconfig (default: $KUBECONFIG / ~/.kube/config)
  context: ["prod-*", "stg"]   # context names or globs; empty = all contexts
  mode: ro                     # rw (default) or ro
```
