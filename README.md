# sbx

Run a command inside a configurable sandbox.

- **macOS**: backed by `sandbox-exec` (seatbelt)
- **Linux**: backed by `bwrap` (bubblewrap)
- **Optional**: in-process Kubernetes and SSH proxies that keep host credentials outside the sandbox

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
| `-c, --config PATH`  | Config file path                                 |
| `--profile NAME`     | Profile name (default: `default`)                |
| `--k8s` / `--no-k8s` | Enable/disable the k8s proxy (overrides profile) |
| `--ssh` / `--no-ssh` | Enable/disable the ssh proxy (overrides profile) |

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

When `k8s` is set on a profile (either `k8s: true` or a mapping), sbx starts a localhost HTTP proxy in front of the upstream Kubernetes API server(s) and writes a kubeconfig pointing at it. `KUBECONFIG` is set inside the sandbox, and the kubeconfig directory is auto-allowed for read. Empty `rules` means every source context is exposed read/write.

```yaml
k8s:
  rules:
    - allow(r, prod-*)         # context globs; r blocks mutating requests
    - allow(rw, dev)
    - deny(rw, *)
```

### ssh

When `ssh` is set on a profile (either `ssh: true` or a mapping), sbx starts a local SSH MITM proxy and injects a dummy `ssh` command at the front of `PATH`. The dummy command always runs OpenSSH with an sbx-managed ssh config that connects to the local proxy and passes the original target through `SetEnv`. The sandbox does not need access to private keys, ssh-agent sockets, or the outer ssh config.

The proxy resolves the real destination with the outer OpenSSH config, checks the resolved host against the host rules, then runs the outer `ssh` with `BatchMode=yes`. If a passphrase/password prompt would be required, the connection fails; unlock keys with `ssh-add` before running sbx.

```yaml
ssh:
  rules:
    - allow(github.com)        # resolved HostName patterns; empty = all hosts
    - allow(*.example.com)
    - deny(*)
```
