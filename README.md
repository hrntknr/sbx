# sbx

Run a command inside a configurable sandbox.

- **macOS**: backed by `sandbox-exec` (seatbelt)
- **Linux**: backed by `bwrap` (bubblewrap)
- **Optional**: in-process Kubernetes, Docker, and SSH proxies that keep host credentials outside the sandbox

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
  - allow(rw, ~/.claude)
  - allow(rw, ~/.claude.json)
  - allow(rw, ~/.codex)
  - deny(rw, ~/.ssh)
  - deny(rw, ~/.docker)
  - deny(rw, /var/run/docker.sock)
  - deny(rw, ~/.kube/config)
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
| `--docker` / `--no-docker` | Enable/disable the Docker proxy (overrides profile) |

## Config

Multi-document YAML; each document is one profile.

```yaml
name: default
rules:
  - allow(rw, ${WORK_DIR})
  - allow(rw, ~/.claude)
  - allow(rw, ~/.claude.json)
  - allow(rw, ~/.codex)
  - deny(rw, ~/.ssh)
  - deny(rw, ~/.docker)
  - deny(rw, /var/run/docker.sock)
  - deny(rw, ~/.kube/config)
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
name: docker
docker: true # Enable Docker proxy
rules:
  - allow(rw, ${WORK_DIR})
  - deny(rw, ~/.docker) # Deny Docker credentials
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

When `k8s` is set on a profile (either `k8s: true` or a rule list), sbx starts a localhost HTTP proxy in front of the upstream Kubernetes API server(s) and writes a kubeconfig pointing at it. `KUBECONFIG` is set inside the sandbox, and the kubeconfig directory is auto-allowed for read. Empty rules means every source context is exposed read/write.

```yaml
k8s:
  - allow(r, prod-*)           # context globs; r blocks mutating requests
  - allow(rw, dev)
  - deny(rw, *)
```

### docker

When `docker` is set on a profile (either `docker: true` or a rule list), sbx starts a Docker API proxy and writes a temporary `DOCKER_CONFIG` with one generated context per allowed source context. `DOCKER_CONFIG` is set inside the sandbox, and `DOCKER_HOST` / `DOCKER_CONTEXT` are cleared. The generated config/proxy directory is auto-allowed read/write. `~/.docker` and upstream Docker socket paths are not auto-denied; hide them with normal sandbox rules if needed.

Supported source context endpoints:

- `unix://...`
- `tcp://...`
- `http://...`

Unsupported source context endpoints:

- TLS contexts, including `DOCKER_TLS_VERIFY` / `DOCKER_CERT_PATH`
- `ssh://...`

Empty rules expose every supported context read/write, current context first. Docker's built-in `default` context is exposed as `sbx-default` inside the sandbox to avoid Docker CLI's special handling of `default`. If `DOCKER_HOST` is not set outside the sandbox, this default context points at Docker's usual `unix:///var/run/docker.sock` endpoint.

```yaml
docker:
  - allow(r, prod-*)           # context globs; r blocks mutating requests and archive/export reads
  - allow(rw, dev)
  - deny(rw, *)
```

`r` mode is only supported for `unix://` contexts. TCP Docker daemons are reachable over the host network, and sbx does not currently isolate network egress, so a sandboxed process could bypass the proxy by connecting to the TCP daemon directly. Use `rw` for `tcp://` / `http://` contexts only when that direct access is acceptable.

Docker access is powerful. `rw` mode delegates Docker daemon permissions to the sandboxed command, and Docker can bypass filesystem sandboxing by design. For example, a command may create a container with host bind mounts such as `-v /:/host` or `-v ~/.ssh:/x`, depending on the daemon's own permissions. `docker.sock:ro` is not a read-only Docker permission boundary; read-only behavior is enforced only by the sbx Docker proxy.

In `r` mode, sbx blocks mutating HTTP methods and known file/interactive read endpoints such as container archive/export, image export, attach, and exec. It should be treated as a practical Docker API filter, not as a complete data-loss-prevention boundary: existing container metadata, logs, environment, and image/container state visible through allowed read APIs may still contain secrets.

### ssh

When `ssh` is set on a profile (either `ssh: true` or a rule list), sbx starts a local SSH MITM proxy and injects a dummy `ssh` command at the front of `PATH`. The dummy command always runs OpenSSH with an sbx-managed ssh config that connects to the local proxy and passes the original target through `SetEnv`. `SSH_AUTH_SOCK` is cleared inside the sandbox. Private keys, ssh-agent sockets, and the outer ssh config are not auto-denied; hide them with normal sandbox rules if needed.

The proxy resolves the real destination with the outer OpenSSH config, checks the resolved host against the host rules, then runs the outer `ssh` with `BatchMode=yes`. If a passphrase/password prompt would be required, the connection fails; unlock keys with `ssh-add` before running sbx.

```yaml
ssh:
  - allow(github.com)          # resolved HostName patterns; empty = all hosts
  - allow(*.example.com)
  - deny(*)
```
