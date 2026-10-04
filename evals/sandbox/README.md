# Sandbox evaluation (v2 research, not a shipped feature)

Question: can this skill safely *run* a suspect artifact's scripts and watch
what they do, and does [Harbor](https://github.com/harbor-framework/harbor)
(Apache-2.0) earn its place as the isolation layer?

Everything here is a harmless canary or isolation probe. Samples touch only
fake credential files and `198.51.100.7` (TEST-NET-2, never routable). **No
real malware has been run.** Run the whole thing with the `sandbox-eval`
workflow (manual dispatch). It needs Docker, which the author's machine
lacks, so results come from GitHub's ubuntu runner (Docker 28, kernel 6.17).

## What was measured

### 1. Network containment (requires a real HTTP response, not a TCP handshake)

| Mode | Host listener | Internet | DNS | ICMP |
|---|---|---|---|---|
| `docker run --network none` | no route | blocked | fails | no route |
| `--internal` network | **reached (HTTP 200)** | blocked | fails | **reply** |
| bridge (control) | reached | reached | resolves | reply |
| Harbor default `no-network` | handshake only, no response | handshake only, no response | **resolves public names** | **reply** |
| Harbor + task-authored compose overlay (`network_mode: none`) | no route | blocked | fails | no route |

- `--internal` is **not** safe for suspect code: it can reach the host.
- Harbor's stock `no-network` blocks application TCP, but DNS resolution and
  ICMP still work, so DNS exfiltration is possible. It is a transparent-proxy
  egress sidecar, not `--network none`.
- A task can ship its own `environment/docker-compose.yaml`. Doing that with
  `network_mode: none` restores full containment under Harbor (last row).

**Retraction.** Midway through I told the user Harbor's `no-network` gave "no
network isolation at all". That was wrong: I counted the sidecar's local TCP
handshake as reachability. The corrected finding is the table above.

### 2. Behavioral analysis (strace, analyzed by `monitor/analyze_trace.py`)

| Sample | Verdict | Why |
|---|---|---|
| malicious-canary | high | credential read + external connect + persistence + out-of-workspace write |
| evasive-tamper | high | tries to zero its own trace; evidence survives (see 3) |
| evasive-netgated | high / review | only misbehaves if a network interface exists; `review` (environment probe) under `--network none` |
| probe-egress | review | the containment probe itself |
| benign-network | review | DNS lookup attempt |
| evasive-delayed | clean + coverage gap | sleeps past the timeout; reported as a gap, not as safe |
| evasive-argsgated | clean | acts only with `--deploy`; **invisible to dynamic execution** (static analysis is the answer) |
| benign | clean | |

Caveats that matter: these canaries test the *mechanism*, not malware recall.
The analyzer's rules were written after seeing these samples, so detecting
them is not an independent result (the environment-probe rule was added after
seeing `evasive-netgated`, and the DNS-question decoder after `evasive-rawdns`).
`curl`/`wget` hostnames are visible via argv. Hostnames in raw sockets are
decoded from the DNS question in `sendto`/`send`/`write` buffers (`dns-query`
ioc). Writing that sample also exposed a gap: a UDP `sendto()` with an explicit
destination never calls `connect()`, so it was not counted as external at all;
it now is. Decoding covers plain DNS-over-UDP/TCP questions only: not DoH/DoT,
not names split across several packets, not an answer-section channel.

### 3. The tracer can be tampered with

A script running as the same uid as the tracer can truncate its own trace
(observed: ~20 KB of NUL bytes). The fix, verified end to end: the tracer
stays root and the script is dropped to an unprivileged user with
`setpriv --reuid ... --reset-env` (`RUN_AS=sandbox` in
`monitor/run_under_strace.sh`). `strace -u` was not relied on at first because
an earlier run seemed to show it failing. **Re-tested 2026-10-04**
(`monitor/strace_u_diag.sh`, strace 6.13, root tracer, caps SETUID/SETGID/
SYS_PTRACE): `strace -u sandbox` and the `setpriv` drop behave identically.
Both give the tracee uid/gid 1000 with `CapEff=0`, both leave the root-owned
trace intact (truncate refused, 0 NUL bytes), while a plain root tracee
truncates it (103944 NUL bytes). So `-u` does protect the trace when the tracer
is root; the earlier observation is unexplained (most likely that run's tracer
was not root, but that was not reconstructed). Tier 4 keeps `setpriv`: it also
resets the environment and supplementary groups explicitly.

### 4. Harbor itself

- Apache-2.0, 310 MB / 92 packages, 23 s to install in CI. A Harbor run of 7
  tasks took ~144 s vs ~21 s for plain Docker.
- Default container hardening is only cpus and memory. No `cap_drop`,
  read-only root, pids limit, or non-root user unless the task asks.
- **Fails open:** the egress sidecar is enabled only if a kernel-support check
  passes; an exception or timeout in that check silently disables it.
- `/logs` is a host bind mount the suspect can write arbitrary filenames
  into (a literal `*.trace` file broke artifact upload once).
- `harbor run` has `--upload`/`--public`; keep them off.

## Recommendation

- **Script-execution mode (the v2 candidate): do not adopt Harbor.** A thin
  `docker run --network none` wrapper with a root tracer, an unprivileged
  script user, `cap_drop`, `no-new-privileges` and a pids limit is lighter
  (about 7x faster here), gives finer control, and is more clearly contained.
  Harbor adds nothing for this job, and its defaults are weaker.
- **Harbor's real value is agent-in-the-loop prompt-injection testing**
  (agent integrations, trajectories, verifiers). That needs LLM keys and
  cost, and was not run here. If built, use the compose-overlay pattern
  above, and **verify the sandbox before trusting it**: run the containment
  probe inside the same environment and refuse to report if anything gets out.
- **Do not run real malware samples through this** without the owner's
  explicit approval (acceptable-use and container-escape risk).

## Open items

A sinkhole resolver (to observe lookups that actually get answered); the
prompt-injection fuzzing half of the question, which needs a live agent.
Resolved 2026-10-04: DNS-qname decoding (above), the `strace -u` puzzle
(above), and the ICMP row: with a bridge network the probe's ICMP check gets
an echo reply from the host/gateway (the public 1.1.1.1 target never answered
on the runner, which is why the earlier row was inconclusive), and CI requires
that check to fail on the deliberately weakened sandbox, so the ICMP method is
positively controlled.
