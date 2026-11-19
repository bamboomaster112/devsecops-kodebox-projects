# Project 06: Runtime threat detection with your own Falco

**Tools:** Falco 0.45.2 (modern eBPF, in Docker), custom rules, the hardened app from project 01 &nbsp;|&nbsp; **Time:** 30 to 45 minutes &nbsp;|&nbsp; **Run time:** under a minute

Everything up to project 05 happens before a container starts. Falco watches what a
container actually does once it is running: every process it starts, every file it opens,
every connection it makes, taken straight from the kernel through eBPF. In this project
you write rules for the app from project 01, act like an intruder inside it, and check
that each step raises the alert you expect.

## Before you start: there is already a Falco on this box

KodeKloud runs its own Falco as a system service (`falco-modern-bpf.service`) to protect
the platform. It loads its own rules (crypto miners, reverse shells, internet-wide
scanners, proxies, tunnels, and changes to the platform's own files) and reports to a
KodeKloud agent.

**Leave it alone.** Do not stop it, edit `/etc/falco`, or load kernel modules. This
project runs a **second, independent** Falco in a container that loads only the rules in
`rules/kbx_rules.yaml`, and the simulated attacks are chosen so they never resemble the
behaviours the platform watches for: no reverse shells, no network tools, no mining
ports, nothing written to the host.

## What you will learn

- How Falco rules are built: macros, lists, conditions, output fields and priorities.
- How to scope rules to one workload so they stay quiet everywhere else.
- Fields that matter in practice: `proc.is_exe_upper_layer` (a binary written after the
  container started), `evt.rawres` (the numeric syscall result) and `fd.sip`.
- What changed in Falco 0.45: only exit events are captured, so the classic
  `evt.dir = <` filter is deprecated and no longer needed.
- How to make a detection test reliable instead of flaky.

## Run it

```bash
cd ~/devsecops-kodebox-projects
./06-falco-runtime/falco-up.sh      # start kbx-falco (privileged, host PID, modern eBPF)
./06-falco-runtime/simulate.sh      # start the app, act like an intruder, check the alerts
./06-falco-runtime/falco-up.sh stop
```

## The rules (`rules/kbx_rules.yaml`)

Every rule is limited to containers named `kbx-target*` through one macro:

```yaml
- macro: kbx_target
  condition: (container.id != host and container.name startswith "kbx-target")
```

| Rule | Priority | Fires when | Maps to |
|---|---|---|---|
| KBX Shell Spawned In App Container | WARNING | `sh`, `bash` and similar start in the app container | T1059 |
| KBX Sensitive File Read In App Container | ERROR | `/etc/shadow`, `/etc/gshadow` or `/etc/sudoers` is opened | T1003 |
| KBX Package Manager In App Container | WARNING | `apt`, `dpkg`, `pip` and similar run at runtime | Drift |
| KBX Write Below Binary Dir In App Container | ERROR | A file is opened for writing in `/bin`, `/usr/bin`, `/usr/local/bin`... | T1543 |
| KBX Executable Not In Image | CRITICAL | A program runs whose file was written after the container started | T1204 |
| KBX Unexpected Outbound Connection From App Container | NOTICE | The app opens an outbound IPv4 connection | T1071 |

The image has no shell use, no package installs and no outbound calls in normal
operation, which is what makes these rules precise rather than noisy. That is the payoff
of project 01: a minimal, single-purpose container is easy to watch.

## What `simulate.sh` does

1. Starts `sample-app:after` as `kbx-target` on `127.0.0.1:18000`.
2. **Waits for a canary.** It runs `python -c "'kbx-canary'"` in the container until
   Falco reports the `KBX Canary` rule. Falco learns a new container's name a moment after
   the container starts, and rules that match on `container.name` cannot fire before that.
   Without this step the first attacks were missed in testing; with it, the run passed
   even straight after restarting Falco.
3. Performs six harmless "attacker" actions with `docker exec`:

   | # | Action | Command |
   |---|---|---|
   | 1 | Shell | `sh -c id` |
   | 2 | Read credentials (as root, like after an escalation) | `cat /etc/shadow` |
   | 3 | Package manager | `apt-get --version` |
   | 4 | Persistence attempt | `touch /usr/local/bin/kbx-implant` |
   | 5 | Drop and run a binary | copy `/bin/ls` to `/tmp/kbx-dropped`, run it |
   | 6 | Call home | one TCP connection to `1.1.1.1:443` |

4. Reads `docker logs kbx-falco` since the start and checks each expected rule.

```text
Alerts raised by kbx-falco:
  1     CRITICAL  KBX Executable Not In Image
  1     ERROR  KBX Sensitive File Read In App Container
  1     ERROR  KBX Write Below Binary Dir In App Container
  1     NOTICE  KBX Unexpected Outbound Connection From App Container
  1     WARNING  KBX Package Manager In App Container
  1     WARNING  KBX Shell Spawned In App Container

RESULT EXPECTED RULE
PASS   KBX Shell Spawned In App Container
PASS   KBX Sensitive File Read In App Container
PASS   KBX Package Manager In App Container
PASS   KBX Write Below Binary Dir In App Container
PASS   KBX Executable Not In Image
PASS   KBX Unexpected Outbound Connection From App Container
```

Each alert is one JSON line (`json_output=true`), ready for a SIEM or Falcosidekick:

```json
{"time":"2026-11-19T15:09:10.604Z","priority":"Error","rule":"KBX Sensitive File Read In App Container",
 "output_fields":{"container.id":"45f253579917","container.image.repository":"sample-app", ...}}
```

## Lessons from building it

- **`evt.res` is a name, `evt.rawres` is a number.** The first version used
  `evt.res = 0` for successful `execve` and `connect`, and those rules never fired.
  `evt.rawres = 0` is the numeric check.
- **`evt.dir` is deprecated in Falco 0.45.** Falco now captures only exit events. The
  rule loader prints `LOAD_DEPRECATED_ITEM` if you still use it.
- **Run with `--pid=host`.** Without it Falco logs that BPF iterators are disabled
  because it is "not running in the root PID namespace".

## Try it yourself

1. Add a rule for `curl` or `wget` running inside the app container. The hardened image
   has neither, so you will need to copy one in, which also trips "Executable Not In Image".
2. Add an exception so a shell started by your on-call runbook user is allowed. Hint:
   `and not user.name = ...` or Falco's `exceptions:` block.
3. Run the hardened app with `--read-only --tmpfs /tmp` and repeat step 5. What changes,
   and why is `/tmp` on tmpfs no longer an "upper layer"?

## Files

| File | Purpose |
|---|---|
| `falco-up.sh` | Starts or stops `kbx-falco`, mounting our rules over the image's default ruleset |
| `simulate.sh` | Target app, canary, six actions, PASS/FAIL per rule |
| `rules/kbx_rules.yaml` | The custom rules, macros and lists |
