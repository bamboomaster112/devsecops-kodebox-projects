# DevSecOps KodeBox Projects

Six hands-on DevSecOps projects, built and tested end to end on a KodeKloud **KodeBox**
running the **DevSecOps Toolkit** image. Each project is a working set of scripts plus a
lab write-up, and each script checks its own results and prints PASS or FAIL, so you know
when you are done.

The projects follow one story: a small Flask app arrives with a bad Dockerfile, old
dependencies and a leaked token. You harden it, clean up the leak, sign what you ship,
gate every change in CI, stop unsigned or vulnerable images at the Kubernetes front door,
and watch the running container for attacks.

| # | Project | You will use | Run time |
|---|---|---|---|
| 01 | [Harden a container image](01-image-hardening/README.md) | Hadolint, Trivy, Grype, Dockle, Syft | ~2 min |
| 02 | [Respond to a leaked secret](02-secret-leak-response/README.md) | Gitleaks, git-filter-repo, pre-commit | < 1 min |
| 03 | [SBOMs, signatures and attestations](03-sbom-and-signing/README.md) | Private TLS registry, Syft, Grype, Cosign 3, Rego | ~3 min |
| 04 | [A CI security gate with a report page](04-ci-security-gate/README.md) | All scanners, Semgrep, Bandit, Checkov, GitHub Actions, nginx | ~3 min |
| 05 | [Kubernetes admission control](05-k8s-admission-kind/README.md) | kind, Kyverno 1.20 (CEL policies), Pod Security Admission | ~5 min |
| 06 | [Runtime threat detection](06-falco-runtime/README.md) | Falco (our own instance), custom rules | ~2 min |

Projects 01 and 02 stand alone. 03 builds on 01's hardened image. 05 needs 03's registry,
key and signed images. 04 and 06 reuse 01's app.

## The box

Tested on 19 Nov 2026 on a KodeBox with the DevSecOps Toolkit: Ubuntu 24.04.5, 2 vCPU,
4 GB RAM, 30 GB disk, Docker 29.9.3.

| Preinstalled | Version | Added by `setup/install-extras.sh` | Version |
|---|---|---|---|
| Trivy | 0.76.0 | kubectl | v1.37.2 |
| Grype | 0.120.1 | kind (Kubernetes v1.37.0 node) | v0.33.0 |
| Syft | 1.54.1 | Helm | v4.3.2 |
| Cosign | v3.1.3 | pre-commit | 4.7.0 |
| Hadolint | 2.15.1 | Semgrep | 1.186.0 |
| Gitleaks | 8.30.1 | Checkov | 3.4.6 |
| Dockle | 0.4.15 | Bandit | 1.9.4 |
| | | git-filter-repo | 2.47.0 |

## Quick start

```bash
git clone https://github.com/bamboomaster112/devsecops-kodebox-projects.git
cd devsecops-kodebox-projects
tmux new -A -s kbx                 # long steps survive a browser refresh
./setup/install-extras.sh          # kubectl, kind, Helm (checksum-verified) and a Python venv
source ~/.bashrc
./setup/update-vuln-dbs.sh         # refresh Trivy and Grype databases (slow the first time)
./setup/check-env.sh               # every tool, its version, and free capacity
```

Run everything in one go (13.5 minutes on the tested box, every step PASS from a fresh clone):

```bash
./run-all.sh            # logs in ~/kbx-logs/
```

Or open a project's README and follow it, or run its main script directly:

```bash
./01-image-hardening/compare.sh
./02-secret-leak-response/run-lab.sh
./03-sbom-and-signing/pipeline.sh
./04-ci-security-gate/gate.sh && ./04-ci-security-gate/serve-report.sh
./05-k8s-admission-kind/run-lab.sh
./06-falco-runtime/falco-up.sh && ./06-falco-runtime/simulate.sh
```

## Things that will bite you on a KodeBox (and how the projects handle them)

- **Grype's database expires after 5 days.** On a box built more than 5 days ago, the
  first Grype run downloads a new database (about 7 minutes on 2 vCPU and roughly 7 GB of
  free disk while it unpacks). `setup/update-vuln-dbs.sh` does this once, up front.
- **A browser refresh kills foreground jobs.** Work inside `tmux` (preinstalled).
- **KodeKloud runs its own Falco** (`falco-modern-bpf.service`) with platform rules for
  crypto miners, reverse shells, internet-wide scanners, proxies, tunnels and changes to
  its own files. Leave that service and `/etc/falco` alone. Project 06 runs a separate
  Falco in Docker, and every simulated attack in these labs avoids those behaviours.
- **Port 22 cannot be opened to everyone; 80 and 443 are open by default.** Project 04
  serves its report on port 80. Restrict that rule to your own IP if the report should
  stay private.
- **Memory is 4 GB.** The kind node with Kyverno uses about 1.6 GB. Run
  `kind delete cluster --name kbx` when you finish project 05.

## Repository layout

```text
setup/                    install-extras.sh, update-vuln-dbs.sh, check-env.sh, install-scanners.sh (CI)
lib/kbx_reports.py        parses every scanner's JSON into comparable numbers (stdlib only)
01-image-hardening/       ... one folder per project, each with its own README.md
.github/workflows/        devsecops-gate.yml: project 04 on every push and pull request
```

Generated reports, keys and certificates never land in the repo: reports go to ignored
`reports/` and `out/` folders, and keys and the lab CA live under `~/.kbx/`.
