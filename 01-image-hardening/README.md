# Project 01: Harden a container image, and prove it with four scanners

**Tools:** Hadolint, Docker, Trivy, Grype, Dockle, Syft &nbsp;|&nbsp; **Time:** 30 to 45 minutes &nbsp;|&nbsp; **Run time:** about 2 minutes

The KodeBox ships a deliberately flawed app in `~/devsecops`. In this project you scan it,
read what each tool says, fix the image, and scan again. When you finish, you have a
before and after table that you can defend line by line.

## What you will learn

- How a Dockerfile linter (Hadolint), two vulnerability scanners (Trivy and Grype) and a
  CIS image checker (Dockle) each see a different slice of the same problem.
- Why "fixable" is the number that matters for a release decision.
- Seven concrete hardening moves, and which finding each one removes.
- How to record an accepted false positive so the next person can audit it.

## Before you start

```bash
cd ~/devsecops-kodebox-projects
./setup/install-extras.sh        # once per box
./setup/update-vuln-dbs.sh       # once per lab session (see the note below)
```

> **Why the database step matters.** Grype refuses to scan with a database older than
> 5 days. On a fresh KodeBox it downloads a new one first, which took about 7 minutes on
> 2 vCPU during testing and needs roughly 7 GB of free disk while it unpacks. Do it once
> up front and every scan in these projects stays fast. Run long steps inside `tmux` so a
> browser refresh does not kill them.

## Step 1: Look at the flawed app

```bash
cat ~/devsecops/Dockerfile ~/devsecops/requirements.txt
```

```dockerfile
FROM python:3.8-slim
RUN apt-get update && apt-get install -y curl
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENV FLASK_ENV=development
EXPOSE 5000
CMD python app.py
```

Before you run anything, write down what you think is wrong. Then compare with the tools.

## Step 2: Scan before and after in one command

```bash
./01-image-hardening/compare.sh
```

`compare.sh` calls `scan-image.sh` twice. For each image it lints the Dockerfile, builds
the image, and runs Trivy, Grype, Dockle and Syft, writing JSON into
`01-image-hardening/reports/{before,after}/`. Then `lib/kbx_reports.py` turns those
reports into this table. These are the real numbers from the KodeBox on 19 Nov 2026:

```text
 Check                  | before (~/devsecops)           | after (hardened)
------------------------+--------------------------------+---------------------
 Image size (MB)        | 256.0                          | 193.9
 Runs as user           | root (unset)                   | 10001:10001
 Hadolint findings      | 6 (error:1, info:2, warning:3) | 0 (clean)
 Trivy vulns (all)      | C:9 H:185 M:296 L:228          | C:0 H:47 M:103 L:67
 Trivy vulns (fixable)  | C:7 H:70 M:134 L:59            | C:0 H:0 M:0 L:0
 Trivy secrets in image | 1                              | 0
 Grype vulns (all)      | C:41 H:269 M:308 L:163         | C:0 H:77 M:85 L:68
 Grype vulns (fixable)  | C:22 H:132 M:156 L:29          | C:0 H:0 M:5 L:3
 Dockle fatal/warn/info | 2/1/4                          | 0/0/2
```

Your counts will drift as the vulnerability databases update. The shape will not.

## Step 3: Read the "before" findings

**Hadolint** (`reports/before/hadolint.txt`) flags the Dockerfile itself:

| Rule | Level | Line | Meaning |
|---|---|---|---|
| DL3020 | error | `ADD . /app` | Use COPY. ADD can fetch URLs and unpack archives you did not mean to. |
| DL3008 | warning | `apt-get install -y curl` | Unpinned apt packages change between builds. |
| DL3042 | warning | `pip install -r ...` | pip's cache stays in the layer. |
| DL3025 | warning | `CMD python app.py` | Shell form: signals go to `/bin/sh`, not your app. |
| DL3009 | info | apt line | apt lists left in the image. |
| DL3015 | info | apt line | Recommended packages pulled in for nothing. |

**Dockle** checks the built image against the CIS Docker Benchmark. Before: FATAL
`CIS-DI-0009` (ADD instead of COPY) and `DKL-DI-0005` (apt caches), WARN `CIS-DI-0001`
(no user, so root), plus INFO items for HEALTHCHECK, setuid files and unnecessary files
(`app/.git` and `app/Dockerfile` ended up inside the image).

**Trivy secret scanning** found `github-pat` in `/app/config.env`. `ADD . /app` copied the
fake token into a layer. Anyone who can pull the image can read it, even if a later layer
deletes the file.

**Trivy and Grype** both found critical CVEs, but the counts differ (9 vs 41 critical).
They use different databases, matching rules and severity sources (Trivy prefers the
distribution's own rating where one exists, so the same CVE can land in a different
bucket). Running two scanners is a cheap second opinion, and a gap like this is worth
a look: pick one CVE that only Grype calls critical and find out why.

## Step 4: Read the hardened Dockerfile

Open `01-image-hardening/hardened/Dockerfile`. Each numbered comment is one fix:

1. **Supported base, pinned by tag and digest.** `python:3.13-slim@sha256:...` instead of
   end-of-life `python:3.8-slim`. The digest means a rebuild uses exactly the bytes you
   scanned. Updating it becomes a deliberate, reviewable change.
2. **Dependencies before code.** Only the lockfile is copied before `pip install`, so
   that layer is cached until dependencies change.
3. **Hash-locked dependencies.** `requirements.txt` was generated with
   `pip-compile --generate-hashes` and installed with `--require-hashes`. pip refuses any
   package whose hash differs, which blocks a tampered or typosquatted download.
4. **Security updates, and no pip at runtime.** `apt-get upgrade` picks up Debian fixes
   published after the base image was built (zlib1g had one during testing). Removing pip
   also removed its vendored urllib3, msgpack and setuptools, which were the only
   fixable Python CVEs left in the image.
5. **Non-root user with a fixed UID (10001).** Kubernetes can check `runAsNonRoot` against
   it, and a container escape lands as an unprivileged user.
6. **COPY one named file** plus a whitelist `.dockerignore`. `config.env` and `.git` can no
   longer reach the image.
7. **Exec-form CMD with gunicorn** instead of the Flask development server, plus a
   `HEALTHCHECK` and `APP_ENV=production` (no debug mode).

The app itself (`hardened/app.py`) now reads settings from environment variables, exposes
`/healthz`, and sets basic security headers.

## Step 5: Read what is left, and why it is acceptable

The hardened image still shows 47 HIGH findings in Trivy. Every one of them is **not
fixable yet**: Debian has not shipped a patched package (util-linux, ncurses, perl-base
and similar). That is why the release gate in project 04 counts **fixable** findings.
Blocking on unfixable ones only teaches people to ignore the gate.

Grype's 5 fixable MEDIUM findings are in the CPython binary itself and go away with the
next Python patch release, which is a base-image digest bump.

**Dockle exceptions are written down.** `hardened/.dockleignore` accepts `DKL-DI-0005`
with a reason: it fires on the python:3.13-slim base layer, which cleans up with
`apt-get dist-clean`, a command Dockle does not recognise. `scan-image.sh` passes every
code in that file to `dockle --ignore`. A reviewer can see what was accepted, why, and when.

## Try it yourself

1. Change `--workers 2` to a shell-form `CMD gunicorn ...` and rerun
   `./01-image-hardening/scan-image.sh 01-image-hardening/hardened test:shellform /tmp/r`.
   Which tool complains?
2. Remove `!app.py` from `.dockerignore`. What breaks, and at which step?
3. Swap the base to `python:3.13-alpine` and compare the fixable counts and the size.
   What do you lose? (Hint: musl and wheel availability.)

## Files

| File | Purpose |
|---|---|
| `compare.sh` | Builds and scans before and after, prints the table |
| `scan-image.sh` | Lint, build, Trivy, Grype, Dockle and Syft for one build context |
| `hardened/` | The fixed Dockerfile, app, lockfile, `.dockerignore`, `.dockleignore` |
| `../lib/kbx_reports.py` | Parses every scanner's JSON into comparable numbers |
