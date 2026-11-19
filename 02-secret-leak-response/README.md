# Project 02: Respond to a leaked secret, from detection to prevention

**Tools:** Gitleaks, git-filter-repo, pre-commit &nbsp;|&nbsp; **Time:** 30 minutes &nbsp;|&nbsp; **Run time:** under a minute

`~/devsecops/config.env` holds a GitHub token, and it was committed. It is fake (the
toolkit put it there for practice), but you will treat it like a real incident: detect,
contain, rotate, purge, prevent, and then adopt scanning on a repo you cannot rewrite.

## What you will learn

- Why deleting a file does not remove a secret, and how to prove it.
- The response order that matters: rotate first, rewrite history second.
- How to rewrite history with `git filter-repo` and verify the result.
- How to stop the next leak at `git commit` time with a custom Gitleaks rule.
- How to introduce scanning to an old repo with a baseline instead of a flood of alerts.

## Run it

```bash
cd ~/devsecops-kodebox-projects
./02-secret-leak-response/run-lab.sh            # all six stages, PASS/FAIL summary at the end
./02-secret-leak-response/run-lab.sh --pause    # stop after each stage to look around
```

The script works on a throwaway clone in `~/work/leak-lab/app`, so `~/devsecops` is never
changed. Reports land in `~/work/leak-lab/reports`.

## Stage 1: Detect

```bash
gitleaks git --redact -v .     # every commit in history
gitleaks dir --redact -v .     # only the files on disk
```

```text
github-pat  config.env:4  commit 9e221a19  secret REDACTED
```

`--redact` keeps the secret out of your terminal and your CI logs. Always use it.

## Stage 2: Contain

The script replaces `config.env` with `config.env.example` (no value), adds `*.env` to
`.gitignore`, and commits. Then it scans again:

```text
[PASS] working tree clean after the fix (expected 0, got 0)
--> History still holds the token: deleting a file does not delete it from earlier commits.
[PASS] token still in history after the fix (expected yes, got yes)
```

This is the lesson most teams learn the hard way. Anyone who cloned the repo, or who
browses the old commit on the hosting site, still has the token.

## Stage 3: Rotate

Rotation comes before any history rewrite. Revoke the token at the provider, issue a
replacement with the smallest scope and shortest expiry that works, store it in a secret
manager or CI secret, and check the provider's audit log for use since the leak commit.
Rewriting history protects future clones. Only rotation protects you from the copies
that already exist.

## Stage 4: Purge

```bash
echo 'regex:ghp_[0-9A-Za-z]{36}==>REDACTED_GITHUB_TOKEN' > replacements.txt
git filter-repo --force --replace-text replacements.txt
gitleaks git --redact .        # now clean
```

```text
HEAD was d24dbc8, now 490304d: every commit after the leak has a new hash.
    6acfaae Sample app for the DevSecOps exercises
    +GITHUB_TOKEN=REDACTED_GITHUB_TOKEN
[PASS] history clean after filter-repo (expected 0, got 0)
```

Every commit hash after the leak changes, which is why a purge on a shared repo needs a
force-push of every branch and tag, everyone re-cloning, and a request to the host to drop
cached views and pull-request refs. `filter-repo` also removes the `origin` remote on
purpose, so you cannot push the rewrite by accident.

## Stage 5: Prevent

Two files go into the repo:

- `.gitleaks.toml` keeps all built-in rules and adds one for an internal token format,
  `kbx_` followed by 32 hex characters. No public rule knows your company's key format,
  so this is the rule that catches your own keys.
- `.pre-commit-config.yaml` runs `gitleaks git --pre-commit --staged` (and Hadolint for
  Dockerfiles) using the binaries already on the box.

```bash
pre-commit install
echo "INTERNAL_API_KEY=kbx_$(python3 -c 'import secrets; print(secrets.token_hex(16))')" > service.cfg
git add service.cfg && git commit -m "Add service settings"
```

```text
gitleaks (staged changes)................................................Failed
Finding:     INTERNAL_API_KEY=REDACTED
RuleID:      kodebox-internal-api-key
[PASS] commit with an internal key is blocked (expected blocked, got blocked)
[PASS] clean commit is allowed (expected allowed, got allowed)
```

A pre-commit hook is a seatbelt, not a lock: anyone can skip it with `--no-verify`. That
is why project 04 runs the same scan again in CI, where it cannot be skipped.

## Stage 6: Baseline an old repo

On a repo whose history you cannot rewrite, record today's findings and report only new ones:

```bash
gitleaks git --report-path baseline.json .                       # today's known findings
gitleaks git --baseline-path baseline.json --report-path new.json .   # only what is new
```

```text
Baseline records 1 known finding(s); they are tracked, not re-reported.
NEW: kodebox-internal-api-key  new-service.cfg:1  fingerprint 7d3d5468...:new-service.cfg:kodebox-internal-api-key:1
[PASS] only the new leak is reported against the baseline
[PASS] accepted finding silenced by .gitleaksignore
```

`.gitleaksignore` takes fingerprints of findings you have accepted. Only add one after the
secret is rotated. Ignoring a live key hides the risk without removing it.

## Result

```text
PASS   leak found in git history
PASS   leak found in working tree
PASS   working tree clean after the fix
PASS   token still in history after the fix
PASS   rotation checklist reviewed
PASS   history clean after filter-repo
PASS   commit with an internal key is blocked
PASS   clean commit is allowed
PASS   only the new leak is reported against the baseline
PASS   accepted finding silenced by .gitleaksignore
```

## Try it yourself

1. Add a rule to `.gitleaks.toml` for a made-up format, such as `acme-[A-Z0-9]{20}`, and
   prove the hook blocks it.
2. Put a fake key under a `testdata/` folder and confirm the allowlist lets it through.
3. Run `gitleaks git --report-format sarif --report-path leaks.sarif .` and open the file:
   this is the format GitHub code scanning reads in project 04.

## Files

| File | Purpose |
|---|---|
| `run-lab.sh` | The six stages with automatic checks |
| `.gitleaks.toml` | Built-in rules plus the internal key rule and a test-fixture allowlist |
| `pre-commit-config.yaml` | Hooks copied into the lab repo as `.pre-commit-config.yaml` |
