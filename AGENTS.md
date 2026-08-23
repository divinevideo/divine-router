# Repository Guidelines

## Divine Context And Brain

Before broad product, architecture, protocol, cross-repo, service-boundary, or pull-request authoring, review, or modification work, read the shared Divine context primer.

Resolve the context directory and clone it there if it is missing:

```bash
CONTEXT_DIR="${DIVINE_CONTEXT_ROOT:-../divine-context}"
[ -e "$CONTEXT_DIR/.git" ] || gh repo clone divinevideo/divine-context "$CONTEXT_DIR"
```

Use that value as `<context-dir>` below.

The `divine-context` repo is private, so cloning requires GitHub access. If clone, network, or auth fails, continue from the local repo docs and avoid cross-repo assumptions.

Before updating an existing context checkout, verify it is clean and on its default branch. If it is clean and on the default branch, update it with `git -C <context-dir> pull --ff-only`. If it is dirty, on another branch, cannot fast-forward, or network/auth fails, leave it untouched and say the context may be stale.

Read `<context-dir>/AGENT_CONTEXT.md` and follow its instructions. If unavailable, continue from the local repo docs and avoid cross-repo assumptions.

Before working on a pull request, follow `<context-dir>/PR_REVIEW.md` and use `<context-dir>/PR_REVIEW_TEAMS.md` to request the normal team and check takeover authority. Ordinary review remains open to any eligible Divine human. Before modifying a pull-request branch, enforce the mapping and every takeover gate; if the mapping cannot be read, feedback-only review may continue but automated takeover must stop. Request and verify required human review automatically when tooling permits. If the runbook is unavailable, leave the pull request open and report the blocker.

If a Divine Brain search or ask tool is available, you may use it for company memory. Treat it as optional and credentialed: tool names vary by client, and work must continue when Brain is unavailable. When Brain results influence work, cite the returned document ids. Never commit Brain credentials or expose Brain-derived sensitive content in public PRs, issues, branch names, commit messages, code comments, logs, screenshots, release notes, or externally shared agent transcripts.

## Project Structure & Module Organization
- Edge service code lives under `src/`.
- Runtime configuration lives in `fastly.toml` and related data files such as `kv_usernames.json`.
- This repo is a public edge service, separate from the GitOps-managed GKE stack. Keep routing and edge-behavior changes scoped and explicit.

## Build, Test, and Validation Commands
- Use the Fastly local workflow for validation: `fastly compute serve`.
- Use the documented publish flow for deploy work: `fastly compute publish --non-interactive && fastly purge --all`.
- If you add or change local verification steps, document them in the PR.

## Coding Style & Naming Conventions
- Follow the existing Rust and Fastly Compute patterns already established in the repo.
- Keep username routing, NIP-05 behavior, KV lookup logic, and system-subdomain passthrough changes focused. Do not mix unrelated cleanup or refactors into the same PR.
- Verify reserved subdomains, redirect behavior, and KV data assumptions against the current code and README before changing them.

## Security & Operational Notes
- Never commit secrets, private keys, service credentials, or logs containing sensitive values.
- Public issues, PRs, branch names, screenshots, and descriptions must not mention corporate partners, customers, brands, campaign names, or other sensitive external identities unless a maintainer explicitly approves it. Use generic descriptors instead.
- Be explicit about any change that affects public routing, identity verification, or Fastly KV-backed behavior.

## Pull Request Guardrails
- PR titles must use Conventional Commit format: `type(scope): summary` or `type: summary`.
- Set the correct PR title when opening the PR. Do not rely on fixing it later.
- If a PR title is edited after opening, verify that the semantic PR title check reruns successfully.
- Keep PRs tightly scoped. Do not include unrelated formatting churn, dependency noise, or drive-by refactors.
- Temporary or transitional code must include `TODO(#issue):` with a tracking issue.
- Externally visible routing or identity behavior changes should include sample URLs, responses, or an explicit note that there is no visual change.
- PR descriptions must include a summary, motivation, linked issue when applicable, and manual validation plan.
- Before requesting review, note what you validated locally and what remains manual.
