# Repository Guidelines

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
