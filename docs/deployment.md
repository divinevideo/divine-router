# Fastly production deployment

## Before enabling

An authorized operator must confirm the `fastly.toml` service association still
identifies the intended serving service and account. Reuse that service, its
existing domains, backends, KV stores, runtime secrets and bindings. This workflow
does not provision replacements or move traffic. Inspect backend addresses,
TLS/SNI and host overrides as well as names: the automated name/binding guards
are not a substitute for confirming the serving configuration.

Create or reuse the GitHub **production** environment with the repository's
approved protection rules (including deployment branches restricted to `main`).
Configure these environment settings through the separately authorized operational
process, not by committing credentials:

| Setting | Kind | Purpose |
| --- | --- | --- |
| `FASTLY_API_TOKEN` | Environment secret | Automation token restricted to the associated service, with `global` scope for version clone/update, package upload, validation, activation and purge. Do not use an account-wide token. Rotate/revoke through the credential owner. |
| `FASTLY_SERVICE_ID` | Environment variable | Confirmed existing service ID; must exactly match `fastly.toml`. |
| `FASTLY_CUSTOMER_ID` | Environment variable | Confirmed Fastly account/customer ID; checked against the service before writes. |
| `FASTLY_CD_ENABLED` | Environment variable | Set to `true` **last**, after serving configuration, protections and scoped token are confirmed. Any other value fails closed. |

The workflow's GitHub token has only `contents: read`; no repository write,
OIDC, or extra cloud credentials are needed. The Fastly token is injected only
into the activation step, not tests, builds or third-party setup actions. Action
references are pinned to commits; Fastly CLI and Viceroy versions are explicit.

## Release path and evidence

1. A push to `main` starts the workflow. Manual replay is available only for
   `main`; both the job and script reject other refs/events. The checkout is
   pinned to the triggering SHA. It runs the deployment safety tests and locked
   Rust tests, then `fastly compute build --non-interactive`, using the pinned
   Rust toolchain and locked manifest build script. A failed command stops the
   job before credentials are injected or provider writes run. These checks
   run in this job for the exact source; deployment does not depend on a PR's
   older check results or a separately published image.
2. One `fastly-production` concurrency group serializes runs, without cancelling
   an in-progress activation. GitHub may replace pending runs; it does not
   promise queue order. The script checks live `main` before preparing a version
   and again before activation. An older replay cannot overwrite a release from
   newer `main`. Do not run another release workflow or manual deployment
   concurrently: GitHub concurrency cannot lock an external operator. An
   intervening active-version change detected during preparation fails the run.
3. `scripts/deploy.py` uses the Fastly API equivalent of the CLI deploy flow:
   clone the **active** version (not the latest unrelated draft), upload the
   built package, read back its package ID, attach a `git:<SHA> run:<ID>` version
   comment, validate and activate that explicit version. Domains, backend
   settings, KV links and runtime bindings are inherited, not created or edited.
   Uploading explicitly also handles unchanged code/manual replays without
   attributing an old source marker to the new commit.
4. It reads the active production version and source marker, purges the associated
   service, then performs a bounded, redirect-free **HEAD /** probe of that
   service's existing `edgecompute.app` domain, expecting HTTP 200. It reads the
   active version/marker once more before recording success. This is a safe
   availability probe, not a test of every public route or global propagation.
5. The Actions summary and `deployment.json` artifact record environment, source
   SHA, run URL, previous/new provider version, package ID/SHA-256, health result
   and final result. Artifacts are retained for 90 days. An activation-step
   failure retains a failure receipt with whatever version information was
   already obtained; an earlier setup/test/build failure is visible in job logs
   and has no deployment receipt. Never infer release success from a skipped
   job, an upload alone, or a green Rust check.

No activation is attempted by local safety tests. To validate them locally:

```bash
python3 -m unittest discover -s tests -p 'test_deploy.py'
cargo +1.88.0 test --locked
cargo +1.88.0 build --locked --profile release --target wasm32-wasip1
fastly compute build --non-interactive
```

The first controlled merge/replay, actual environment protections, credential
scope, production activation and active-version/health evidence must be verified
by an authorized operator after setup. Local/static tests do not establish those
operational acceptance criteria. No routing or identity behavior changes are
part of this automation.

## Ordering and failures

Publish after `divine-name-server` has written the required handle/ATProto state.
A package that references a new static backend must not activate until the
backend exists, with correct TLS/SNI and host settings, in the active version
that will be cloned. This workflow deliberately fails rather than provisioning
missing bindings, backends or stores. It runs no migrations, seed traffic,
destructive resource changes, or application writes.

Provider writes are not automatically retried. On a timeout or failed activation,
inspect the run's receipt and Fastly's current active version/comment before
retrying: a failed response does not prove the write did not happen. A failed
health probe or purge can leave the new version active; the run still fails.
There is no automatic rollback and no success claim for partial deployment.

## Rollback

Rollback is a separately authorized production action:

1. Stop further release runs and disable CD (`FASTLY_CD_ENABLED=false`) through
   the operational process. Do not cancel an activation midway; inspect it and
   wait for the running operation to settle before rollback.
2. Read the failed run's `previous_version`, source marker and package metadata;
   confirm that version is a known-good compatible release on the same service.
   Verify its backend, domain and KV bindings still fit current data. Re-activating
   code does **not** revert shared KV contents, runtime secrets or upstream data.
3. From an authenticated operator terminal, activate that explicit version, then
   purge that explicit service (replace placeholders; never use an unrelated
   editable draft):

   ```bash
   fastly service version activate --service-id <confirmed-service> --version <known-good-version>
   fastly purge --all --service-id <confirmed-service>
   ```

4. Independently read the Fastly production active version/comment and repeat
   the service-domain HEAD probe. Record the rollback version/source and result
   in the incident/change record. Keep CD disabled until `main` contains the
   intended fix or revert and the credential owner authorizes resumption.

Replaying an old workflow is not rollback: the live-main guard rejects stale
commits. Use explicit provider-version activation or a reviewed revert on `main`.
