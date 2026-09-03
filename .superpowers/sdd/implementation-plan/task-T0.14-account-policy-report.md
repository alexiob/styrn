# T0.14 Slice 1 — Worker account policy report

## Scope

This commit implements only Slice 1 from `task-T0.14-action-design.md`.
It does not create accounts, mutate worker directories, add directory Actions
or receipts, or change schemas/examples.

Baseline was clean `3e4bf7b` (`Keep token repair report local`). The accepted
platform-foundation lineage includes `5146c5b` and the pending-publication
lineage includes `c67e546`; their focused regressions were rerun before this
slice.

## RED / GREEN

RED was captured with the new principal-policy tests before production changes:
the compiler reported the missing `WorkerAccountPolicy`, `account_policy()` and
`isolation()` APIs, the former three-argument `WorkerPrincipal::new`, and the
former policy-free named lookup. The test also intentionally exercised an
unavailable explicit named-policy lookup.

GREEN adds the closed serializable `WorkerAccountPolicy` enum and makes it a
field of `WorkerPrincipal`. Equality, serde round trips, authorization-request
binding, native UID/SID revalidation, and receipt/manifest store bindings now
include it. A changed policy is therefore principal drift, even if uid/SID and
name match.

## API and call-site migration

- `WorkerPrincipal::new(kind, id, name, policy)` requires every caller to pick
  `CurrentUser` or `Dedicated` explicitly.
- `resolve_current_worker_principal()` is always `CurrentUser` on Linux,
  macOS, and Windows.
- `resolve_named_worker_principal(name, policy)` requires the caller to make
  the policy decision. Environmental distinct-worker tests select `Dedicated`;
  no literal worker account name is used.
- Unix UID and Windows SID resolution/revalidation receive and retain the
  expected policy, preserving the existing UID/SID/name identity checks.
- User scope rejects `Dedicated` before directory-layout/native mutation.
- `platform::WorkerIsolation` derives exclusively from account policy. The
  manifest converts its `mode` to policy and rejects a detached isolation
  value, so a policy/isolation mismatch cannot produce a principal.

## Focused verification

- Platform prerequisite regressions: 25 worker-directory tests passed.
- T0.13 action pending regressions: 6 passed; receipt pending regressions: 4
  passed.
- Slice-focused principal tests: 11 passed in each source-inclusion build.
- Manifest worker-identity contract tests: 3 passed.
- Receipt execution-witness binding: 1 passed.
- Authorization account-policy binding: 1 passed.

`cargo build --locked`, `cargo check --locked --tests`,
`cargo fmt --all -- --check`, host strict Clippy, and `git diff --check` passed.
The full locked suite passed: 400 passed, 0 failed, 5 environmental tests
ignored. Linux and Windows `cargo check --locked --tests` and strict target
Clippy also passed for `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc`.

## Native limitations

This host is macOS. Current-user principal resolution was exercised locally;
Linux and Windows native account-resolution runtime gates remain unavailable
without their native hosts. No dedicated account was created or adopted by this
slice, and no elevated/account mutation gate was run or claimed.
