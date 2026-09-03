# T0.13 completion-token fix5b report — Tasks 3 and 4

## Status

DONE_WITH_CONCERNS. Task 3, “Make authorization completion truthful and
end-to-end,” is implemented and all available local and cross-compile gates are
green. The remaining concerns are verification availability, not known code
defects: native Linux and native Windows runtime/authorization gates were not
available from this macOS host, and the five existing real-privilege/real-worker
tests remain honestly ignored without their documented prerequisites.

This slice started from Task 2 commit `cd9a58b` (`Bind pending publication to
receipt occurrences`), following Task 1 commit `cc78311` (`Seal pending
publication behind execution`). Its implementation commit is titled `Preserve
deferred authorization as pending`; the handoff records the resulting hash
because a commit cannot include its own object ID.

## Checklist

- [x] Task 3 Step 1 RED — strengthened the declined mixed-plan test and observed
  the privileged `Todo` missing from both the report and durable receipt.
- [x] Task 3 Step 2 GREEN — converted each privileged `Todo` to a private typed
  pending descriptor, journaled all privileged descriptors before any grant
  outcome or native invocation, consumed the ordinary report, and issued one
  replacement completion token.
- [x] Task 3 Steps 3–4 — covered cancellation, launcher failure, and child
  failure; every case leaves a reusable pending occurrence and removes the
  request, while the existing `setup.elevation_required` / exit 13 mapping is
  unchanged.
- [x] Task 3 Steps 5–6 — replaced the type-only boundary check with executed
  grant/decline integration coverage through manifest publication, both JSON
  policies, and exact human rendering. Removed the ordinary-token escape from
  `AuthorizedExecutionReport`.
- [x] Task 3 Step 7 — formatted, reviewed, staged only owned paths, and committed
  with the planned imperative subject.
- [x] Task 4 Steps 1–3 — inspected the diff and ran all focused and mandatory
  local gates.
- [x] Task 4 Step 4 — ran installed Linux and Windows test-check and strict
  cross-Clippy targets without representing them as native runtime results.
- [x] Task 4 Step 5 — completed the final scope, causal-boundary, locking,
  stale-token, ordering, and secret-output review.

## RED/GREEN chronology

1. The first focused RED was
   `mixed_plan_decline_applies_ordinary_prefix_and_preserves_system_delta`.
   Its new pending assertion failed with left `0`, right `1`; the old receipt
   contained only the ordinary applied entry. This directly proved the shared
   defect underlying decline, cancellation, and merged projection: privileged
   `Todo` was represented only by a status/request count, not a durable pending
   occurrence.
2. The minimum GREEN added `deferred_authorization_pending`, retained the closed
   requested action for the native request, and passed both ordinary and
   privileged pending descriptors through `complete_authorized_execution`.
   The exact decline and no-grant tests then passed. Ordinary work still applies
   first, and no user-level action enters the privileged request or runner.
3. The cancellation and full-projection tests were introduced immediately
   after that minimum shared fix. Their first behaviorally valid runs passed
   because Step 2 necessarily established the plan's journal-before-invocation
   and replacement-token prerequisites. The earlier Step 1 failure is the
   causal RED for their previously missing privileged occurrence; no later RED
   is fabricated here. A preliminary cancellation-test compile error was only
   a test-harness `Debug` bound from `unwrap_err`, not product evidence, and was
   corrected before evaluating behavior.
4. The full authorization suite then exposed a real regression RED:
   `generated_request_is_size_bounded_before_private_file_creation` received
   `setup.receipt_conflict` and a receipt attempt instead of the required
   pre-state `setup.plan_invalid`. Request validation was split into an
   in-memory `PreparedAuthorizationRequest` and a later private-file write.
   Oversize/secret-shaped invalid requests now fail before request or receipt
   creation, while every valid invocation remains journal-first.
5. A self-review negative RED,
   `authorization_completion_rejects_invalid_display_order_before_pending_append`,
   initially returned the conflict but had already created receipt state.
   Display-order and duplicate-ID validation moved ahead of the receipt session;
   the GREEN asserts `setup.receipt_conflict` / 13 and no receipt file.
6. The first mandatory strict-Clippy run produced
   `clippy::too_many_arguments` on the Task 2 private receipt publication
   method. The GREEN tightened that private method to accept the sealed
   `CompletedExecutionToken` as its one evidence argument and derive pending,
   occurrences, and witness internally. This removes argument skew, preserves
   the public plan API, and avoids introducing a second raw-slice route.

## Implemented behavior and API choices

- `AUTHORIZATION_PENDING_INSTRUCTIONS` is the closed static instruction
  `Authorize the displayed system change, then rerun setup.` Each privileged
  `Todo` gets a warning-severity `PendingAction` with no rendered fragment.
  The closed typed `RequestedAction` remains the only child request form.
- `execute_with_authorization` runs and journals ordinary actions first, probes
  every privileged action, prepares any valid request in memory, then consumes
  the ordinary `ApplyReport` and durably records all intrinsic and
  authorization-deferred pending actions before deciding decline/no-elevate,
  writing a request, or calling the native invoker.
- `complete_authorized_execution` prevalidates the unique displayed plan and
  complete pending membership, opens a fresh receipt apply session, requires
  the current effective receipt witness to equal the consumed ordinary witness,
  records/reuses every privileged occurrence, sorts descriptor/occurrence pairs
  by original displayed-plan order, captures the final witness under the same
  receipt lock, and privately constructs one replacement token.
- `AuthorizedExecutionReport` contains only `ApplySummary`, the replacement
  `CompletedExecutionToken`, and `PrivilegedStatus`. It cannot return the
  consumed `ApplyReport` or its ordinary-only token.
- A successful launcher still returns `AuthorizationLaunched` with every
  protected action pending. Child exit zero alone is not activation evidence.
  A later verified re-probe omits only actions that now check `Done`; publishing
  that fresh token records the resolution projection without rewriting history.
- Cancellation, launcher errors, and child failures retain their existing typed
  authorization error. The private request is removed, but pending receipt
  entries remain durable; a no-consent rerun consumes no new entry metadata,
  returns a fresh token over the same occurrence IDs, and can publish them.
- `PendingPolicy::default`, strict `PendingPolicy`, manifest publication, and
  human rendering all consume the same replacement token. Exact descriptors
  and publication links preserve displayed order even though ordinary receipt
  entries are appended before privileged entries.
- The private receipt publisher now also takes the whole sealed token rather
  than separately accepting its three evidence views. It revalidates after
  intent recovery and constructs publication links only from token-carried
  exact entry IDs. Receipt-lock-before-manifest-lock ordering and the durable
  pending-publication intent protocol are unchanged.

## Focused GREEN evidence

- `cargo test --locked setup::action::authorization::tests -- --nocapture` —
  34 passed, 0 failed, 0 ignored.
- `cargo test --locked setup::action::tests -- --nocapture` — 64 passed,
  0 failed, 0 ignored. The obsolete type-only authorization publication test
  was removed, so this is one fewer test than Task 2's 65-test count.
- `cargo test --locked setup::receipt::tests -- --nocapture` — 39 passed,
  0 failed, 1 ignored. The ignored test requires root plus
  `STYRN_UNIX_TEST_WORKER` naming a real unprivileged account.
- `cargo test --locked manifest::tests -- --nocapture` — command passed but
  selected 0 tests because this repository's manifest contract coverage lives
  in integration-test targets, which the full suite ran.
- `cargo test --locked output::tests -- --nocapture` — command passed but
  selected 0 tests; output boundary/integration targets ran in the full suite.
- `cargo test --locked --test outcome_contract` — 7 passed, 0 failed,
  0 ignored.

The authorization coverage includes all three non-grant inputs, explicit
noninteractive consent, interactive consent, cancellation, launcher failure,
child failure, mixed ordinary/privileged `Todo` plus intrinsic `NeedsHuman`,
both pending exit policies, exact JSON/warning/human/manifest agreement, stale
ordinary-token rejection, current occurrence reuse, verified re-probe omission,
recurrence with a fresh occurrence, and invalid merge ordering before mutation.

## Full and platform verification

- `cargo fmt --all -- --check` — passed.
- `cargo build --locked` — passed.
- `cargo test --locked` — 395 passed, 0 failed, 5 ignored across all targets:
  249 unit tests passed with 2 ignored; `cli_contract` 11/11;
  `fixture_builder` 1/1; `machine_manifest_cli` 4/4;
  `manifest_contract` 115 passed with 3 ignored; `outcome_contract` 7/7;
  `output_boundary` 5/5; `platform_boundary` 1/1; and
  `toolchain_contract` 2/2.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` —
  passed on the native macOS host after the private publisher tightening.
- `cargo check --locked --tests --target x86_64-unknown-linux-gnu` — passed.
- `cargo clippy --locked --workspace --all-targets --all-features --target
  x86_64-unknown-linux-gnu -- -D warnings` — passed.
- `cargo check --locked --tests --target x86_64-pc-windows-msvc` — passed.
- `cargo clippy --locked --workspace --all-targets --all-features --target
  x86_64-pc-windows-msvc -- -D warnings` — passed.
- `git diff --check` and the final cached-diff check — passed.

The five full-suite ignores are existing native privilege/real-account tests:
two unit tests and three manifest-contract tests. Native Ubuntu and native
Windows runtime/authorization gates remain required for three-OS acceptance but
were unavailable here. The Linux and Windows results above are compilation and
lint evidence only. No real sudo prompt, UAC prompt, or configured external
worker-account integration was exercised.

## Final scope and security review

- No production pending publisher, policy evaluator, or human renderer accepts
  a raw `&[PendingAction]`; only the descriptor-validation test helper does.
- `CompletedExecutionToken` remains non-`Clone`, non-serializable, private-field
  evidence. Construction is confined to action execution; the hostile
  plan-descendant compile-fail fixtures remain green.
- The authorized report exposes exactly one merged token. The independently
  minted ordinary token is stale after privileged append and is rejected with
  `setup.receipt_conflict` / exit 13 before draft, manifest, receipt, or metadata
  mutation.
- Every real publication validates receipt path/scope/principal, effective
  counts/digest, exact current occurrence IDs, and manifest binding under the
  receipt lock before manifest mutation. Links never reverse-search by action
  ID.
- Empty clearing epochs, unchanged occurrence reuse, prepared-intent recovery,
  and resolved-then-recurring behavior remain covered by the Task 2 tests and
  the full suite.
- Deferred authorization stores only typed action identity and static human
  instructions. No secret, arbitrary command, raw parameter, credential, or
  rendered setup script was added to receipt, manifest, request, output, or
  diagnostics.
- The scoped diff changes only authorization/action execution tests and code,
  the token-only pending/receipt private call boundary required by strict
  Clippy, and this report. No platform adapter, manifest implementation, schema,
  example, dependency, command surface, account, directory, or unrelated file
  changed.
