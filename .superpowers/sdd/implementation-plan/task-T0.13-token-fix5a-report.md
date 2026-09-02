# T0.13 completion-token fix5a report — Task 2

## Status

DONE for Task 2, “Bind ordinary completion to exact durable receipt occurrences.”
Task 3 authorization completion was deliberately not started in this slice.

Task 1 was completed immediately before this slice in commit `cc78311`
(`Seal pending publication behind execution`). This report covers the subsequent
Task 2 commit boundary.

## Checklist

- [x] Step 1 RED — added exact-current occurrence, empty clearing-epoch, and
  effective prepared-publication witness tests.
- [x] Step 2 GREEN — receipt appends/reuses opaque occurrence IDs and ordinary
  execution privately mints a receipt-bound completion token, including for an
  empty plan.
- [x] Step 3 RED — demonstrated that the old reverse action-ID lookup accepted
  an equivalent action from another receipt store and accepted an obsolete
  occurrence after resolution and recurrence.
- [x] Step 4 GREEN — publisher validates destination/scope/principal, effective
  receipt counts and digest, and exact current occurrences under the receipt
  lock before draft/manifest mutation; links now come directly from token
  occurrence IDs.
- [x] Step 5 RED/GREEN — migrated policy evaluation and human rendering to the
  same token-only input as publication; existing action and receipt behavior is
  green.
- [x] Step 6 — formatted, inspected, and committed the scoped Task 2 change as
  `Bind pending publication to receipt occurrences`.

## RED evidence

- The three issuer tests initially failed to compile with `E0599` because
  `CompletedExecutionToken` had neither `occurrences()` nor
  `receipt_witness()` and did not carry durable evidence.
- Passing `report.completion()` through ordinary output and human rendering
  initially produced five causal `E0308` errors: those APIs still required
  `&[PendingAction]`.
- `completed_execution_rejects_an_equivalent_action_in_a_different_receipt_store`
  initially returned `Ok`: the publisher silently reverse-searched store B for
  the same action name and linked B's unrelated occurrence.
- `stale_completed_execution_cannot_publish_after_a_resolved_then_recurring_occurrence`
  initially returned `Ok` for the old A/e1 token after A/e1 -> [] -> A/e2.
- Cross-binding and missing-occurrence cases initially reached legacy paths
  instead of the required direct `ReceiptStoreError::IntentConflict` before
  publication.

No production behavior was added for a checklist item before its focused RED
was observed. The clone and serialization hostile checks added at the final
boundary are compile-fail characterization of the already-sealed Task 1 type:
they pass with one exact `E0599` and `E0277`, respectively.

## Implemented API and invariants

- `PendingReceiptOccurrence` carries one opaque action/receipt-entry pairing;
  `ReceiptExecutionWitness` binds scope, worker principal, normalized receipt
  path, effective entry/publication counts, and canonical effective receipt
  SHA-256. Neither is serialized.
- `ReceiptApplySession::record_pending` returns the newly appended occurrence or
  the exact existing current/unpublished occurrence without consuming metadata
  on an unchanged rerun.
- `ReceiptApplySession::complete_execution` rejects duplicate or non-current
  occurrences and captures the effective receipt, including a verified prepared
  pending-publication intent.
- `CompletedExecutionToken` owns ordered descriptors, exact ordered occurrences,
  and the receipt witness. It has private fields, no construction API outside
  action execution, and no `Clone`, `Copy`, `Default`, `Serialize`, or
  `Deserialize` implementation.
- `ApplyReport` retains count/message convenience through `ApplySummary` and
  owns the token. Empty ordinary execution still returns a publishable clearing
  witness.
- `PendingPolicy::evaluate`, `render_human`, and real `publish_manifest` accept
  only `&CompletedExecutionToken`.
- Publication validates the complete receipt and manifest binding before
  projecting/assigning the caller's draft, revalidates after durable intent
  recovery, and constructs receipt links from token-carried IDs. Mismatch tests
  assert error code `setup.receipt_conflict`, exit 13, unchanged durable bytes
  and draft state, and no publication metadata consumption.
- Existing receipt-before-manifest lock ordering and the prepared-intent
  recovery protocol remain intact.

## GREEN and verification evidence

- `cargo test --locked setup::action::tests::unresolved_rerun_token_reuses_the_exact_current_pending_entry_id -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::empty_completed_execution_can_publish_a_resolution_epoch -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::completion_witness_treats_a_verified_prepared_publication_as_effective -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::completed_execution_rejects_ -- --nocapture`
  — 3 passed.
- `cargo test --locked setup::action::tests::stale_completed_execution_cannot_publish_after_a_resolved_then_recurring_occurrence -- --exact`
  — 1 passed.
- `cargo test --locked setup::receipt::tests::execution_witness_binding_ -- --nocapture`
  — 1 passed.
- `cargo test --locked setup::action::tests::resolved_publication_intent_prevents_immediate_recurrence_suppression -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::publication_recovery_rejects_a_third_manifest_digest_and_retains_evidence -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::needs_human_journals_each_current_occurrence_once_and_recurrence_after_witnessed_resolution -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::setup_plan_cannot_clone_a_completed_execution_token -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests::setup_plan_cannot_serialize_a_completed_execution_token -- --exact`
  — 1 passed.
- `cargo test --locked setup::action::tests -- --nocapture`
  — 65 passed, 0 failed, 0 ignored.
- `cargo test --locked setup::receipt::tests -- --nocapture`
  — 39 passed, 0 failed, 1 ignored. The ignored test explicitly requires root
  plus `STYRN_UNIX_TEST_WORKER` selecting a real unprivileged account.
- `cargo build --locked` — passed.
- `cargo fmt --all -- --check` — passed.
- `git diff --check` — passed.

The first post-fixture full action run was 64/65 because adding cfg-selectable
clone/serialization probes moved the existing mutation diagnostic from fixture
line 2 to line 3. The emitted error remained the intended sole `E0616` private
field rejection. The exact expectation was corrected, its focused test passed,
and the full 65-test action suite then passed.

## Self-review and native limits

- Reviewed the production diff for direct raw-slice publisher/output entry
  points, reverse action-ID receipt searches, token trait derives, field
  visibility, receipt/manifest lock order, mismatch-before-mutation ordering,
  and receipt/publication recovery behavior.
- No manifest, platform, schema, example, dependency, public envelope, or design
  file changed.
- This split Task 2 verification ran on the native macOS host. Full locked,
  strict Clippy, Linux target, Windows target, and native Linux/Windows runtime
  gates are intentionally deferred to the final Task 4 owner; no cross-compile
  result is represented as native coverage.

## Task 3 handoff

Authorization remains intentionally incomplete and must be changed next:

- `AuthorizedExecutionReport` still retains the ordinary `ApplyReport` and an
  independently merged `Vec<PendingAction>`; therefore its ordinary-only token
  remains accessible.
- `record_pending_observations` still records only intrinsic privileged
  `NeedsHuman` actions and discards the returned occurrence IDs.
- Privileged `Todo` is not yet converted to the closed static authorization
  pending descriptor or journaled before decline/request/invocation.
- Implement `complete_authorized_execution` in action execution, consuming
  `ApplyReport::into_parts`, verifying the ordinary witness under a fresh apply
  session, recording all privileged occurrences, sorting descriptor/occurrence
  pairs by displayed plan order, and issuing one replacement token.
- Replace the temporary
  `pending_publication_boundary_accepts_the_complete_authorized_report_slice`
  type check, which currently publishes `report.ordinary().completion()`, with
  the Task 3 executed authorization projection matrix. After merging, no
  accessor may expose a publishable ordinary-only token.
