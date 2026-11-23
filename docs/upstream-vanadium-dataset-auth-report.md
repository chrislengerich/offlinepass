# Vanadium/AOSP: dataset-authentication result never applied — the for-result launch of a service-created auth PendingIntent aborts with a spurious CANCELED before the auth activity runs

**Affected:** Vanadium (GrapheneOS) / Chromium-based browsers on Android; the platform autofill pipeline (framework-side behavior captured on device).
**Reporter:** offlinepass (an open-source password manager with a standard `AutofillService`).
**Status:** reproduces 100% of the time; configuration-independent (three distinct launch configurations captured).

## Summary

Dataset authentication (the documented flow —
developer.android.com/guide/topics/text/autofill-services, "Require user
authentication", the CVC example) never applies its returned dataset in
Vanadium. The auth activity is launched by the browser via
`Activity.startIntentSenderForResult` with the framework's
`@android:autoFillAuth:` routing. On this device the for-result launch of a
**service-created** auth PendingIntent **aborts before the auth activity's
`onCreate`** and delivers a spurious **CANCELED result to the browser**. That
spurious result consumes the framework's authentication tracking; the system
then relaunches the auth activity as a plain (non-result) launch. When the
auth activity later finishes with the real `RESULT_OK` + the filled
`Dataset` in `AutofillManager.EXTRA_AUTHENTICATION_RESULT` (exactly the
documented pattern), the result has **no recipient** and is dropped. The
session stays `WAITING_FOR_AUTH` forever and nothing fills.

## The documented contract (what should happen)

Per the official docs, when the authenticated activity returns
`RESULT_OK` with a `Dataset` in `EXTRA_AUTHENTICATION_RESULT`:

> "the new dataset replaces the dataset that requires authentication, and
> the views are filled out immediately"

The framework implements exactly this — verified in the AOSP source:

- `AutofillClientController.onDispatchActivityResult`:
  `resultData = (resultCode == RESULT_OK) ? data : null` →
  `AutofillManager.onAuthenticationResult`.
- `AutofillManager.onAuthenticationResult` → reads the extra →
  `IAutofillManager.setAuthenticationResult`.
- `Session.setAuthenticationResultLocked`: `result instanceof Dataset` →
  `autoFill(requestId, datasetIdx, datasetFromResult, ...)` — the immediate
  fill.

## The captured failure (events log, one tap of an auth'd dataset)

```
22:15:36.712  AutofillManager: entering STATE_PENDING_AUTHENTICATION : mRelayoutFix:true
22:15:36.721  wm_create_task [776]
22:15:36.721  wm_create_activity [AutofillAuthActivity, task 776, flags=0x10802000/0x10000000]
22:15:36.721  wm_pause_activity [app.vanadium.browser/...Main, pauseBackTasks]
22:15:36.728  wm_on_paused_called [Vanadium's Main]
22:15:36.728  AutofillManager: onAuthenticationResult(): authId=..., data=null   ★
22:15:36.728  AutofillManager: onAuthenticationResult(): empty intent
22:15:36.728  wm_on_activity_result_called [Vanadium's Main, ACTIVITY_RESULT]
22:15:36.737  wm_on_resume_called [Vanadium's Main]          ← the browser bounces back
22:15:36.743  wm_restart_activity [AutofillAuthActivity]      ← the relaunch
22:15:36.801  wm_on_create_called [the auth activity]         ← the app's code starts HERE
...the auth activity runs, unlocks, builds the filled Dataset, setResult(RESULT_OK, intent), finish()...
              (no second onAuthenticationResult — the result has no recipient)
```

Key observations:

1. **The spurious result precedes `onCreate` by ~70ms** (delivered at the
   pause of the browser, 9–16ms after `wm_create_activity`). It cannot be
   the auth activity's own result — the activity has not run yet.
2. `AutofillManager.java` (the client, in the browser's process) maps a
   non-`RESULT_OK` result to `data=null`:
   ```java
   // AutofillClientController.onDispatchActivityResult
   Intent resultData = (resultCode == Activity.RESULT_OK) ? data : null;
   ```
   and then: `Log.i(TAG, "onAuthenticationResult(): empty intent")` — the
   line captured above. The client returns without notifying the service,
   so the session's view state stays `WAITING_FOR_AUTH` (confirmed via
   `dumpsys autofill`), and the browser never receives a fill.
3. The relaunch (`wm_restart_activity`, the same ActivityRecord) has **no
   result recipient** — the pending-result bookkeeping was consumed by the
   aborted first attempt. The real `RESULT_OK` + `Dataset` returned by the
   auth activity is silently dropped.

## Configuration-independence (three captured configurations)

| # | The auth activity's config | The auth intent's flags | Outcome |
|---|---|---|---|
| 1 | opaque, `taskAffinity=""`, `noHistory`, `excludeFromRecents` | `FLAG_ACTIVITY_NEW_TASK` | abort + spurious CANCELED + dropped result |
| 2 | translucent (the browser never stops — `onInvisibleForAutofill` never fires, the response never expires) | `FLAG_ACTIVITY_NEW_TASK` | identical abort |
| 3 | plain (no task-forcing properties), intent without `NEW_TASK` | none | identical abort — **the launch still carries `FLAG_ACTIVITY_NEW_TASK` (`0x10000000` in `wm_create_activity`), added by the system because the PendingIntent's creator is a service (a task-less context)** |

In configuration 2 the response-expiry recovery was also removed
(`AutofillClientController.onActivityStopped` → `onInvisibleForAutofill` →
the response expiry): the stuck session then never reset, and re-focusing
the field produced no sheet at all. The opaque configuration recovers via
that expiry: the next focus starts a fresh fill request that serves the
saved/generated item as a plain dataset, which fills correctly on tap — the
"two-tap" workaround.

## Reproduction

1. GrapheneOS + Vanadium; a third-party password manager as the autofill
   service offering authenticated datasets (dataset-level
   `setAuthentication(PendingIntent)`; the PendingIntent created by the
   service via `PendingIntent.getActivity(context, requestCode, intent,
   FLAG_IMMUTABLE)`).
2. Focus a login form in Vanadium → the sheet lists the auth'd datasets.
3. Tap one. The auth activity runs (unlock), finishes with
   `RESULT_OK` + the filled `Dataset` in `EXTRA_AUTHENTICATION_RESULT`.
4. **Expected (the docs):** the views fill immediately.
   **Actual:** nothing fills; logcat shows
   `onAuthenticationResult(): empty intent` delivered ~10ms after
   `wm_create_activity` (before the auth activity's `onCreate`); the
   session stays `WAITING_FOR_AUTH` (`dumpsys autofill`).
5. Re-focusing the field starts a fresh session (after the response
   expiry) — the item then fills via a plain dataset on tap.

The identical failure exists for the FULL-response authentication and for
both the reveal (an existing entry) and the generate (a freshly created
one) flows.

## Environment

- Device: Pixel 9 Pro (GrapheneOS)
- OS: GrapheneOS (Android 16/17 — please fill the exact build)
- Browser: Vanadium (`app.vanadium.browser`), current stable at report time
- The autofill service: offlinepass (the standard `AutofillService`, no
  compatibility mode, no accessibility hacks)

## Notes

- The CTS tests (`LoginActivityTest#testDatasetAuthTwoFieldsUserCancelsFirstAttempt`,
  `testFillResponseAuthBothFieldsUserCancelsFirstAttempt`) exercise this
  flow and pass on AOSP — the abort appears specific to the
  browser-as-caller configuration on this device/ROM.
- The same app-side result-carrying dataset fills correctly on
  non-Chromium browsers and in apps (native views), so the service's
  response shape is doc-compliant.
- The ecosystem impact: every third-party password manager on
  Chromium-based Android browsers currently falls back to
  unlock-then-re-focus-then-tap; the immediate documented fill never
  happens. KeePassDX's issue #769 (closed as out-of-scope) and the
  referenced crbug 1015381 / 1151614 / 1014945 document the history from
  the compatibility-mode era; this report isolates the modern native-flow
  failure to the for-result launch abort.
