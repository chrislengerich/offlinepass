# Vanadium/AOSP: FLAG_IMMUTABLE dataset-auth PendingIntents abort before the auth activity runs — the documented immediate-fill requires FLAG_MUTABLE (resolved)

**Affected:** Vanadium (GrapheneOS) / Chromium-based browsers on Android; any
autofill service offering dataset authentication with an immutable
PendingIntent.
**Reporter:** offlinepass (an open-source password manager with a standard
`AutofillService`).
**Status:** root-caused and resolved app-side. Reproduced 100% of the time
under four launch configurations; the fix is one line.

## Summary

Dataset authentication (the documented flow —
developer.android.com/guide/topics/text/autofill-services, "Require user
authentication", the CVC example) never applied its returned dataset in
Vanadium. The auth activity is launched by the browser via
`Activity.startIntentSenderForResult` with the framework's
`@android:autoFillAuth:` routing — and the framework passes a
**fill-in intent** with that call. Our auth PendingIntent was created
**`FLAG_IMMUTABLE`**, so the fill-in intent could not be merged: the launch
**aborted before the auth activity's `onCreate`**, and the system dispatched
a spurious **CANCELED result to the browser**:

```
W/ActivityTaskManager: Activity is launching as a new task, so cancelling activity result.
```

That spurious result consumed the framework's authentication tracking; the
system then relaunched the auth activity as a plain (non-result) launch. When
the auth activity later finished with the real `RESULT_OK` + the filled
`Dataset` in `AutofillManager.EXTRA_AUTHENTICATION_RESULT` (exactly the
documented pattern), the result had **no recipient** and was dropped. The
session stayed `WAITING_FOR_AUTH` forever and nothing filled.

**The fix**: create the auth PendingIntents **mutable** on S+
(`FLAG_MUTABLE or FLAG_CANCEL_CURRENT`) so the fill-in intent merges and the
launch proceeds with its result routing intact. With that one change the
captured sequence becomes the documented one:

```
00:38:10.105 V/AutofillManager: onAuthenticationResult(): authId=..., data=Intent { xflg=0x4 (has extras) }
00:38:10.112 D/AutofillSession: setAuthenticationResultLocked(): id=..., data=Bundle[...]
00:38:10.113 D/AutofillSession: setAuthenticationResultLocked(): result=Dataset[... fieldValues=[[29_chars],[29_chars],[16_chars]] ...]
00:38:10.113 D/AutofillSession: setAuthenticationResultLocked(): received Dataset from authentication flow
```

The views fill immediately — the docs' guarantee, now observable.

## The documented contract (what should happen)

Per the official docs, when the authenticated activity returns
`RESULT_OK` with a `Dataset` in `EXTRA_AUTHENTICATION_RESULT`:

> "the new dataset replaces the dataset that requires authentication, and
> the views are filled out immediately"

The framework implements exactly this — verified in the AOSP source:

- `AutofillClientController.autofillClientAuthenticate` →
  `mActivity.startIntentSenderForResult(intent, AUTO_FILL_AUTH_WHO_PREFIX,
  authenticationId, fillInIntent, 0, 0, options)` — the **fill-in intent**
  rides this call.
- `AutofillClientController.onDispatchActivityResult`:
  `resultData = (resultCode == RESULT_OK) ? data : null` →
  `AutofillManager.onAuthenticationResult`.
- `AutofillManager.onAuthenticationResult` → reads the extra →
  `IAutofillManager.setAuthenticationResult`.
- `Session.setAuthenticationResultLocked`: `result instanceof Dataset` →
  `autoFill(requestId, datasetIdx, datasetFromResult, ...)` — the immediate
  fill.

## The captured failure (events log, one tap of an auth'd dataset — the immutable binding)

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

## The root cause

The launch abort is the system's handling of an **immutable
PendingIntent that cannot accept the framework's fill-in intent**. The
autofill framework launches the auth activity *for result* and passes a
fill-in intent (`Activity.startIntentSenderForResult`'s `fillInIntent`
parameter) — an immutable PendingIntent record cannot merge it, and the
start is aborted: the system delivers an instant `RESULT_CANCELED, data=null`
to the caller (the framework's own wording for the path:
*"We pretend to the caller that it was really started, but they will just
get a cancel result"*), then relaunches the activity without the result
routing.

Two cascading consequences, both captured:

- The spurious CANCELED arrives during the launch's own pause transaction
  (before the auth activity's `onCreate`), consuming the framework's
  authentication tracking — `dumpsys autofill` shows the session stuck in
  `WAITING_FOR_AUTH`.
- The relaunched auth activity finishes with the real `RESULT_OK` +
  filled `Dataset`, but there is **no result recipient** — the result is
  silently dropped.

The abort surfaced through the system buffer as:

```
W/ActivityTaskManager: Activity is launching as a new task, so cancelling activity result.
I/ActivityTaskManager: START u0 {flg=0x10000000
        cmp=com.offlinepass.app/.autofill.AutofillAuthActivity (has extras)}
        with LAUNCH_MULTIPLE from uid 10211 (com.offlinepass.app)
        (realCallingUid=10140) (BAL_ALLOW_VISIBLE_WINDOW [realCaller]) result code=0
```

— the launch itself is permitted (the background-activity-start is
explicitly allowed); it is the **result** that is cancelled, because the
new-task launch cannot carry one.

## Configuration-independence under FLAG_IMMUTABLE (four captured configurations)

| # | The auth activity's config | The auth intent's flags | Outcome |
|---|---|---|---|
| 1 | opaque, `taskAffinity=""`, `noHistory`, `excludeFromRecents` | `FLAG_IMMUTABLE`, `FLAG_ACTIVITY_NEW_TASK` | abort + spurious CANCELED + dropped result |
| 2 | translucent (the browser never stops — `onInvisibleForAutofill` never fires, the response never expires) | `FLAG_IMMUTABLE`, `FLAG_ACTIVITY_NEW_TASK` | identical abort |
| 3 | plain (no task-forcing properties), intent without `NEW_TASK` | `FLAG_IMMUTABLE` | identical abort — **the launch still carries `FLAG_ACTIVITY_NEW_TASK` (`0x10000000` in `wm_create_activity`), added by the system because the PendingIntent's creator is a service (a task-less context)** |
| 4 | opaque, `taskAffinity=""`, `noHistory`, `excludeFromRecents` | **`FLAG_MUTABLE or FLAG_CANCEL_CURRENT` (S+)** | **the result delivers — `data=Intent { (has extras) }` → `received Dataset from authentication flow` → the views fill immediately** |

In configuration 2 the response-expiry recovery was also removed
(`AutofillClientController.onActivityStopped` → `onInvisibleForAutofill` →
the response expiry): the stuck session then never reset, and re-focusing
the field produced no sheet at all. The opaque configuration recovers via
that expiry: the next focus starts a fresh fill request that serves the
saved/generated item as a plain dataset, which fills correctly on tap — the
"two-tap" workaround.

## The fix

```kotlin
// The auth PendingIntents must be mutable on S+: the framework's
// startIntentSenderForResult passes a fill-in intent that an immutable
// record cannot merge — the launch then aborts with an instant CANCELED,
// consuming the auth tracking.
val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_CANCEL_CURRENT
} else {
    PendingIntent.FLAG_CANCEL_CURRENT
}
```

This matches Proton Pass's binding
(`protonpass/android-pass`, `PendingIntentUtils.autofillPendingIntentFlags`)
and is consistent with Bitwarden's flow — both ship dataset authentication
through mutable auth activities that return the filled dataset in
`EXTRA_AUTHENTICATION_RESULT`, exactly the documented pattern.

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

With the mutable binding (the fix) the flow becomes one-tap: the auth
activity's result delivers and the views fill immediately.

The identical failure exists for the FULL-response authentication and for
both the reveal (an existing entry) and the generate (a freshly created
one) flows.

## Evaluated and rejected alternatives (under the immutable binding)

| Approach | Why it fails |
|---|---|
| Translucent auth activity (the browser never stops, so the response never expires) | The launch abort is upstream of the expiry — identical spurious CANCELED. Also removes the response-expiry recovery: the stuck session then never resets and re-focusing produces no sheet at all. |
| The auth intent without `FLAG_ACTIVITY_NEW_TASK`, plain activity declaration, no task-forcing manifest properties | The system still adds `NEW_TASK` at send time — the PendingIntent's creator is a service (a task-less context has no source activity record to join the caller's task from). |
| Prefill ciphertext as the dataset placeholder, "decrypt on pick" | The decryption still has to write the plaintext through the framework's fill — the same broken delivery. Only moves the plaintext out of the response bundle. |
| A helper activity with a context (to give the PendingIntent a source task) | The task placement is resolved at **send** time from the PendingIntent's creator (the service), not at creation; a kept-alive activity cannot be the creator. |
| Chromium feature flags | `components/android_autofill/browser/android_autofill_features.cc` defines six features (LazyFrameworkWrapper, ImprovedVisibilityDetection, FieldsUpdatedOnSelect, SuppressOffscreenDatalist, IncludeSelectOptionValues, RefetchManagerIfDisabled) — none touches the launch/result plumbing; the abort is a system-side rule. |

All of these were captured on device; none changed the outcome, because the
immutable binding aborted the launch before any of them could matter.

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
- The same result-carrying dataset with the mutable binding fills correctly
  on Chromium browsers and in apps (native views), so the service's
  response shape is doc-compliant.
- The ecosystem: Proton Pass and Bitwarden ship the identical architecture
  (auth'd suggestion datasets; their own auth activities returning the
  filled dataset in `EXTRA_AUTHENTICATION_RESULT`) with **mutable**
  PendingIntents. KeePassDX's issue #769 (closed as out-of-scope) and the
  referenced crbug 1015381 / 1151614 / 1014945 document the history from
  the compatibility-mode era.
- Diagnostic note for maintainers and reporters: the abort reason is only
  visible in the **system** log buffer (`adb logcat -b system`) — the
  events buffer shows only the timing, and the silent abort sites in
  `ActivityStarter` log nothing even at DEBUG.
