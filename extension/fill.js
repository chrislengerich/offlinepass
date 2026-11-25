"use strict";

/** Content script injected at fill time (not auto-run on every page).
 *  Fills the login form on the page from the scan window. Idempotent. */

if (!window.__lpFillInstalled) {
  window.__lpFillInstalled = true;

  const VISIBLE = (el) => el && el.offsetParent !== null && !el.disabled && !el.readOnly;

  function findPasswordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(VISIBLE);
  }

  // Search boxes must never receive the username: they are often the first
  // visible text field on the page (site header), so the naive "first text
  // input before the password" guess lands there.
  const SEARCH_RE = /search|query|filter|keyword/i;

  function looksLikeSearch(el) {
    if (el.type === "search") return true;
    if (SEARCH_RE.test(el.name || "") || SEARCH_RE.test(el.id || "") ||
        SEARCH_RE.test(el.getAttribute("placeholder") || "") ||
        SEARCH_RE.test(el.getAttribute("aria-label") || "")) return true;
    const form = el.form || el.closest("form");
    if (form && (form.getAttribute("role") === "search" ||
                 SEARCH_RE.test(form.getAttribute("class") || ""))) return true;
    return false;
  }

  // Positive signal: the page told us what the field is for.
  function autocompleteHint(el) {
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac === "username" || ac === "email" || ac === "nickname") return true;
    return false;
  }

  function usernameFor(passwordInput) {
    const form = passwordInput.form || passwordInput.closest("form");
    const scope = form || document;
    const cands = Array.from(scope.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'))
      .filter((el) => VISIBLE(el) && el !== passwordInput && !looksLikeSearch(el));
    if (!cands.length) return null;
    // 1) an autocomplete-hinted field; 2) a plain text/email field that
    // precedes the password field in the DOM; 3) any remaining candidate.
    const hinted = cands.filter(autocompleteHint);
    const before = cands.filter((el) => el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING);
    const pick = hinted[0] || before[0] || cands[0];
    return pick || null;
  }

  function setValue(el, value) {
    // Native setter so framework (React/Vue) listeners observe the change.
    const desc = Object.getOwnPropertyDescriptor(el.constructor.prototype, "value")
      || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.set) desc.set.call(el, value); else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  chrome.runtime.onMessage.addListener((m, _sender, sendResponse) => {
    if (!m || m.type !== "offlinepass-fill") return; // unknown message: ignore
    try {
      const pwds = findPasswordFields();
      if (!pwds.length) {
        // No password field: still fill the username/email if the entry has
        // one (e.g. username-only lookups) instead of aborting outright.
        if (m.username) {
          const u = usernameFor(document.querySelector('input[type="password"]') ||
            document.body);
          if (u) {
            setValue(u, m.username);
            sendResponse({ ok: true, count: 0, username: true });
            return;
          }
        }
        sendResponse({ ok: false, error: "no visible password field" });
        return;
      }
      let count = 0;
      let filledUser = false;
      for (const pwd of pwds) {
        setValue(pwd, m.password);
        count++;
        if (!filledUser && m.username) {
          const u = usernameFor(pwd);
          if (u) { setValue(u, m.username); filledUser = true; }
        }
      }
      // Single-password pages: also fill the username once even if it lives
      // outside the password's form.
      if (!filledUser && m.username) {
        const u = usernameFor(pwds[0]);
        if (u) { setValue(u, m.username); filledUser = true; }
      }
      sendResponse({ ok: true, count, username: filledUser });
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message || e) });
    }
  });
}