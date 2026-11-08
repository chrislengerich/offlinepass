"use strict";

/** Content script injected at fill time (not auto-run on every page).
 *  Fills the login form on the page from the scan window. Idempotent. */

if (!window.__lpFillInstalled) {
  window.__lpFillInstalled = true;

  const VISIBLE = (el) => el && el.offsetParent !== null && !el.disabled && !el.readOnly;

  function findPasswordFields() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(VISIBLE);
  }

  function usernameFor(passwordInput) {
    const form = passwordInput.form || passwordInput.closest("form");
    const scope = form || document;
    const cands = Array.from(scope.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'))
      .filter((el) => VISIBLE(el) && el !== passwordInput);
    // Prefer a text/email field that precedes the password field in the DOM.
    const before = cands.filter((el) => el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING);
    const pick = before[0] || cands[0];
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
    if (!m || m.type !== "linuxpass-fill") return; // unknown message: ignore
    try {
      const pwds = findPasswordFields();
      if (!pwds.length) { sendResponse({ ok: false, error: "no visible password field" }); return; }
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