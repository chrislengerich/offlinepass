/**
 * THE PLATFORM-CLAIM FAILURE CONTRACT (the WebUSB reality): the CCID
 * interface can be held by ANOTHER consumer — pcscd on Linux, the
 * CryptoTokenKit's smart-card daemon on macOS, the Windows Smart Card
 * service — and Chrome surfaces that as a DOMException. The user must
 * get a NAMED, actionable message instead of a raw USB error. The
 * classifier is pure (name + message in → the message out) — this
 * suite pins every shape it must distinguish.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { describeClaimFailure } from "../card/ccid.js";

const domErr = (name, message) => {
  const e = new Error(message);
  e.name = name;
  return e;
};

test("the busy/claimed interface → the other-consumer message", () => {
  for (const err of [
    domErr("AbortError", "Unable to claim interface (already claimed)."),
    domErr("InvalidStateError", "Interface is already claimed."),
    domErr("DeviceBusy", "device busy"),
    new Error("claimInterface failed: the device or its interface is already claimed by another driver or app"),
  ]) {
    const msg = describeClaimFailure(err, "linux");
    assert.ok(msg.includes("another"), `"another" in the busy message: ${msg}`);
    assert.ok(msg.toLowerCase().includes("smartcard") || msg.toLowerCase().includes("smart card"),
      `names the smartcard interface: ${msg}`);
    assert.ok(msg.includes("unplug") || msg.includes("replug") || msg.includes("unplug/replug"),
      `suggests the recovery: ${msg}`);
  }
});

test("the disconnected/no-device shapes → the reconnect message", () => {
  for (const err of [
    domErr("NotFoundError", "No device selected."),
    domErr("NotFoundError", "The device was disconnected."),
    domErr("InvalidStateError", "The device must be opened first."),
  ]) {
    const msg = describeClaimFailure(err, "linux");
    assert.ok(msg.includes("reconnect") || msg.includes("Reconnect") || msg.includes("plugged"),
      `the reconnect message for ${err.name}: ${msg}`);
  }
});

test("the reserved-interface/kernel-driver shapes → the same other-consumer message", () => {
  for (const err of [
    domErr("SecurityError", "The requested interface implements a reserved class (smartcard)."),
    new Error("Unable to claim interface: driver is bound (usbhid)"),
  ]) {
    const msg = describeClaimFailure(err, "linux");
    assert.ok(msg.includes("another"), `the reserved-class message: ${msg}`);
  }
});

test("the unknown error keeps the original detail (diagnosable, never swallowed)", () => {
  const err = domErr("TypeError", "the quantum flux misaligned");
  const msg = describeClaimFailure(err, "linux");
  assert.ok(msg.includes("quantum flux"), `the raw detail survives: ${msg}`);
});

test("the mac/windows note names the platform's usual claimer", () => {
  const busy = domErr("AbortError", "Unable to claim interface (already claimed).");
  const mac = describeClaimFailure(busy, "macos");
  assert.ok(/CryptoTokenKit|macOS/i.test(mac), `the macOS note: ${mac}`);
  const win = describeClaimFailure(busy, "windows");
  assert.ok(/Smart Card service|Windows/i.test(win), `the windows note: ${win}`);
  const linux = describeClaimFailure(busy, "linux");
  assert.ok(/pcscd/i.test(linux), `the linux note: ${linux}`);
});
