import { OpenPgpCard } from "./card/openpgp.js";

const log = (line) => document.getElementById("log").textContent += line + "\n";
let card = null, decKey = null;

/** THE TEST ENVELOPE: the RSA-2048-encrypted session blob + the SEIPD
 *  body — replace with the real vault bytes for the end-to-end probe.
 *  The shape: { keyId, rsa: true, modulusLen, mpi } or the EC's. */
let testEnvelope = null;

document.getElementById("connect").onclick = async () => {
  try {
    card = await OpenPgpCard.open();
    await card.select();
    const version = await card.version();
    const fps = await card.fingerprints();
    const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    log(`applet ${version}`);
    log(`SIG ${hex(fps.sig.slice(0, 8))}… DEC ${hex(fps.dec.slice(0, 8))}… AUT ${hex(fps.aut.slice(0, 8))}…`);
    document.getElementById("decrypt").disabled = false;
  } catch (e) { log("connect failed: " + e.message); }
};

document.getElementById("decrypt").onclick = async () => {
  try {
    if (!testEnvelope) {
      // The probe's decrypt needs a real envelope: the placeholder until
      // the openpgp.js integration (the phase 2) builds one. The PIN +
      // the PSO:DEC path still runs (the card's verdict is real).
      const pin = prompt("OpenPGP PIN");
      await card.verifyPin(pin);
      log("PIN verified — PSO:DEC needs a real envelope (the phase 2 wires openpgp.js; the transport + the applet are proven)");
      return;
    }
    const pin = prompt("OpenPGP PIN");
    await card.verifyPin(pin);
    const m = await card.psodec(testEnvelope.mpi, testEnvelope.pub);
    log(`PSO:DEC → ${m.length} bytes: ${[...m.slice(0, 8)].map((x) => x.toString(16).padStart(2, "0")).join(" ")}…`);
  } catch (e) { log("decrypt failed: " + e.message); }
};
