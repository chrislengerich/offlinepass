import { OpenPgpCard } from "./card/openpgp.js";
import { decryptWithCard } from "./card/decrypt.js";

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

// THE REAL E2E: the vault file via the picker → the card-in-the-middle
// decrypt → the entries' summary. The vault file = the phone's
// state/10.gpg (the USB export or the synced copy).
const filePicker = document.createElement("input");
filePicker.type = "file";
filePicker.accept = ".gpg,application/octet-stream";
filePicker.style.display = "none";
document.body.appendChild(filePicker);
const pickBtn = document.createElement("button");
pickBtn.textContent = "Decrypt a vault file";
pickBtn.disabled = true;
document.body.appendChild(pickBtn);
pickBtn.onclick = () => filePicker.click();
filePicker.onchange = async () => {
  const file = filePicker.files[0];
  if (!file) return;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const result = await decryptWithCard(bytes, card, log);
    const text = new TextDecoder().decode(result.data);
    // The literal's plaintext = the vault's JSON envelope — count the
    // entries (a light parse; the full render = the phase 3).
    const matches = text.match(/"name"/g) || [];
    log(`DECRYPTED: ${result.data.length} bytes, ~${matches.length} entries`);
    log(text.slice(0, 300) + "…");
  } catch (e) { log("decrypt failed: " + e.message); }
};
