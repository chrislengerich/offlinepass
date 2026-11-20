import { OpenPgpCard } from "./card/openpgp.js";
import { cloneVault, syncVault } from "./git.js";

const log = (line) => document.getElementById("log").textContent += line + "\n";
const $ = (id) => document.getElementById(id);
let card = null;

$("clone").onclick = async () => {
  try {
    if (!card) { card = await OpenPgpCard.open(); await card.select(); }
    const url = $("url").value.trim(), token = $("token").value.trim();
    const out = await cloneVault({ httpUrl: url, token, card, onLog: log });
    log(`DONE: ${JSON.stringify(out)}`);
  } catch (e) { log("failed: " + e.message); }
};
$("sync").onclick = async () => {
  try {
    if (!card) { card = await OpenPgpCard.open(); await card.select(); }
    const url = $("url").value.trim(), token = $("token").value.trim();
    const out = await syncVault({ httpUrl: url, token, card, onLog: log });
    log(`DONE: ${JSON.stringify(out)}`);
  } catch (e) { log("failed: " + e.message); }
};
