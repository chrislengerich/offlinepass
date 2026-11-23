/**
 * THE FOREIGN-FORMAT IMPORTS (the extension's twin of the Android's
 * GooglePasswordsCsv + the Proton plaintext parse): the two formats the
 * phone's Setup already accepts, parsed here to the SAME entry shape —
 * then merged into the repo vault in BULK, each entry carrying a
 * provenance note appended to its note field.
 *
 * No autodetection: the Import section's popup names the source
 * explicitly, the parse is the explicit call.
 */

// -- the GOOGLE PASSWORDS CSV (the Android's GooglePasswordsCsv.parse) ------

/**
 * THE LOSSY RULE: the Google CSV has NO note, TOTP, multi-URL, passkey
 * or alias columns — an import drops those (nothing to import). The
 * callers' status lines say so (the provenance note makes the source
 * visible per entry).
 */

/** The RFC-4180 row split: the quoted fields (the embedded commas, the
 *  escaped "" quotes, the embedded newlines) — the same semantics the
 *  Android's parseRows implements. Returns the rows as cell arrays. */
function parseRows(raw) {
  const rows = [];
  let row = [], cell = "", inQuotes = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (inQuotes) {
      if (c === '"') {
        if (raw[i + 1] === '"') { cell += '"'; i++; }
        else inQuotes = false;
      } else cell += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && raw[i + 1] === "\n") i++;
      row.push(cell); cell = ""; rows.push(row); row = [];
    } else cell += c;
  }
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((cell) => cell.trim() !== ""));
}

function cellAt(cells, idx, fallback = "") {
  if (idx == null || idx < 0 || idx >= cells.length) return fallback;
  return cells[idx].trim();
}

/** The Google export → the login items. Lenient on the header: the
 *  canonical four by name (case-insensitive, the BOM tolerated, extra
 *  columns ignored), falling back to the positional
 *  `name,url,username,password` order when no header row is present. */
export function parseGoogleCsv(raw) {
  const rows = parseRows(raw);
  if (!rows.length) return [];
  const header = rows[0].map((c) => c.replace(/^\uFEFF/, "").trim().toLowerCase());
  let idx = null;
  if (header.includes("username") && header.includes("password")) {
    idx = {
      name: header.indexOf("name"),
      url: header.indexOf("url"),
      username: header.indexOf("username"),
      password: header.indexOf("password"),
    };
  }
  const dataRows = idx ? rows.slice(1) : rows;
  const items = [];
  for (const cells of dataRows) {
    const name = cellAt(cells, idx ? idx.name : 0);
    const url = cellAt(cells, idx ? idx.url : 1);
    const username = cellAt(cells, idx ? idx.username : 2);
    const password = cellAt(cells, idx ? idx.password : 3);
    if (!name && !username && !password) continue;   // the empty row
    items.push(newItem({
      name, username, password,
      urls: url ? [url] : [],
    }));
  }
  return items;
}

// -- the PROTON PASS PLAINTEXT EXPORT (the Envelope.parseImport twin) -------

/** The entry shape = the ProtonItem's JSON: the data/metadata/content
 *  walk with the same field names and defaults. */
function itemFromJson(obj) {
  const data = obj.data ?? obj;
  const meta = data.metadata ?? {};
  const content = data.content ?? {};
  return newItem({
    name: meta.name ?? "",
    username: content.itemUsername ?? "",
    email: content.itemEmail ?? "",
    password: content.password ?? "",
    urls: Array.isArray(content.urls) ? content.urls : [],
    note: meta.note ?? "",
    totpUri: content.totpUri ?? "",
    modifyTime: typeof obj.modifyTime === "number" ? obj.modifyTime
      : (data.modifyTime ?? 0),
    itemUuid: meta.itemUuid ?? "",
  });
}

/** The plaintext Proton export → the items. The shapes the Android
 *  accepts: the bare array, {items}, {vaults.<k>.items}, the single
 *  {data…} item. Anything else (a malformed JSON, the encrypted
 *  armor) → null — the caller's status names it. */
export function parseProtonPlaintext(raw) {
  const t = raw.trimStart();
  if (!t.startsWith("{") && !t.startsWith("[")) return null;
  let obj;
  try { obj = JSON.parse(t); } catch { return null; }
  const items = [];
  if (Array.isArray(obj)) {
    for (const it of obj) if (it && typeof it === "object") items.push(itemFromJson(it));
    return items;
  }
  if (Array.isArray(obj.items)) {
    for (const it of obj.items) if (it && typeof it === "object") items.push(itemFromJson(it));
    return items;
  }
  if (obj.vaults && typeof obj.vaults === "object") {
    for (const k of Object.keys(obj.vaults)) {
      const arr = obj.vaults[k]?.items;
      if (Array.isArray(arr)) for (const it of arr) if (it && typeof it === "object") items.push(itemFromJson(it));
    }
    return items;
  }
  if (obj.data) return [itemFromJson(obj)];
  return null;
}

// -- the shared entry builder + the provenance note --------------------------

function uuid() {
  // WebCrypto's UUID: the extension pages have crypto.randomUUID; the
  // node tests need the fallback (the import never depends on it —
  // only the missing-uuid shapes do).
  return crypto.randomUUID
    ? crypto.randomUUID()
    : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function newItem(f) {
  return {
    itemId: "imp-" + uuid(),
    shareId: "local",
    state: 1,
    data: {
      type: "login",
      metadata: { name: f.name ?? "", itemUuid: f.itemUuid || uuid(), note: f.note ?? "" },
      content: {
        itemUsername: f.username ?? "", itemEmail: f.email ?? "",
        password: f.password ?? "", urls: f.urls ?? [], totpUri: f.totpUri ?? "",
        modifyTime: f.modifyTime ?? Math.floor(Date.now() / 1000),
      },
      extraFields: [], platformSpecific: {},
    },
  };
}

/** The provenance: the note's appended line naming the source — the
 *  re-import with the SAME label does not stack (the dedupe on the
 *  exact line); a DIFFERENT label appends (the source changed). */
export function appendImportNote(item, label) {
  const date = new Date().toISOString().slice(0, 10);
  const line = `[Imported from ${label} — ${date}]`;
  const note = item.data?.metadata?.note ?? "";
  if (note.includes(line)) return item;
  item.data.metadata.note = note ? `${note}\n${line}` : line;
  return item;
}
