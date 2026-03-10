console.log("[ACrypt] dashboard.js loaded");

function requireAuthOrRedirect() {
  if (!getToken() || !getUsername()) {
    location.href = "/login";
    return false;
  }
  return true;
}

function bind(id, event, handler) {
  const el = document.getElementById(id);
  if (!el) {
    log(`❌ Missing element #${id} on this page`);
    return;
  }
  el.addEventListener(event, handler);
}

async function decryptLocalPrivateKey(packed, password) {
  // packed is the string produced by encryptLocalPrivateKey(): "salt.iv.ciphertext"
  // where each component is base64-encoded. Split to recover the three parts.
  const [saltB64, ivB64, ctB64] = packed.split(".");
  const salt = new Uint8Array(b64ToBuf(saltB64));
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const ct = b64ToBuf(ctB64);

  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  try {
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  } catch (e) {
    // This is where your vague "operation-specific reason" usually comes from.
    throw new Error("Wrong password (or corrupted local key). Try again, or re-register on this browser.");
  }
}


async function loadLocalPrivateKey(username, password) {
  log(`Loading local private key for username="${username}"`);
  const keyName = LS.rsaPriv(username);
  log(`LocalStorage key = ${keyName}`);

  const packed = localStorage.getItem(keyName);
  if (!packed) throw new Error("No local private key found. Register on this device first.");
  const pkcs8 = await decryptLocalPrivateKey(packed, password);
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

function pemToArrayBuffer(pemText) {
  // strip header/footer and whitespace
  const b64 = pemText
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return b64ToBuf(b64);
}

async function importSpkiPublicKeyFromServer(rsa_pub_pem_b64) {
  // Server returns base64 of whatever was stored (could be DER SPKI bytes OR PEM ASCII bytes)
  const raw = b64ToBuf(rsa_pub_pem_b64);

  // Try to interpret as text to detect PEM
  let asText = "";
  try {
    asText = new TextDecoder().decode(new Uint8Array(raw));
  } catch {}

  let spkiBytes = raw;

  // If it looks like PEM, convert PEM -> DER
  if (asText.includes("BEGIN PUBLIC KEY")) {
    spkiBytes = pemToArrayBuffer(asText);
  }

  // Import as RSA-OAEP public key
  return crypto.subtle.importKey(
    "spki",
    spkiBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}


async function rsaWrap(dekBytes, recipientPubKey) {
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientPubKey, dekBytes);
  return bufToB64(wrapped);
}

async function rsaUnwrap(wrappedB64, privKey) {
  const wrapped = b64ToBuf(wrappedB64);
  const dek = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, wrapped);
  return new Uint8Array(dek);
}

async function aesGcmEncrypt(plaintextBuf, dekBytes) {
  const key = await crypto.subtle.importKey("raw", dekBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBuf);
  return { ivB64: bufToB64(iv.buffer), ctB64: bufToB64(ct) };
}

async function aesGcmDecrypt(ivB64, ctB64, dekBytes) {
  const key = await crypto.subtle.importKey("raw", dekBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const ct = b64ToBuf(ctB64);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
}

// -------------------------
// Signing helpers (ECDSA P-256)
// -------------------------

/**
 * Canonical message signed on every ciphertext upload/update/rotate.
 * Must mirror make_upload_message() in crypto_utils.py (server-side verification
 * uses Ed25519 for the CLI client; the web client uses ECDSA P-256 — both follow
 * the same message format so the structure is auditable and consistent).
 */
async function makeUploadMessage(fileId, nonceB64, ciphertextB64, version) {
  const nonce = new Uint8Array(b64ToBuf(nonceB64));
  const ct = new Uint8Array(b64ToBuf(ciphertextB64));
  // Compute SHA-256 of ciphertext bytes
  const ctDigestBuf = await crypto.subtle.digest("SHA-256", ct);
  // Convert digest bytes to a lowercase hex string: each byte → 2-char hex with leading zero
  const ctDigest = Array.from(new Uint8Array(ctDigestBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  // Likewise convert nonce bytes to hex for the signed message
  const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, "0")).join("");
  const msg = `file_id:${fileId}|version:${version}|nonce:${nonceHex}|ciphertext_sha256:${ctDigest}`;
  return new TextEncoder().encode(msg);
}

async function loadLocalSignPrivateKey(username, password) {
  const packed = localStorage.getItem(LS.signPriv(username));
  if (!packed) throw new Error("No local signing key found. Register on this device first.");
  const [saltB64, ivB64, ctB64] = packed.split(".");
  const salt = new Uint8Array(b64ToBuf(saltB64));
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const ct = b64ToBuf(ctB64);
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

async function ecdsaSign(msgBytes, signPrivKey) {
  const sigBuf = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signPrivKey, msgBytes);
  return bufToB64(sigBuf);
}

async function importEcdsaPublicKey(spkiB64) {
  const raw = b64ToBuf(spkiB64);
  // The CLI client registers PEM bytes; the web client registers raw DER bytes.
  // Detect PEM by checking for the ASCII "-----" header and convert if needed.
  let spkiBytes = raw;
  try {
    const asText = new TextDecoder().decode(new Uint8Array(raw));
    if (asText.includes("BEGIN PUBLIC KEY")) {
      const b64 = asText
        .replace(/-----BEGIN PUBLIC KEY-----/g, "")
        .replace(/-----END PUBLIC KEY-----/g, "")
        .replace(/\s+/g, "");
      spkiBytes = b64ToBuf(b64);
    }
  } catch (_) {}
  return crypto.subtle.importKey("spki", spkiBytes, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

async function ecdsaVerify(msgBytes, sigB64, pubKey) {
  const sig = b64ToBuf(sigB64);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, sig, msgBytes);
}

async function refreshList() {
  setStatus("listStatus", "Loading files…");
  log("Refreshing file list…");

  let files;
  try {
    files = await api("/list");
  } catch (e) {
    setStatus("listStatus", `Failed to load: ${e.message}`);
    log(`List error: ${e.message}`);
    return;
  }

  if (!Array.isArray(files)) {
    setStatus("listStatus", "Server returned unexpected data. Check Server URL.");
    return;
  }

  const tb = document.getElementById("filesTbody");
  const empty = document.getElementById("emptyState");
  if (!tb) return;

  tb.innerHTML = "";

  if (files.length === 0) {
    populateFileSelects([]);
    setStatus("listStatus", "");
    if (empty) empty.style.display = "";
    return;
  }
  if (empty) empty.style.display = "none";

  const me = getUsername();

  for (const f of files) {
    const isOwner = (f.owner === me);
    const tr = document.createElement("tr");
    // last_modified_by is the signer of the most recent upload/update/rotate.
    // It equals the owner on initial upload, and changes when any authorised
    // user calls modify (update) or the owner calls rotate.
    const lastMod = f.last_modified_by || f.owner;
    const modifiedByOther = (lastMod !== f.owner);
    const modCell = modifiedByOther
      ? `${escHtml(lastMod)} <span class="badge badge-shared" style="margin-left:4px" title="Different from owner">✏ modified</span>`
      : escHtml(lastMod);

    tr.innerHTML = `
      <td><code title="${f.file_id}">${f.file_id}</code></td>
      <td>${escHtml(f.filename)}</td>
      <td>
        ${escHtml(f.owner)}
        ${isOwner ? '<span class="badge badge-owner" style="margin-left:6px">You</span>' : '<span class="badge badge-shared" style="margin-left:6px">Shared</span>'}
      </td>
      <td>v${f.version}</td>
      <td>${modCell}</td>
      <td class="action-cell">
        <button type="button" data-id="${f.file_id}" class="dlBtn btn-sm secondary">⬇ Download</button>
        ${isOwner ? `<button type="button" data-id="${f.file_id}" class="delBtn btn-sm danger">🗑 Delete</button>` : ""}
      </td>
    `;
    tb.appendChild(tr);
  }

  tb.querySelectorAll(".dlBtn").forEach(btn =>
    btn.addEventListener("click", () => downloadFlow(btn.dataset.id))
  );
  tb.querySelectorAll(".delBtn").forEach(btn =>
    btn.addEventListener("click", () => deleteFlow(btn.dataset.id))
  );

  populateFileSelects(files);

  setStatus("listStatus", `Loaded ${files.length} file(s).`);
  log(`Loaded ${files.length} file(s).`);
}

function escHtml(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// Populate all file-id <select> dropdowns with the current accessible file list.
// Called after refreshList() fetches the file list from the server.
// Each option shows "filename (file_id)" so users can identify files without
// memorising opaque IDs. The selects stay in sync every time the list refreshes.
function populateFileSelects(files) {
  const me = getUsername();
  const selects = {
    modifyFileId: files,               // any accessible file can be modified
    grantFileId:  files.filter(f => f.owner === me),  // only owner can grant
    revokeFileId: files.filter(f => f.owner === me),  // only owner can revoke/rotate
  };

  for (const [id, list] of Object.entries(selects)) {
    const sel = document.getElementById(id);
    if (!sel) continue;

    // Preserve current selection so a refresh doesn't lose the user's choice
    const prev = sel.value;

    sel.innerHTML = `<option value="">— select a file —</option>` +
      list.map(f =>
        `<option value="${escHtml(f.file_id)}">${escHtml(f.filename)} (${escHtml(f.file_id)})</option>`
      ).join("");

    // Restore previous selection if it still exists in the new list
    if (prev && [...sel.options].some(o => o.value === prev)) {
      sel.value = prev;
    }
  }
}

async function uploadFlow() {
  const username = getUsername();
  const password = await askPassword("Enter your password to use your local keys:");
  if (!password) {
    setStatus("uploadStatus", "Upload cancelled (password required).");
    return;
  }

  const fileEl = document.getElementById("fileInput");
  if (!fileEl || !fileEl.files || fileEl.files.length === 0) {
    setStatus("uploadStatus", "Choose a file first.");
    return;
  }

  const file = fileEl.files[0];
  const plaintext = await file.arrayBuffer();

  setStatus("uploadStatus", "Encrypting…");

  const dek = crypto.getRandomValues(new Uint8Array(32));
  const enc = await aesGcmEncrypt(plaintext, dek);

  const ownerSpkiB64 = localStorage.getItem(LS.rsaPub(username));
  if (!ownerSpkiB64) {
    setStatus("uploadStatus", "No local public key found. Register on this device first.");
    return;
  }

  const ownerPubKey = await crypto.subtle.importKey(
    "spki",
    b64ToBuf(ownerSpkiB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );

  const wrappedForOwner = await rsaWrap(dek, ownerPubKey);

  // Generate a client-side file_id so we can pre-sign before the server assigns one
  const fileIdBytes = crypto.getRandomValues(new Uint8Array(16));
  // bufToB64 produces standard base64 which can contain '+', '/', and '=' padding.
  // Replace them with URL-safe equivalents ('-', '_') and strip padding so the
  // file_id can be used safely in URL path segments (e.g. GET /download/<file_id>).
  const fileId = bufToB64(fileIdBytes.buffer).replace(/[+/=]/g, c => ({"+":"-","/":"_","=":""})[c]);
  const version = 1;

  setStatus("uploadStatus", "Signing…");
  let signPrivKey;
  try {
    signPrivKey = await loadLocalSignPrivateKey(username, password);
  } catch (e) {
    setStatus("uploadStatus", `❌ Could not load signing key: ${e.message}`);
    return;
  }
  const msgBytes = await makeUploadMessage(fileId, enc.ivB64, enc.ctB64, version);
  const sigB64 = await ecdsaSign(msgBytes, signPrivKey);

  setStatus("uploadStatus", "Uploading ciphertext…");

  let res;
  try {
    res = await api("/upload", {
      method: "POST",
      body: JSON.stringify({
        file_id: fileId,
        filename: file.name,
        nonce_b64: enc.ivB64,
        ciphertext_b64: enc.ctB64,
        wrapped_dek_b64: wrappedForOwner,
        sig_b64: sigB64,
      })
    });
  } catch (e) {
    setStatus("uploadStatus", `Upload failed: ${e.message}`);
    log(`Upload error: ${e.message}`);
    return;
  }

  setStatus("uploadStatus", `✅ Upload successful: ${file.name} (file_id=${res.file_id}, v${res.version})`);
  log(`Uploaded ${file.name} -> ${res.file_id}`);

  await refreshList();
}


async function downloadFlow(fileId) {
  const username = getUsername();
  const password = await askPassword("Enter your password to decrypt locally:");
  if (!password) return;

  let priv;
  try {
    priv = await loadLocalPrivateKey(username, password);
  } catch (e) {
    log(`Private key load error: ${e.message}`);
    return;
  }

  let j;
  try {
    j = await api(`/download/${fileId}`);
  } catch (e) {
    if ((e.message || "").toLowerCase().includes("no access")) {
      alert("You no longer have access to this file. The owner may have rotated the encryption keys.");
      log(`❌ Download blocked: no access (possibly revoked) for file ${fileId}`);
      return;
    }
    alert(`Download failed: ${e.message}`);
    log(`Download API error: ${e.message}`);
    return;
  }

  // Verify signature before decrypting — protects against server tampering
  const sigB64 = j.sig_b64 || "";
  const signer = j.signer || "";
  if (sigB64 && signer) {
    try {
      const signerPubObj = await api(`/user_pubkeys/${signer}`);
      const signerSignPubB64 = signerPubObj.sign_pub_pem_b64;
      const signerSignPub = await importEcdsaPublicKey(signerSignPubB64);
      const msgBytes = await makeUploadMessage(fileId, j.nonce_b64, j.ciphertext_b64, j.version);
      const valid = await ecdsaVerify(msgBytes, sigB64, signerSignPub);
      if (!valid) {
        alert(`⚠️ Signature verification FAILED for file ${fileId} (signer: ${signer}).\nThe ciphertext may have been tampered with. Aborting download.`);
        log(`❌ Signature invalid for ${fileId} — download aborted`);
        return;
      }
      log(`✅ Signature verified: ciphertext signed by ${signer} at version ${j.version}`);
    } catch (e) {
      log(`⚠️ Signature check error: ${e.message} — proceeding without verification`);
    }
  } else {
    log(`⚠️ No signature present for ${fileId} — skipping verification`);
  }

  let dek;
  try {
    dek = await rsaUnwrap(j.wrapped_dek_b64, priv);
  } catch (e) {
    alert("Could not decrypt the file key. Your local private key may be out of sync (try re-registering on this browser).");
    log(`❌ Unwrap failed for ${fileId}: ${e.message}`);
    return;
  }

  let pt;
  try {
    pt = await aesGcmDecrypt(j.nonce_b64, j.ciphertext_b64, dek);
  } catch (e) {
    alert("Could not decrypt the file content. The file may have been rotated and you don't have the new key.");
    log(`❌ Decrypt failed for ${fileId}: ${e.message}`);
    return;
  }

  // Trigger a browser file-save dialog: create an object URL from the decrypted
  // bytes, attach it to a temporary <a> element, click it programmatically, then
  // immediately remove the element and revoke the URL to free memory.
  const blob = new Blob([pt], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = j.filename || `${fileId}.bin`;
  document.body.appendChild(a);
  a.click();
  a.remove();

  log(`Downloaded & decrypted: ${j.filename}`);
}


async function grantFlow() {
  const owner = getUsername();
  const password = await askPassword("Enter your password to grant access:");
  if (!password) return;

  const fileId = (document.getElementById("grantFileId")?.value || "").trim();
  const recipient = (document.getElementById("grantRecipient")?.value || "").trim();
  if (!fileId || !recipient) {
    setStatus("ownerStatus", "Enter file_id + recipient.");
    return;
  }

  setStatus("ownerStatus", "Granting…");
  log(`Grant start: file=${fileId}, recipient=${recipient}`);

  let priv;
  try {
    log("Step 1/5: Loading owner private key…");
    priv = await loadLocalPrivateKey(owner, password);
    log("✅ Step 1 ok");
  } catch (e) {
    setStatus("ownerStatus", `❌ ${e.message}`);
    log(`❌ Step 1 failed: ${e.message}`);
    return;
  }

  let dl;
  try {
    log("Step 2/5: Downloading wrapped DEK for owner…");
    dl = await api(`/download/${fileId}`);
    log("✅ Step 2 ok");
  } catch (e) {
    setStatus("ownerStatus", `❌ Download failed: ${e.message}`);
    log(`❌ Step 2 failed: ${e.message}`);
    return;
  }

  let dek;
  try {
    log("Step 3/5: Unwrapping DEK with owner private key…");
    dek = await rsaUnwrap(dl.wrapped_dek_b64, priv);
    log(`✅ Step 3 ok (DEK length=${dek.length})`);
  } catch (e) {
    setStatus("ownerStatus", `❌ Could not unwrap file key (wrong password/key?): ${e.message}`);
    log(`❌ Step 3 failed: ${e.message}`);
    return;
  }

  let pubObj, recipientPub;
  try {
    log("Step 4/5: Fetching + importing recipient public key…");
    pubObj = await api(`/user_pubkeys/${recipient}`);
    recipientPub = await importSpkiPublicKeyFromServer(pubObj.rsa_pub_pem_b64);
    log("✅ Step 4 ok");
  } catch (e) {
    setStatus("ownerStatus", `❌ Recipient key import failed: ${e.message}`);
    log(`❌ Step 4 failed: ${e.message}`);
    return;
  }

  let wrappedForRecipient;
  try {
    log("Step 5/5: Wrapping DEK for recipient…");
    wrappedForRecipient = await rsaWrap(dek, recipientPub);
    log("✅ Step 5 ok");
  } catch (e) {
    setStatus("ownerStatus", `❌ RSA wrap failed: ${e.message}`);
    log(`❌ Step 5 failed: ${e.message}`);
    return;
  }

  try {
    log("Final: Sending /grant to server…");
    await api("/grant", {
      method: "POST",
      body: JSON.stringify({ file_id: fileId, recipient, wrapped_dek_b64: wrappedForRecipient })
    });
  } catch (e) {
    setStatus("ownerStatus", `❌ Server grant failed: ${e.message}`);
    log(`❌ Server /grant failed: ${e.message}`);
    return;
  }

  setStatus("ownerStatus", `✅ Granted ${recipient} access to ${fileId}.`);
  log(`✅ Grant complete: ${recipient} -> ${fileId}`);
}

async function revokeFlow() {
  // Optional chaining (?.) is used throughout: if a UI element is missing (e.g.
  // the page was loaded without the full dashboard HTML), the value falls back to
  // "" gracefully rather than throwing a TypeError.
  const fileId = (document.getElementById("revokeFileId")?.value || "").trim();
  const recipient = (document.getElementById("revokeRecipient")?.value || "").trim();
  if (!fileId || !recipient) {
    setStatus("ownerStatus", "Enter file_id + recipient.");
    return;
  }

  await api("/revoke", {
    method: "POST",
    body: JSON.stringify({ file_id: fileId, recipient })
  });

  setStatus("ownerStatus", `✅ Revoked ${recipient} access to ${fileId}. Rotate for strong revoke.`);
  log(`Revoked access: ${recipient} -> ${fileId}`);
}

async function modifyFlow() {
  const username = getUsername();
  const password = await askPassword("Enter your password to modify this file:");
  if (!password) {
    setStatus("modifyStatus", "Modification cancelled (password required).");
    return;
  }

  const fileId = (document.getElementById("modifyFileId")?.value || "").trim();
  const fileEl = document.getElementById("modifyFileInput");
  if (!fileId) {
    setStatus("modifyStatus", "Enter a file ID.");
    return;
  }
  if (!fileEl || !fileEl.files || fileEl.files.length === 0) {
    setStatus("modifyStatus", "Choose a modified file first.");
    return;
  }

  setStatus("modifyStatus", "Loading your private keys…");
  let priv, signPrivKey;
  try {
    priv = await loadLocalPrivateKey(username, password);
    signPrivKey = await loadLocalSignPrivateKey(username, password);
  } catch (e) {
    setStatus("modifyStatus", `❌ ${e.message}`);
    return;
  }

  // Download the current wrapped DEK for this user and current version
  setStatus("modifyStatus", "Fetching current file key…");
  let j;
  try {
    j = await api(`/download/${fileId}`);
  } catch (e) {
    setStatus("modifyStatus", `❌ Could not fetch file: ${e.message}`);
    return;
  }

  let dek;
  try {
    dek = await rsaUnwrap(j.wrapped_dek_b64, priv);
  } catch (e) {
    setStatus("modifyStatus", `❌ Could not unwrap file key: ${e.message}`);
    return;
  }

  const newVersion = j.version + 1;

  // Encrypt the new plaintext with the same DEK
  setStatus("modifyStatus", "Encrypting modified file…");
  const plaintext = await fileEl.files[0].arrayBuffer();
  const enc = await aesGcmEncrypt(plaintext, dek);

  // Sign
  const msgBytes = await makeUploadMessage(fileId, enc.ivB64, enc.ctB64, newVersion);
  const sigB64 = await ecdsaSign(msgBytes, signPrivKey);

  setStatus("modifyStatus", "Uploading…");
  let res;
  try {
    res = await api("/update", {
      method: "POST",
      body: JSON.stringify({
        file_id: fileId,
        nonce_b64: enc.ivB64,
        ciphertext_b64: enc.ctB64,
        sig_b64: sigB64,
      })
    });
  } catch (e) {
    setStatus("modifyStatus", `❌ Update failed: ${e.message}`);
    return;
  }

  setStatus("modifyStatus", `✅ File updated (new version=${res.version})`);
  log(`Modified ${fileId} -> version ${res.version}`);
  await refreshList();
}


async function rotateFlow() {
  const username = getUsername();
  const password = await askPassword("Enter your password to decrypt & re-encrypt:");
  if (!password) return;

  // rotateFileId shares the revokeFileId input in the redesigned layout
  const fileId = (document.getElementById("rotateFileId")?.value ||
                  document.getElementById("revokeFileId")?.value || "").trim();
  const allowed = (document.getElementById("rotateAllowed")?.value || "").trim();
  if (!fileId || !allowed) {
    setStatus("ownerStatus", "Enter file_id + allowed users.");
    return;
  }

  // Split on any whitespace (spaces, tabs, newlines) so users can paste a
  // space- or newline-separated list. filter(Boolean) removes empty tokens.
  const allowedUsers = allowed.split(/\s+/).filter(Boolean);

  // Fetch the current allowed users BEFORE rotation to compute who will be revoked
  let oldAllowed = [];
  try {
    const a = await api(`/allowed/${fileId}`);
    oldAllowed = Array.isArray(a.allowed) ? a.allowed : [];
  } catch (e) {
    setStatus("ownerStatus", `❌ Could not fetch current allowed users: ${e.message}`);
    return;
  }

  const revokedUsers = oldAllowed.filter((u) => !allowedUsers.includes(u));

  // Confirm BEFORE doing anything irreversible
  if (revokedUsers.length > 0) {
    const ok = confirm(
      `You are about to revoke access for: ${revokedUsers.join(", ")}.\n\n` +
      "They will no longer be able to decrypt or download this file after rotation.\n\n" +
      "Continue?"
    );
    if (!ok) return;
  }

  const priv = await loadLocalPrivateKey(username, password);

  const j = await api(`/download/${fileId}`);
  const oldDek = await rsaUnwrap(j.wrapped_dek_b64, priv);
  const pt = await aesGcmDecrypt(j.nonce_b64, j.ciphertext_b64, oldDek);

  const newDek = crypto.getRandomValues(new Uint8Array(32));
  const enc = await aesGcmEncrypt(pt, newDek);

  const wrapped_map = {};
  for (const u of allowedUsers) {
    const pubObj = await api(`/user_pubkeys/${u}`);
    const pub = await importSpkiPublicKeyFromServer(pubObj.rsa_pub_pem_b64);
    wrapped_map[u] = await rsaWrap(newDek, pub);
  }

  const newVersion = j.version + 1;
  let signPrivKey;
  try {
    signPrivKey = await loadLocalSignPrivateKey(username, password);
  } catch (e) {
    setStatus("ownerStatus", `❌ Could not load signing key: ${e.message}`);
    return;
  }
  const msgBytes = await makeUploadMessage(fileId, enc.ivB64, enc.ctB64, newVersion);
  const sigB64 = await ecdsaSign(msgBytes, signPrivKey);

  const rr = await api("/rotate", {
    method: "POST",
    body: JSON.stringify({
      file_id: fileId,
      nonce_b64: enc.ivB64,
      ciphertext_b64: enc.ctB64,
      sig_b64: sigB64,
      wrapped_map
    })
  });

  if (revokedUsers.length > 0) {
    setStatus("ownerStatus", `✅ Access revoked for ${revokedUsers.join(", ")}. Rotated key. New version=${rr.version}`);
  } else {
    setStatus("ownerStatus", `✅ Rotated key. New version=${rr.version}`);
  }

  log(`Rotated ${fileId} -> version ${rr.version}`);
  await refreshList();
}

function resetLocalKeysFlow() {
  const u = getUsername();
  if (!u) return;

  const ok1 = confirm("This will delete your locally stored keys for this username in THIS browser only. Continue?");
  if (!ok1) return;

  localStorage.removeItem(LS.rsaPub(u));
  localStorage.removeItem(LS.rsaPriv(u));
  localStorage.removeItem(LS.signPub(u));
  localStorage.removeItem(LS.signPriv(u));

  log(`✅ Local keys cleared for ${u} on this browser.`);
  alert("Local keys cleared. Now go to Register and create the account again (or register with the same username after server clear).");
}


async function deleteFlow(fileId) {
  // fileId can be passed directly (from table button) or read from the input field
  const id = fileId || (document.getElementById("deleteFileId")?.value || "").trim();
  if (!id) {
    setStatus("ownerStatus", "❌ Enter a File ID to delete.");
    return;
  }

  const confirmed = await askConfirm(
    "Permanently delete file?",
    `File ID: ${id}\n\nThis will remove the encrypted file from the server for all users. This action cannot be undone.`,
    "Delete permanently",
    true
  );
  if (!confirmed) return;

  setStatus("ownerStatus", "Deleting…");
  log(`Deleting file ${id}…`);

  try {
    await api(`/delete/${id}`, { method: "DELETE" });
    setStatus("ownerStatus", `✅ File ${id} deleted.`);
    log(`✅ Deleted file ${id}`);
    const inp = document.getElementById("deleteFileId");
    if (inp) inp.value = "";
    await refreshList();
  } catch (e) {
    setStatus("ownerStatus", `❌ Delete failed: ${e.message}`);
    log(`❌ Delete error: ${e.message}`);
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  if (!requireAuthOrRedirect()) return;

  initServerUrlUI();
  log("✅ Dashboard ready: event listeners attaching");
  log(`Server URL: ${getServer()}`);
  log(`Token present: ${getToken() ? "YES" : "NO"}`);
  log(`Username: ${getUsername() || "(none)"}`);

  // Bind buttons safely (won't crash even if IDs mismatch)
  bind("modifyBtn",         "click", () => modifyFlow());
  bind("refreshBtn",        "click", () => refreshList());
  bind("uploadBtn",         "click", () => { log("Upload button clicked"); uploadFlow(); });
  bind("grantBtn",          "click", () => grantFlow());
  bind("revokeBtn",         "click", () => revokeFlow());
  bind("rotateBtn",         "click", () => rotateFlow());
  bind("deleteBtn",         "click", () => deleteFlow());
  // Logout is handled by #navLogout injected by navbar.js;
  // bind() here covers any page that still has a static #logoutBtn.
  bind("logoutBtn", "click", () => {
    localStorage.removeItem(LS.token);
    localStorage.removeItem(LS.username);
    location.href = "/login";
  });
  // Also wire the navbar logout button if present (rendered after DOMContentLoaded by navbar.js)
  const navLogout = document.getElementById("navLogout");
  if (navLogout) {
    navLogout.addEventListener("click", (e) => {
      e.preventDefault();
      localStorage.removeItem(LS.token);
      localStorage.removeItem(LS.username);
      location.href = "/login";
    });
  }
  bind("resetLocalKeysBtn", "click", () => resetLocalKeysFlow());

  await refreshList();
});
