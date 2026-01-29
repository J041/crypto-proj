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
    setStatus("listStatus", "Server returned unexpected data (not a list). Check Server URL.");
    log(`List returned non-array: ${JSON.stringify(files).slice(0, 200)}`);
    return;
  }

  const tb = document.getElementById("filesTbody");
  if (!tb) {
    log("❌ Missing #filesTbody");
    return;
  }
  tb.innerHTML = "";

  if (files.length === 0) {
    setStatus("listStatus", "No accessible files yet.");
    return;
  }

  for (const f of files) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${f.file_id}</code></td>
      <td>${f.filename}</td>
      <td>${f.owner}</td>
      <td>${f.version}</td>
      <td class="row">
        <button type="button" data-id="${f.file_id}" class="dlBtn">Download</button>
      </td>
    `;
    tb.appendChild(tr);
  }

  tb.querySelectorAll(".dlBtn").forEach(btn => {
    btn.addEventListener("click", () => downloadFlow(btn.dataset.id));
  });

  setStatus("listStatus", `Loaded ${files.length} file(s).`);
  log(`Loaded ${files.length} file(s).`);
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

  setStatus("uploadStatus", "Uploading ciphertext…");

  let res;
  try {
    res = await api("/upload", {
      method: "POST",
      body: JSON.stringify({
        filename: file.name,
        nonce_b64: enc.ivB64,
        ciphertext_b64: enc.ctB64,
        wrapped_dek_b64: wrappedForOwner
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
    log(`Download API error: ${e.message}`);
    return;
  }

  const dek = await rsaUnwrap(j.wrapped_dek_b64, priv);
  const pt = await aesGcmDecrypt(j.nonce_b64, j.ciphertext_b64, dek);

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

async function rotateFlow() {
  const username = getUsername();
  const password = await askPassword("Enter your password to decrypt & re-encrypt:");
  if (!password) return;

  const fileId = (document.getElementById("rotateFileId")?.value || "").trim();
  const allowed = (document.getElementById("rotateAllowed")?.value || "").trim();
  if (!fileId || !allowed) {
    setStatus("ownerStatus", "Enter file_id + allowed users.");
    return;
  }

  const allowedUsers = allowed.split(/\s+/).filter(Boolean);
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

  const rr = await api("/rotate", {
    method: "POST",
    body: JSON.stringify({
      file_id: fileId,
      nonce_b64: enc.ivB64,
      ciphertext_b64: enc.ctB64,
      wrapped_map
    })
  });

  setStatus("ownerStatus", `✅ Rotated key. New version=${rr.version}`);
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

  log(`✅ Local keys cleared for ${u} on this browser.`);
  alert("Local keys cleared. Now go to Register and create the account again (or register with the same username after server clear).");
}


window.addEventListener("DOMContentLoaded", async () => {
  if (!requireAuthOrRedirect()) return;

  initServerUrlUI();
  log("✅ Dashboard ready: event listeners attaching");
  log(`Server URL: ${getServer()}`);
  log(`Token present: ${getToken() ? "YES" : "NO"}`);
  log(`Username: ${getUsername() || "(none)"}`);

  // Bind buttons safely (won't crash even if IDs mismatch)
  bind("refreshBtn", "click", () => refreshList());
  bind("uploadBtn", "click", () => {
    log("Upload button clicked");
    uploadFlow();
  });
  bind("grantBtn", "click", () => grantFlow());
  bind("revokeBtn", "click", () => revokeFlow());
  bind("rotateBtn", "click", () => rotateFlow());
  bind("logoutBtn", "click", () => {
    localStorage.removeItem(LS.token);
    localStorage.removeItem(LS.username);
    location.href = "/login";
  });
  bind("resetLocalKeysBtn", "click", () => resetLocalKeysFlow());

  await refreshList();
});
