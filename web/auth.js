async function deriveKeyFromPassword(password, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptLocalPrivateKey(pkcs8Bytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pkcs8Bytes);
  return `${bufToB64(salt.buffer)}.${bufToB64(iv.buffer)}.${bufToB64(ct)}`;
}

async function generateRsaKeypairForWrap() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function ensureLocalKeys(username, password) {
  const pubB64 = localStorage.getItem(LS.rsaPub(username));
  const privPacked = localStorage.getItem(LS.rsaPriv(username));
  if (pubB64 && privPacked) return;

  log(`Generating RSA keypair locally for ${username}...`);
  const kp = await generateRsaKeypairForWrap();
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);

  localStorage.setItem(LS.rsaPub(username), bufToB64(spki));
  localStorage.setItem(LS.rsaPriv(username), await encryptLocalPrivateKey(pkcs8, password));
  log(`Saved local keys (encrypted private key).`);
}

async function registerFlow() {
  const username = document.getElementById("regUser").value.trim();
  const password = document.getElementById("regPass").value;
  if (!username || !password) throw new Error("Enter username + password.");

  await ensureLocalKeys(username, password);
  const ownerSpkiB64 = localStorage.getItem(LS.rsaPub(username));

  // Server stores raw bytes base64-encoded (we reuse the existing field name)
  const rsa_pub_raw = b64ToBuf(ownerSpkiB64);
  const rsa_pub_b64 = bufToB64(rsa_pub_raw);

  // Placeholder signing pubkey (not used by server in this build)
  const sign_pub_b64 = rsa_pub_b64;

  await api("/register", {
    method: "POST",
    body: JSON.stringify({
      username,
      password,
      rsa_pub_pem_b64: rsa_pub_b64,
      sign_pub_pem_b64: sign_pub_b64,
    })
  });

  log(`Registered: ${username}`);
}

async function loginFlow() {
  const username = document.getElementById("logUser").value.trim();
  const password = document.getElementById("logPass").value;
  if (!username || !password) throw new Error("Enter username + password.");

  // Requires registering on this device (or implement key import/export)
  await ensureLocalKeys(username, password);

  const j = await api("/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });

  localStorage.setItem(LS.token, j.token);
  localStorage.setItem(LS.username, username);
  log(`Logged in as ${username}`);
}
