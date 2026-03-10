async function deriveKeyFromPassword(password, saltBytes) {
  const enc = new TextEncoder();
  // Import the raw password bytes as a PBKDF2 "base key" — WebCrypto requires
  // this two-step process before the actual key derivation can happen.
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,        // non-extractable: the base key cannot be read back out of WebCrypto
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,        // non-extractable: the derived AES key stays inside WebCrypto
    ["encrypt", "decrypt"]
  );
}

async function encryptLocalPrivateKey(pkcs8Bytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pkcs8Bytes);
  // Pack as "salt.iv.ciphertext" (all base64), so everything needed for decryption
  // travels together in a single localStorage string.
  return `${bufToB64(salt.buffer)}.${bufToB64(iv.buffer)}.${bufToB64(ct)}`;
}

async function generateRsaKeypairForWrap() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      // publicExponent 65537 as a 3-byte big-endian Uint8Array: [0x01, 0x00, 0x01]
      // This is the standard Fermat F4 exponent, universally recommended.
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,          // extractable: we need to export and store the key bytes
    ["encrypt", "decrypt"]
  );
}

async function generateEcdsaKeypairForSign() {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,          // extractable: needed so we can export and store the key
    ["sign", "verify"]
  );
}

async function ensureLocalKeys(username, password) {
  const pubB64 = localStorage.getItem(LS.rsaPub(username));
  const privPacked = localStorage.getItem(LS.rsaPriv(username));
  const signPubB64 = localStorage.getItem(LS.signPub(username));
  const signPrivPacked = localStorage.getItem(LS.signPriv(username));

  if (!pubB64 || !privPacked) {
    log(`Generating RSA keypair locally for ${username}...`);
    const kp = await generateRsaKeypairForWrap();
    const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
    localStorage.setItem(LS.rsaPub(username), bufToB64(spki));
    localStorage.setItem(LS.rsaPriv(username), await encryptLocalPrivateKey(pkcs8, password));
    log(`Saved local RSA keys.`);
  }

  if (!signPubB64 || !signPrivPacked) {
    log(`Generating ECDSA P-256 signing keypair for ${username}...`);
    const skp = await generateEcdsaKeypairForSign();
    const signSpki = await crypto.subtle.exportKey("spki", skp.publicKey);
    const signPkcs8 = await crypto.subtle.exportKey("pkcs8", skp.privateKey);
    localStorage.setItem(LS.signPub(username), bufToB64(signSpki));
    localStorage.setItem(LS.signPriv(username), await encryptLocalPrivateKey(signPkcs8, password));
    log(`Saved local ECDSA signing keys.`);
  }
}

async function registerFlow() {
  const username = document.getElementById("regUser").value.trim();
  const password = document.getElementById("regPass").value;
  if (!username || !password) throw new Error("Enter username + password.");

  await ensureLocalKeys(username, password);
  const ownerSpkiB64 = localStorage.getItem(LS.rsaPub(username));
  const signSpkiB64 = localStorage.getItem(LS.signPub(username));

  // Re-encode through bufToB64(b64ToBuf(...)) to normalise padding: localStorage
  // may hold a slightly different base64 variant depending on how the key was
  // exported. This round-trip ensures the server always receives canonical base64.
  const rsa_pub_b64 = bufToB64(b64ToBuf(ownerSpkiB64));
  const sign_pub_b64 = bufToB64(b64ToBuf(signSpkiB64));

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

  // ensureLocalKeys generates new keypairs if none exist in localStorage for this
  // username. On a device the user already registered from, the existing keys are
  // reused and only the server authentication call is made below.
  await ensureLocalKeys(username, password);

  const j = await api("/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });

  localStorage.setItem(LS.token, j.token);
  localStorage.setItem(LS.username, username);
  log(`Logged in as ${username}`);
}
