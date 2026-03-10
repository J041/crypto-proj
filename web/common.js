const LS = {
  serverUrl: "acrypt_server_url",
  token: "acrypt_token",
  username: "acrypt_username",
  rsaPub: (u) => `acrypt_${u}_rsa_pub_spki_b64`,
  rsaPriv: (u) => `acrypt_${u}_rsa_priv_pkcs8_enc_b64`,
  signPub: (u) => `acrypt_${u}_sign_pub_spki_b64`,
  signPriv: (u) => `acrypt_${u}_sign_priv_pkcs8_enc_b64`,
};

function log(msg) {
  const box = document.getElementById("logBox");
  if (!box) return;
  box.textContent += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
  box.scrollTop = box.scrollHeight;
}

function setStatus(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg;
}

function getServer() {
  return localStorage.getItem(LS.serverUrl) || "http://127.0.0.1:5000";
}
function getToken() {
  return localStorage.getItem(LS.token) || "";
}
function getUsername() {
  return localStorage.getItem(LS.username) || "";
}

function initServerUrlUI() {
  const inp = document.getElementById("serverUrl");
  if (inp) inp.value = getServer();

  const btn = document.getElementById("saveServer");
  if (btn) {
    btn.addEventListener("click", () => {
      const v = (inp?.value || "").trim();
      localStorage.setItem(LS.serverUrl, v);
      log(`Server URL set to ${v}`);
    });
  }
}

async function api(path, opts = {}) {
  const url = `${getServer()}${path}`;
  const headers = opts.headers || {};
  if (getToken()) headers["Authorization"] = `Bearer ${getToken()}`;
  if (!headers["Content-Type"] && opts.body) headers["Content-Type"] = "application/json";

  const res = await fetch(url, { ...opts, headers });

  const contentType = res.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await res.json().catch(() => null)
    : await res.text().catch(() => "");

  if (!res.ok) {
    // Extract the most informative error message available:
    // prefer the server's JSON "error" field, then raw text, then the HTTP status code.
    const msg =
      (payload && typeof payload === "object" && payload.error) ? payload.error :
      (typeof payload === "string" && payload.trim()) ? payload :
      `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return payload;
}

function bufToB64(buf) {
  // Convert an ArrayBuffer/TypedArray to a base64 string.
  // We build a binary string first because btoa() only accepts strings, not raw buffers.
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64ToBuf(b64) {
  // Convert a base64 string back to an ArrayBuffer for use with WebCrypto APIs.
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---- DEBUG: show any JS errors on screen ----
window.addEventListener("error", (e) => {
  try { log(`❌ JS Error: ${e.message} @ ${e.filename}:${e.lineno}`); } catch {}
});

window.addEventListener("unhandledrejection", (e) => {
  try { log(`❌ Promise Error: ${e.reason?.message || e.reason}`); } catch {}
});

console.log("[ACrypt] common.js loaded");
