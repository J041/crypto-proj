function renderNavbar() {
  const username = getUsername();
  const loggedIn = !!(getToken() && username);

  const nav = document.createElement("div");
  nav.className = "navbar";

  const left = document.createElement("div");
  left.className = "nav-left";
  left.innerHTML = `
    <span class="nav-title">ACrypt</span>
  `;

  const right = document.createElement("div");
  right.className = "nav-right";

  if (loggedIn) {
    right.innerHTML = `
      <span class="nav-meta">Logged in: ${username}</span>
      <a class="nav-link" href="/dashboard">Back to dashboard</a>
      <a class="nav-link" href="#" id="navLogout">Logout</a>
    `;
  } else {
    right.innerHTML = `
      <a class="nav-link" href="/login">Login</a>
      <a class="nav-link" href="/register">Register</a>
    `;
  }

  nav.appendChild(left);
  nav.appendChild(right);

  // Insert below header, before main
  const header = document.querySelector("header");
  if (header) header.insertAdjacentElement("afterend", nav);

  const logout = document.getElementById("navLogout");
  if (logout) {
    logout.addEventListener("click", (e) => {
      e.preventDefault();
      localStorage.removeItem(LS.token);
      localStorage.removeItem(LS.username);
      location.href = "/login";
    });
  }
}

window.addEventListener("DOMContentLoaded", () => {
  try { renderNavbar(); } catch {}
});
