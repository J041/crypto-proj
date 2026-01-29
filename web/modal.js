// Simple password modal returning a Promise<string|null>
function askPassword(title = "Enter password") {
  return new Promise((resolve) => {
    const modal = document.getElementById("pwModal");
    const titleEl = document.getElementById("pwTitle");
    const input = document.getElementById("pwInput");
    const ok = document.getElementById("pwOk");
    const cancel = document.getElementById("pwCancel");

    if (!modal || !titleEl || !input || !ok || !cancel) {
      // fallback (still visible) if modal missing
      const p = window.prompt(title);
      resolve(p);
      return;
    }

    titleEl.textContent = title;
    input.value = "";
    modal.classList.add("open");
    input.focus();

    const cleanup = (val) => {
      modal.classList.remove("open");
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      input.removeEventListener("keydown", onKey);
      resolve(val);
    };

    const onOk = () => cleanup(input.value || null);
    const onCancel = () => cleanup(null);

    const onKey = (e) => {
      if (e.key === "Enter") onOk();
      if (e.key === "Escape") onCancel();
    };

    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    input.addEventListener("keydown", onKey);
  });
}
