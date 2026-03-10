// ---- Password modal (returns Promise<string|null>) ----
function askPassword(title = "Enter password") {
  return new Promise((resolve) => {
    const modal  = document.getElementById("pwModal");
    const titleEl= document.getElementById("pwTitle");
    const input  = document.getElementById("pwInput");
    const ok     = document.getElementById("pwOk");
    const cancel = document.getElementById("pwCancel");

    if (!modal || !titleEl || !input || !ok || !cancel) {
      resolve(window.prompt(title)); return;
    }

    titleEl.textContent = title;
    input.value = "";
    modal.classList.add("open");
    setTimeout(() => input.focus(), 50);

    const cleanup = (val) => {
      modal.classList.remove("open");
      ok.removeEventListener("click", onOk);
      cancel.removeEventListener("click", onCancel);
      input.removeEventListener("keydown", onKey);
      resolve(val);
    };
    const onOk     = () => cleanup(input.value || null);
    const onCancel = () => cleanup(null);
    const onKey    = (e) => { if (e.key === "Enter") onOk(); if (e.key === "Escape") onCancel(); };

    ok.addEventListener("click", onOk);
    cancel.addEventListener("click", onCancel);
    input.addEventListener("keydown", onKey);
  });
}

// ---- Confirm modal (returns Promise<boolean>) ----
function askConfirm(title, message, confirmLabel = "Confirm", danger = true) {
  return new Promise((resolve) => {
    const modal   = document.getElementById("confirmModal");
    const titleEl = document.getElementById("confirmTitle");
    const msgEl   = document.getElementById("confirmMessage");
    const okBtn   = document.getElementById("confirmOk");
    const cancelBtn = document.getElementById("confirmCancel");

    if (!modal || !titleEl || !msgEl || !okBtn || !cancelBtn) {
      resolve(window.confirm(`${title}\n\n${message}`)); return;
    }

    titleEl.textContent = title;
    msgEl.textContent   = message;
    okBtn.textContent   = confirmLabel;
    okBtn.className     = danger ? "danger" : "";
    modal.classList.add("open");

    const cleanup = (val) => {
      modal.classList.remove("open");
      okBtn.removeEventListener("click", onOk);
      cancelBtn.removeEventListener("click", onCancel);
      resolve(val);
    };
    const onOk     = () => cleanup(true);
    const onCancel = () => cleanup(false);
    okBtn.addEventListener("click", onOk);
    cancelBtn.addEventListener("click", onCancel);
  });
}
