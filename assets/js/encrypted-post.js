(function () {
  "use strict";

  const container = document.querySelector(".encrypted-post");
  if (!container) return;

  function base64ToBytes(b64) {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }

  const salt = base64ToBytes(container.dataset.salt);
  const iv = base64ToBytes(container.dataset.iv);
  const sealed = base64ToBytes(container.dataset.ciphertext);
  const iterations = parseInt(container.dataset.iterations, 10);
  const prompt =
    (document.currentScript && document.currentScript.dataset.prompt) ||
    container.dataset.prompt ||
    "This post is encrypted. Enter the flag that unlocks it:";

  async function deriveKey(password) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  function renderForm(errorMessage) {
    container.innerHTML = "";

    const form = document.createElement("form");
    form.className = "decrypt-gate";

    const label = document.createElement("p");
    label.textContent = prompt;
    form.appendChild(label);

    if (errorMessage) {
      const error = document.createElement("p");
      error.className = "decrypt-error";
      error.textContent = errorMessage;
      form.appendChild(error);
    }

    const input = document.createElement("input");
    input.type = "password";
    input.name = "flag";
    input.autocomplete = "off";
    input.placeholder = "flag";
    input.required = true;
    form.appendChild(input);

    const button = document.createElement("button");
    button.type = "submit";
    button.textContent = "Decrypt";
    form.appendChild(button);

    form.addEventListener("submit", onSubmit);
    container.appendChild(form);
    input.focus();
  }

  async function onSubmit(event) {
    event.preventDefault();
    const password = event.target.flag.value.trim();
    try {
      const key = await deriveKey(password);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, sealed);
      container.innerHTML = new TextDecoder().decode(plaintext);
      document.dispatchEvent(new CustomEvent("post:decrypted"));
    } catch (err) {
      renderForm("Incorrect flag, try again.");
    }
  }

  renderForm();
})();
