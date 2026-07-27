document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (button) {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      const original = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => { button.textContent = original; }, 1200);
    } catch (_) {
      button.textContent = "Copy failed";
    }
  }
});
