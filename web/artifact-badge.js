/* External stylesheet required; no inline styles, HTML injection or handlers. */
(() => {
  "use strict";
  const valid = /^[0-9a-f]{6}$/;
  const ready = new WeakSet();
  function prepare(el) {
    const id = el.getAttribute("data-aid");
    if (!valid.test(id || "")) return;
    el.textContent = "a#" + id;
    el.title = "Artefakt-ID – klicken zum Kopieren";
    el.setAttribute("role", "button");
    el.setAttribute("tabindex", "0");
    if (ready.has(el)) return;
    ready.add(el);
    async function copy(event) {
      if (event.type === "keydown" && !["Enter", " "].includes(event.key)) return;
      event.preventDefault(); event.stopPropagation();
      const current = el.getAttribute("data-aid");
      if (!valid.test(current || "")) return;
      try {
        await navigator.clipboard.writeText("a#" + current);
        const toast = document.createElement("span");
        toast.className = "aid-toast"; toast.textContent = "kopiert";
        toast.setAttribute("role", "status"); document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 1100);
      } catch (_) { /* Do not claim success when clipboard permission is denied. */ }
    }
    el.addEventListener("click", copy); el.addEventListener("keydown", copy);
  }
  function scan(root) {
    if (root.nodeType !== 1 && root.nodeType !== 9) return;
    if (root.matches && root.matches(".aid[data-aid]")) prepare(root);
    root.querySelectorAll(".aid[data-aid]").forEach(prepare);
  }
  function start() {
    scan(document);
    new MutationObserver(records => records.forEach(record => {
      if (record.type === "attributes") scan(record.target);
      else record.addedNodes.forEach(scan);
    })).observe(document.documentElement, {subtree: true, childList: true,
      attributes: true, attributeFilter: ["data-aid", "class"]});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, {once: true});
  else start();
})();
