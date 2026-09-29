const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const vis = (e) => !!(e.offsetParent || e.getClientRects().length);
const set = (el, v) => {
  const p = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(p, "value").set.call(el, v);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
};
const dlg = () => [...document.querySelectorAll(".bx--modal.is-visible")][0];
const scope = () => dlg() || document;
const btn = (t) => [...scope().querySelectorAll("button")].filter((b) => vis(b) && b.textContent.trim().startsWith(t))[0];
const labels = (l) => [...scope().querySelectorAll("label")].filter((x) => vis(x) && x.textContent.trim().startsWith(l));
const field = (l) => { const lab = labels(l)[0]; return lab && document.getElementById(lab.getAttribute("for")); };
const tick = (l) => { const lab = labels(l)[0]; if (!lab) return "MISSING " + l; lab.click(); return "ok"; };
const vm = (name) => { let c = document.querySelector(".page-title").__vue__; while (c && c.$options.name !== name) c = c.$parent; return c; };
const errs = () => [...document.querySelectorAll(".bx--form-requirement,.bx--inline-notification__subtitle")].filter(vis).map((e) => e.textContent.trim()).filter(Boolean);
const rows = (sel) => [...document.querySelectorAll(sel + " tbody tr")].map((r) => r.innerText.replace(/\s*\n+\s*/g, " / ").replace(/\t/g, " "));
