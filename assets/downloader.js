const $ = s => document.querySelector(s);
const log = (m) => { const el = $("#log"); el.textContent += m + "\n"; el.scrollTop = el.scrollHeight; };

async function getManifest(prefix) {
  const r = await fetch((prefix || "") + "/manifest");
  if (!r.ok) throw new Error("manifest HTTP " + r.status);
  return await r.json();
}

function downloadOne(prefix, p) {
  const a = document.createElement("a");
  a.href = (prefix || "") + "/file/" + encodeURI(p);
  a.download = p.split("/").pop() || "file";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function run() {
  const prefix = $("#prefix").value.trim();
  const conc = Math.max(1, Math.min(64, Number($("#conc").value) || 8));
  log("Загружаю манифест...");
  const paths = await getManifest(prefix);
  log("Файлов: " + paths.length + ". Параллельность: " + conc);

  let i = 0, active = 0;

  function pump() {
    while (active < conc && i < paths.length) {
      const p = paths[i++]; active++;
      try { downloadOne(prefix, p); } catch (e) { log("ошибка: " + p + " -> " + e); }
      active--;
      log("старт: " + i + "/" + paths.length + " (" + p + ")");
    }
    if (i >= paths.length && active === 0) {
      log("ГОТОВО");
    } else {
      requestAnimationFrame(pump);
    }
  }
  pump();
}

window.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#go").addEventListener("click", () => {
    document.querySelector("#log").textContent = "";
    run().catch(e => log("FATAL: " + e));
  });
});
