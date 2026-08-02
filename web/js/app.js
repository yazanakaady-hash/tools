import { initScene, renderGraph } from "./scene3d.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const titles = {
  dashboard: ["YAZAN · الملف الذهبي", "بطاقة شخصية + 29 محركاً — سيطرة كاملة، تشفير، إخفاء، حذف آمن"],
  elite: ["🛡️ المنظومة المتكاملة", "9 وحدات: الممحاة الكمومية · الدرع المتعدد · المنظف العصبي · المستودع الأعمى · المدمج الخفي · الرمز الانتحاري"],
  "shell-ripper": ["تمزيق الأصداف", "فك طبقات + تنبؤ إنتروبيا الطبقة التالية"],
  memory: ["مصيدة المفاتيح العمياء", "Dump أو PID — مسح سجلات و Stack frames"],
  network: ["محلل بروتوكول الشبكة", "PCAP → بصمة C2 / DNS / TLS"],
  "reverse-timestamp": ["البصمة الزمنية المعكوسة", "Toolchain → CVE + خطة استغلال"],
  sovereignty: ["محطم السيادة", "سحق Anti-Debug + TimeStamps + IsDebuggerPresent"],
  "tetra-cube": ["المكعب الرباعي 4D", "وقت · ذاكرة · مسجلات · حلقات I/O"],
  "ghost-spectrum": ["الطيف الخفي", "PEB/ELF من الكاش — invisible للـ kernel"],
  "ant-colony": ["مستعمرة النمل", "10K خيط افتراضي — أضعف قفزة خلال 300ms"],
  "brain-link": ["الوصلة الدماغية", "توقع كود C الأصلي حتى مع التشويش"],
  kamikaze: ["المحرك الانتحاري", "500 عملية صغرى تعيد التجمع على نواة أخرى"],
  "shattered-mind": ["العقل المتشظي", "1000 شظية عبر خيوط CPU — CFG خلال 400ms"],
  blackhole: ["ثقب الهندسة الأسود", "ETW + حذف استباقي قبل كتابة القرص"],
  speculative: ["الحاقن التخميني", "Spectre-v2 — صفر كتابة، صفر اكتشاف"],
  "compiler-flip": ["مقلب المترجم", "اختطاف AST وإدخال باب خلفي لكل eval/exec"],
  "weighted-future": ["المستقبل الموزون", "توقع قيم المسجلات 5 دورات للأمام بـ LSTM"],
  "register-puzzle": ["أحجية السجل", "إعادة بناء مفتاح التشفير من انزياح XMM"],
  "silent-plague": ["الطاعون الصامت", "اختباء SMRAM + إعادة حقن ACPI"],
};

let currentFile = null;
let lastGraph = null;
let entropyVal = 0;

/* ═══════════════════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════════════════ */

function toast(msg, type = "") {
  const t = $("#toast");
  if (!t) return;
  t.textContent = msg;
  t.className = `toast ${type}`;
  clearTimeout(t._tm);
  t._tm = setTimeout(() => t.classList.add("hidden"), 3500);
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function tbl(headers, rows) {
  if (!rows || !rows.length) return "<p class='muted'>—</p>";
  const th = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const tr = rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
    .join("");
  return `<table class="tbl"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}

function formatJSON(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function safe(val, fallback = "—") {
  return val === undefined || val === null || val === "" ? fallback : val;
}

function hexOff(n) {
  if (n === undefined || n === null) return "—";
  return "0x" + Number(n).toString(16);
}

async function pickFile(multiple = false) {
  return new Promise((res, rej) => {
    const inp = document.createElement("input");
    inp.type = "file";
    inp.multiple = multiple;
    inp.onchange = () => res(inp.files);
    inp.oncancel = () => rej(new Error("cancelled"));
    inp.click();
  });
}

async function postFile(url, fileOverride) {
  if (!currentFile && !fileOverride) throw new Error("اختر ملفاً أولاً");
  const fd = new FormData();
  fd.append("file", fileOverride || currentFile);
  const r = await fetch(url, { method: "POST", body: fd });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || j.message || `HTTP ${r.status}`);
  return j;
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || j.message || `HTTP ${r.status}`);
  return j;
}

function showResult(id, data) {
  const el = $(`#${id}`);
  if (!el) return;
  el.textContent = formatJSON(data);
  el.classList.add("show");
}

function setProgress(pct, label) {
  const fill = $("#ribProgressFill");
  const lbl = $("#ribProgressLabel");
  if (fill) fill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  if (lbl) lbl.textContent = label || `${pct}%`;
}

/* ═══════════════════════════════════════════════════════════
   TAB NAVIGATION
   ═══════════════════════════════════════════════════════════ */

function setTab(name) {
  $$(".nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name)
  );
  $$(".tab").forEach((el) =>
    el.classList.toggle("active", el.id === `tab-${name}`)
  );
  const [t, s] = titles[name] || titles.dashboard;
  const pt = $("#pageTitle");
  const ps = $("#pageSub");
  if (pt) pt.textContent = t;
  if (ps) ps.textContent = s;

  if (name === "tetra-cube") {
    const c = $("#c3d");
    if (c) {
      initScene(c);
      if (lastGraph) renderGraph(lastGraph);
    }
  }

  const sensitive = [
    "kamikaze",
    "silent-plague",
    "ghost-spectrum",
    "speculative",
    "sovereignty",
  ];
  const blur = $("#quantumBlur");
  if (blur) blur.classList.toggle("on", sensitive.includes(name));

  document.dispatchEvent(new CustomEvent("tabchange", { detail: name }));
}

$$(".nav button").forEach((b) =>
  b.addEventListener("click", () => setTab(b.dataset.tab))
);

$$(".card.feature").forEach((c) =>
  c.addEventListener("click", () => {
    const nav = c.dataset.nav;
    if (nav) setTab(nav);
  })
);

/* ═══════════════════════════════════════════════════════════
   QUICK ACTION RIBBON
   ═══════════════════════════════════════════════════════════ */

const dropZone = $("#dropZone");
let ribbonFile = null;

if (dropZone) {
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });
  dropZone.addEventListener("dragleave", () =>
    dropZone.classList.remove("drag-over")
  );
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    const f = e.dataTransfer.files[0];
    if (f) {
      ribbonFile = f;
      currentFile = f;
      dropZone.textContent = `📎 ${f.name}`;
      updateEntropy(f);
    }
  });
  dropZone.addEventListener("click", async () => {
    try {
      const files = await pickFile();
      if (files[0]) {
        ribbonFile = files[0];
        currentFile = files[0];
        dropZone.textContent = `📎 ${files[0].name}`;
        updateEntropy(files[0]);
      }
    } catch (_) {}
  });
}

async function updateEntropy(file) {
  if (!file) return;
  try {
    const buf = await file.arrayBuffer();
    const data = new Uint8Array(buf);
    const freq = {};
    for (const b of data) freq[b] = (freq[b] || 0) + 1;
    let H = 0;
    const n = data.length || 1;
    for (const c of Object.values(freq)) {
      const p = c / n;
      H -= p * Math.log2(p);
    }
    entropyVal = H;
    const el = $("#ribEntropy");
    if (el) {
      el.textContent = `H=${H.toFixed(3)}`;
      el.style.color =
        H > 7.8 ? "var(--blood)" : H > 7 ? "var(--warn)" : "var(--good)";
    }
  } catch (_) {}
}

/* Ribbon: Encrypt / Decrypt / Stego work via file upload — good */
$("#ribEncrypt")?.addEventListener("click", async () => {
  if (!ribbonFile) return toast("اسحب ملفاً أولاً", "err");
  const pw = prompt("كلمة المرور للتشفير:");
  if (!pw) return;
  setProgress(20, "جاري التشفير…");
  try {
    const fd = new FormData();
    fd.append("file", ribbonFile);
    fd.append("password", pw);
    const r = await fetch("/api/shield/encrypt", { method: "POST", body: fd });
    const d = await r.json();
    setProgress(100, d.ok ? "✓ مشفر" : "✗ فشل");
    if (d.download) window.open(d.download);
    toast(d.ok ? `✓ ${d.size_out || "?"} bytes` : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
    setProgress(0, "خطأ");
  }
});

$("#ribDecrypt")?.addEventListener("click", async () => {
  if (!ribbonFile) return toast("اسحب ملفاً أولاً", "err");
  const pw = prompt("كلمة المرور لفك التشفير:");
  if (!pw) return;
  setProgress(20, "جاري فك التشفير…");
  try {
    const fd = new FormData();
    fd.append("file", ribbonFile);
    fd.append("password", pw);
    const r = await fetch("/api/shield/decrypt", { method: "POST", body: fd });
    const d = await r.json();
    setProgress(100, d.ok ? "✓ تم الفك" : "✗ فشل");
    if (d.download) window.open(d.download);
    toast(d.ok ? `✓ ${d.size_out || "?"} bytes` : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
    setProgress(0, "خطأ");
  }
});

$("#ribStegoHide")?.addEventListener("click", async () => {
  if (!ribbonFile) return toast("اسحب ملفاً أولاً (صورة الغلاف)", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const pw = prompt("كلمة سر للإخفاء (اختياري):") || "";
    setProgress(30, "جاري الإخفاء…");
    const fd = new FormData();
    fd.append("cover", ribbonFile);
    fd.append("payload", files[0]);
    fd.append("password", pw);
    const r = await fetch("/api/stego/hide", { method: "POST", body: fd });
    const d = await r.json();
    setProgress(100, d.ok ? "✓ مخفي" : "✗ فشل");
    if (d.download) window.open(d.download);
    toast(
      d.ok ? `✓ ratio=${d.hide_ratio ?? "?"}` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
    setProgress(0, "خطأ");
  }
});

$("#ribStegoExtract")?.addEventListener("click", async () => {
  if (!ribbonFile) return toast("اسحب ملفاً أولاً", "err");
  const pw = prompt("كلمة سر الاستخراج (اختياري):") || "";
  setProgress(30, "جاري الاستخراج…");
  try {
    const fd = new FormData();
    fd.append("file", ribbonFile);
    fd.append("password", pw);
    const r = await fetch("/api/stego/extract", { method: "POST", body: fd });
    const d = await r.json();
    setProgress(100, d.ok ? "✓ تم" : "✗ فشل");
    if (d.download) window.open(d.download);
    toast(
      d.ok ? `✓ ${d.extracted_size || "?"} bytes` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
    setProgress(0, "خطأ");
  }
});

/* Wipe / Clean need server-side paths — warn user */
$("#ribWipe")?.addEventListener("click", async () => {
  toast(
    "المسح الكمومي يحتاج مسار ملف على السيرفر. استخدم تبويب المنظومة المتكاملة.",
    "err"
  );
});

$("#ribClean")?.addEventListener("click", async () => {
  toast(
    "تنظيف البيانات الوصفية يحتاج مسار على السيرفر. استخدم تبويب المنظومة المتكاملة.",
    "err"
  );
});

/* ═══════════════════════════════════════════════════════════
   ELITE SYSTEM MODULES
   ═══════════════════════════════════════════════════════════ */

/* Quantum Wiper */
$("#btnWipe")?.addEventListener("click", async () => {
  const path = $("#wiperPath")?.value?.trim();
  if (!path) return toast("أدخل مسار الملف على السيرفر", "err");
  if (!confirm(`تأكيد المسح الكمومي لـ ${path}؟ لا يمكن التراجع!`)) return;
  try {
    const d = await postJSON("/api/wipe", {
      path,
      passes: 7,
      zero_mft: true,
    });
    showResult("wiperResult", d);
    toast(
      d.ok
        ? `✓ ${d.passes_applied || "?"} تمريرات · ${d.elapsed_sec || "?"}s`
        : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnWipeDir")?.addEventListener("click", async () => {
  const path = $("#wiperPath")?.value?.trim();
  if (!path) return toast("أدخل مسار المجلد", "err");
  if (!confirm(`تأكيد مسح كل ملفات ${path}؟`)) return;
  try {
    const d = await postJSON("/api/wipe-dir", { path });
    showResult("wiperResult", d);
    toast(
      d.ok ? `✓ ${d.files_wiped || 0} ملف` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Shield */
$("#btnShieldEnc")?.addEventListener("click", async () => {
  const pw = $("#shieldPass")?.value;
  if (!pw) return toast("أدخل كلمة المرور", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    const r = await fetch("/api/shield/encrypt", { method: "POST", body: fd });
    const d = await r.json();
    showResult("shieldResult", d);
    if (d.download) window.open(d.download);
    toast(d.ok ? "✓ مشفر" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnShieldDec")?.addEventListener("click", async () => {
  const pw = $("#shieldPass")?.value;
  if (!pw) return toast("أدخل كلمة المرور", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    const r = await fetch("/api/shield/decrypt", { method: "POST", body: fd });
    const d = await r.json();
    showResult("shieldResult", d);
    if (d.download) window.open(d.download);
    toast(d.ok ? "✓ تم الفك" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnShieldHoney")?.addEventListener("click", async () => {
  const pw = $("#shieldPass")?.value;
  if (!pw) return toast("أدخل كلمة مرور طبقة العسل", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    fd.append("use_honey", "1");
    const r = await fetch("/api/shield/decrypt", { method: "POST", body: fd });
    const d = await r.json();
    showResult("shieldResult", d);
    if (d.download) window.open(d.download);
    toast(d.ok ? "✓ طبقة العسل" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Neural Cleaner */
$("#btnClean")?.addEventListener("click", async () => {
  const path = $("#cleanerPath")?.value?.trim();
  if (!path) return toast("أدخل مسار الملف على السيرفر", "err");
  try {
    const d = await postJSON("/api/clean", { path, dry_run: false });
    showResult("cleanerResult", d);
    toast(
      d.ok
        ? `✓ ${(d.stripped_metadata || []).join(", ") || "لا شيء"} · ${d.bytes_changed || 0} bytes`
        : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnCleanDry")?.addEventListener("click", async () => {
  const path = $("#cleanerPath")?.value?.trim();
  if (!path) return toast("أدخل مسار الملف", "err");
  try {
    const d = await postJSON("/api/clean", { path, dry_run: true });
    showResult("cleanerResult", d);
    toast(d.ok ? "✓ فحص جاف" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Blind Vault */
$("#btnVaultLock")?.addEventListener("click", async () => {
  const path = $("#vaultPath")?.value?.trim();
  const pw = $("#vaultPass")?.value;
  if (!path || !pw) return toast("أدخل المسار وكلمة المرور", "err");
  try {
    const d = await postJSON("/api/vault/lock", { path, password: pw });
    showResult("vaultResult", d);
    toast(
      d.ok ? `✓ ${d.blocks_encrypted || "?"} blocks` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnVaultUnlock")?.addEventListener("click", async () => {
  const path = $("#vaultPath")?.value?.trim();
  const pw = $("#vaultPass")?.value;
  if (!path || !pw) return toast("أدخل المسار وكلمة المرور", "err");
  try {
    const d = await postJSON("/api/vault/unlock", {
      path,
      map_path: path + ".vault",
      password: pw,
    });
    showResult("vaultResult", d);
    toast(d.ok ? "✓ مفتوح" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Ghost Inlayer */
$("#btnStegoHide")?.addEventListener("click", async () => {
  try {
    const coverF = await pickFile();
    if (!coverF[0]) return;
    const payloadF = await pickFile();
    if (!payloadF[0]) return;
    const pw = $("#stegoPass")?.value || "";
    const fd = new FormData();
    fd.append("cover", coverF[0]);
    fd.append("payload", payloadF[0]);
    fd.append("password", pw);
    const r = await fetch("/api/stego/hide", { method: "POST", body: fd });
    const d = await r.json();
    showResult("stegoResult", d);
    if (d.download) window.open(d.download);
    toast(d.ok ? "✓ مخفي" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnStegoExtract")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const pw = $("#stegoPass")?.value || "";
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    const r = await fetch("/api/stego/extract", { method: "POST", body: fd });
    const d = await r.json();
    showResult("stegoResult", d);
    if (d.download) window.open(d.download);
    toast(d.ok ? "✓ مستخرج" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Kamikaze Token */
$("#btnKamiSeal")?.addEventListener("click", async () => {
  const pw = $("#kamiTokPass")?.value;
  const ttl = $("#kamiTokTTL")?.value || 24;
  if (!pw) return toast("أدخل كلمة المرور", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    fd.append("ttl_hours", ttl);
    const r = await fetch("/api/kamikaze-token/seal", {
      method: "POST",
      body: fd,
    });
    const d = await r.json();
    showResult("kamiTokResult", d);
    if (d.download) window.open(d.download);
    toast(
      d.ok ? `✓ ختم · ينتهي ${d.expires_ts || "?"}` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnKamiUnseal")?.addEventListener("click", async () => {
  const pw = $("#kamiTokPass")?.value;
  if (!pw) return toast("أدخل كلمة المرور", "err");
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    fd.append("password", pw);
    const r = await fetch("/api/kamikaze-token/unseal", {
      method: "POST",
      body: fd,
    });
    const d = await r.json();
    showResult("kamiTokResult", d);
    if (d.download) window.open(d.download);
    toast(
      d.ok
        ? `✓ مفتوح · متبقي ${d.hours_remaining?.toFixed?.(1) || "?"} ساعة`
        : d.expired
          ? "✗ منتهي الصلاحية"
          : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnKamiRefresh")?.addEventListener("click", async () => {
  const path = prompt("مسار ملف الرمز على السيرفر:");
  const pw = $("#kamiTokPass")?.value;
  const ttl = $("#kamiTokTTL")?.value || 24;
  if (!path || !pw) return toast("أدخل المسار وكلمة المرور", "err");
  try {
    const d = await postJSON("/api/kamikaze-token/refresh", {
      path,
      password: pw,
      ttl_hours: parseInt(ttl),
    });
    showResult("kamiTokResult", d);
    toast(d.ok ? "✓ تم التجديد" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Spectral */
$("#btnSpectral")?.addEventListener("click", async () => {
  const path = $("#spectralPath")?.value?.trim();
  if (!path) return toast("أدخل مسار الملف", "err");
  try {
    const d = await postJSON("/api/spectral", { path });
    showResult("spectralResult", d);
    toast(d.ok ? "✓ مسح طيفي" : d.error, d.ok ? "ok" : "err");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Bio-Entropy */
$("#btnEntropy")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    const fd = new FormData();
    fd.append("file", files[0]);
    const r = await fetch("/api/entropy", { method: "POST", body: fd });
    const d = await r.json();
    showResult("entropyResult", d);
    toast(
      d.ok
        ? `✓ ${d.classification || "?"} · H=${d.global_entropy ?? "?"}`
        : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* Fork */
$("#btnFork")?.addEventListener("click", async () => {
  const path = $("#forkPath")?.value?.trim();
  const seed = $("#forkSeed")?.value?.trim();
  if (!path) return toast("أدخل مسار الملف على السيرفر", "err");
  try {
    const d = await postJSON("/api/fork", {
      path,
      count: 10,
      seed: seed || undefined,
    });
    showResult("forkResult", d);
    toast(
      d.ok
        ? `✓ ${d.decoy_count || 10} نسخ · الحقيقي #${d.real_slot}`
        : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ═══════════════════════════════════════════════════════════
   CORE ENGINES — FIXED FIELD MAPPING
   ═══════════════════════════════════════════════════════════ */

/** Recursive tree renderer matching matryoshka response shape */
function renderTree(node, depth = 0) {
  if (!node) return "—";
  const name = node.name || node.layer || "node";
  const magic = node.magic?.label || node.magic?.type || "";
  const ent = node.entropy != null ? Number(node.entropy).toFixed(3) : "?";
  const coreCls = node.core ? " core" : "";
  const size = node.size != null ? ` · ${node.size}B` : "";
  let html = `<details open><summary><span class="${coreCls}">${esc(name)}</span> <span class="meta">${esc(magic)} · H=${ent}${size}</span></summary>`;
  if (node.notes?.length) {
    html += `<div class="meta" style="padding-right:12px">${node.notes.map(esc).join(" · ")}</div>`;
  }
  if (node.pe) {
    html += `<div class="meta" style="padding-right:12px">PE sections=${(node.pe.sections || []).length} imports=${node.pe.import_count || 0}</div>`;
  }
  for (const ch of node.children || []) {
    html += renderTree(ch, depth + 1);
  }
  html += `</details>`;
  return html;
}

/** Memory hits — maps kind/hex/score from hunt_keys */
function renderMemHits(d) {
  const hits = d.hits || [];
  const rows = hits.map((h) => [
    `<span class="badge ${h.score >= 70 ? "danger" : h.score >= 50 ? "info" : "ok"}">${esc(h.kind || "key")}</span>`,
    `<code>${esc((h.hex || "").slice(0, 48))}${(h.hex || "").length > 48 ? "…" : ""}</code>`,
    esc(h.ascii || (h.reasons || []).slice(0, 2).join(", ") || "—"),
    h.score != null ? `${h.score}` : "—",
    hexOff(h.offset),
  ]);
  const el = $("#memHits");
  if (el)
    el.innerHTML = tbl(["type", "hex", "context", "score", "offset"], rows);
}

/* ── Shell Ripper ── */
$("#btnShell")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("فك التغليف…");
    const d = await postFile("/api/shell-ripper");
    const treeEl = $("#shellTree");
    if (treeEl) treeEl.innerHTML = renderTree(d.tree);
    const coresEl = $("#shellCores");
    if (coresEl) coresEl.textContent = formatJSON(d.cores || []);
    const chainsEl = $("#shellChains");
    if (chainsEl)
      chainsEl.textContent = (d.method_chains || [])
        .map((c) => (Array.isArray(c) ? c.join(" → ") : String(c)))
        .join("\n") || "—";
    const stats = d.stats || {};
    const statsEl = $("#shellStats");
    if (statsEl)
      statsEl.textContent = `${stats.layers ?? "?"} layers · depth=${stats.max_depth ?? "?"} · cores=${stats.core_count ?? "?"}`;
    toast(`✓ ${stats.layers ?? "?"} طبقات`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Memory ── */
$("#btnMem")?.addEventListener("click", async () => {
  const pid = $("#memPid")?.value?.trim();
  try {
    if (pid) {
      const d = await postJSON("/api/memory", { pid: parseInt(pid, 10) });
      renderMemHits(d);
      toast(`✓ ${d.hit_count ?? d.hits?.length ?? 0} keys`, "ok");
    } else {
      const files = await pickFile();
      if (!files[0]) return;
      currentFile = files[0];
      const d = await postFile("/api/memory");
      renderMemHits(d);
      toast(`✓ ${d.hit_count ?? d.hits?.length ?? 0} keys`, "ok");
    }
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Network ── */
$("#btnNet")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تحليل PCAP…");
    const d = await postFile("/api/network");

    const protoEl = $("#netProto");
    if (protoEl) protoEl.textContent = formatJSON(d.protocols || {});

    const fpEl = $("#netFp");
    if (fpEl)
      fpEl.textContent = formatJSON(
        d.fingerprint || { summary: d.summary || "—" }
      );

    const ends = (d.endpoints || []).map((e) => [
      esc(e.ip || ""),
      e.port ?? "",
      esc(e.class || e.role || ""),
      e.packets ?? "",
    ]);
    const endsEl = $("#netEnds");
    if (endsEl) endsEl.innerHTML = tbl(["ip", "port", "class", "pkts"], ends);

    const dnsList = d.dns_names || d.http_tls_hosts || [];
    const dnsEl = $("#netDns");
    if (dnsEl)
      dnsEl.textContent =
        Array.isArray(dnsList) && dnsList.length
          ? dnsList.join("\n")
          : formatJSON(d.dns || "—");

    const flowsEl = $("#netFlows");
    if (flowsEl)
      flowsEl.textContent = formatJSON(
        (d.top_flows || []).slice(0, 15)
      );

    toast(
      `✓ ${d.packet_count ?? "?"} packets · ${Object.keys(d.protocols || {}).length} protos`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Reverse Timestamp ── */
$("#btnRevTs")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("استخراج البصمة…");
    const d = await postFile("/api/reverse-timestamp");
    const b = d.best_toolchain || d.best;
    const bestEl = $("#revBest");
    if (bestEl)
      bestEl.innerHTML = b
        ? `${esc(b.era || b.name || b.id)} <span class="badge psychic">${b.match_pct ?? "?"}%</span><small>${esc((b.markers_hit || b.reasons || []).slice(0, 4).join(", "))}</small>`
        : "—";

    const ranked = d.rankings || d.ranking || d.matches || [];
    const rankRows = ranked.map((r, i) => [
      String(i + 1),
      esc(r.era || r.name || r.id || r.toolchain || ""),
      `${r.match_pct ?? "?"}%`,
      (r.cves || [])
        .map((c) => (typeof c === "string" ? c : c.cve))
        .slice(0, 3)
        .join(", "),
    ]);
    const rankEl = $("#revRank");
    if (rankEl)
      rankEl.innerHTML = tbl(["#", "toolchain", "match", "CVEs"], rankRows);

    const planEl = $("#revPlan");
    if (planEl) planEl.textContent = formatJSON(d.exploit_plan || []);

    const discEl = $("#revDisc");
    if (discEl) discEl.textContent = d.disclaimer || "";

    toast(`✓ ${b?.era || b?.id || "?"}`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Sovereignty ── */
$("#btnSov")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("سحق الحمايات…");
    const d = await postFile("/api/sovereignty");
    const scoreEl = $("#sovScore");
    if (scoreEl)
      scoreEl.textContent = `Risk ${d.risk_score ?? "?"}/100 · ${d.count ?? d.findings?.length ?? 0} hits`;

    const findings = d.findings || [];
    const rows = findings.map((f) => [
      `<span class="sev-${esc(f.severity || "low")}">${esc(f.severity || "")}</span>`,
      esc(f.id || ""),
      esc(f.kind || ""),
      esc(f.desc || f.where || ""),
    ]);
    const findEl = $("#sovFindings");
    if (findEl)
      findEl.innerHTML = tbl(["sev", "id", "kind", "desc"], rows);

    const planEl = $("#sovPlan");
    if (planEl)
      planEl.textContent = (d.bypass_plan || [])
        .map((x, i) => `${i + 1}. ${x}`)
        .join("\n");

    toast(`✓ ${d.count ?? findings.length} hits`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

$("#btnPatch")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("ترقيع…");
    const d = await postFile("/api/anti/patch");
    const patchEl = $("#sovPatch");
    if (patchEl) patchEl.textContent = formatJSON(d);
    if (d.download) window.open(d.download);
    toast(
      d.ok ? `✓ ${d.patches_applied || 0} patches` : d.error,
      d.ok ? "ok" : "err"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Tetra Cube ── */
$("#btnTetra")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("بناء المكعب الرباعي…");
    const d = await postFile("/api/tetra-cube");
    lastGraph = d;
    const statsEl = $("#tetraStats");
    if (statsEl)
      statsEl.textContent = `${d.stats?.nodes ?? d.nodes?.length ?? 0} nodes · ${d.stats?.dangerous_apis ?? "?"} dangerous`;

    const hot = (d.nodes || [])
      .filter((n) => n.risk >= 2 || n.group === "dangerous" || n.group === "ioc")
      .sort((a, b) => (b.risk || 0) - (a.risk || 0))
      .slice(0, 12)
      .map((n) => [
        esc(n.id?.slice?.(0, 8) || ""),
        esc(n.label || ""),
        n.risk ?? "",
        esc(n.group || ""),
      ]);
    const hotEl = $("#tetraHot");
    if (hotEl) hotEl.innerHTML = tbl(["id", "label", "risk", "group"], hot);

    setTab("tetra-cube");
    toast(`✓ ${d.stats?.nodes ?? d.nodes?.length ?? 0} nodes`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Ghost Spectrum ── */
$("#btnGhost")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("مسح PEB/ELF…");
    const d = await postFile("/api/ghost-spectrum");

    const markers = d.peb_markers || d.markers || [];
    const rows = markers.map((m) => [
      hexOff(m.offset),
      esc(m.label || ""),
      m.patchable ? "✓" : "—",
    ]);
    const markEl = $("#ghostMarkers");
    if (markEl)
      markEl.innerHTML = tbl(["offset", "label", "patchable"], rows);

    const plan = d.header_patch_plan || d.plan || [];
    const planEl = $("#ghostPlan");
    if (planEl)
      planEl.textContent = plan
        .map((p) =>
          typeof p === "string"
            ? p
            : `• ${p.target || ""} → ${p.action || ""}`
        )
        .join("\n");

    const scoreEl = $("#ghostScore");
    if (scoreEl)
      scoreEl.textContent = `Invisibility ${d.invisibility_score ?? "?"}%`;

    toast(`✓ ${d.marker_count ?? markers.length} markers`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Ant Colony ── */
$("#btnAnts")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("إطلاق المستعمرة…");
    const d = await postFile("/api/ant-colony");

    const weak = d.top_weak || d.weakest_jumps || [];
    const rows = weak.map((j) => [
      hexOff(j.offset),
      esc(j.op || j.type || ""),
      j.weakness != null ? `${j.weakness}` : j.confidence != null ? `${j.confidence}%` : "—",
      j.crashes_sim ?? "—",
    ]);
    const weakEl = $("#antWeak");
    if (weakEl)
      weakEl.innerHTML = tbl(["offset", "op", "weakness", "crashes"], rows);

    const coverEl = $("#antCover");
    if (coverEl)
      coverEl.textContent = formatJSON(
        d.coverage_hint || d.coverage || {
          branches_mined: d.branches_mined,
          branches_fuzzed: d.branches_fuzzed,
          weakest: d.weakest_jump,
        }
      );

    const statsEl = $("#antStats");
    if (statsEl)
      statsEl.textContent = `${d.virtual_ants ?? d.threads ?? "?"} ants · ${d.elapsed_ms ?? "?"}ms · ${d.branches_fuzzed ?? weak.length} branches`;

    toast(
      `✓ weakest @${hexOff(d.weakest_jump?.offset)} · ${d.elapsed_ms ?? "?"}ms`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Brain Link ── */
$("#btnBrain")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("ترجمة إلى pseudo-C…");
    const d = await postFile("/api/brain-link");
    const codeEl = $("#brainCode");
    if (codeEl) codeEl.textContent = d.pseudo_c || "—";
    const confEl = $("#brainConf");
    if (confEl)
      confEl.textContent = `ثقة ${d.confidence_pct ?? "?"}% · APIs=${d.api_recoveries ?? "?"} · obfuscated=${d.obfuscation_suspected ? "نعم" : "لا"}`;
    toast(`✓ ثقة ${d.confidence_pct ?? "?"}%`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Kamikaze Engine ── */
$("#btnKami")?.addEventListener("click", async () => {
  try {
    toast("💀 تسليح…");
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    $("#quantumBlur")?.classList.add("on");
    const d = await postFile("/api/kamikaze");
    const armed = d.armed;
    const statusEl = $("#kamiStatus");
    if (statusEl)
      statusEl.innerHTML = armed
        ? `<span class="kamikaze-armed">💀 مسلّح — Risk ${d.risk_score ?? "?"}</span><small>${d.reassembly?.micro_processes ?? d.shard_count ?? 0} عملية صغرى عبر ${(d.reassembly?.cpu_cores_mapped || []).length} نواة</small>`
        : `<span style="color:var(--good)">● وضع استعداد</span><small>Risk ${d.risk_score ?? "?"} — لم يُكتشف تهديد قوي</small>`;

    const playEl = $("#kamiPlaybook");
    if (playEl)
      playEl.textContent = (d.playbook || []).join("\n");

    const shards = d.shards_preview || [];
    const rows = shards.map((s) => [
      s.shard ?? "",
      `core ${s.core_affinity ?? "?"}`,
      esc(s.md5_10 || ""),
      s.size ?? "",
    ]);
    const shardsEl = $("#kamiShards");
    if (shardsEl)
      shardsEl.innerHTML = tbl(["shard", "core", "md5", "size"], rows);

    setTimeout(() => $("#quantumBlur")?.classList.remove("on"), 1500);
    toast(
      `✓ ${armed ? "مسلّح" : "استعداد"} · ${d.shard_count ?? "?"} شظية`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
    $("#quantumBlur")?.classList.remove("on");
  }
});

/* ── Shattered Mind ── */
$("#btnShatter")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تشتيت…");
    const d = await postFile("/api/shattered-mind");
    const cfgEl = $("#shatterCFG");
    if (cfgEl)
      cfgEl.textContent = formatJSON({
        cfg_nodes_est: d.cfg_nodes_est,
        edges: d.edges_discovered,
        calls: d.calls_found,
        rets: d.rets_found,
        coverage_pct: d.coverage_pct,
        fragments: `${d.fragments_analyzed}/${d.fragments_total}`,
      });

    const frags = d.sample_fragments || [];
    const rows = frags.map((f) => [
      f.idx ?? "",
      hexOff(f.offset),
      f.size ?? "",
      f.jcc ?? "",
      f.calls ?? "",
      f.entropy_est ?? "",
    ]);
    const fragsEl = $("#shatterFrags");
    if (fragsEl)
      fragsEl.innerHTML = tbl(
        ["idx", "offset", "size", "jcc", "calls", "H"],
        rows
      );

    const statsEl = $("#shatterStats");
    if (statsEl)
      statsEl.textContent = `${d.coverage_pct ?? "?"}% · ${d.elapsed_ms ?? "?"}ms · ${d.num_threads ?? "?"} threads`;

    toast(
      `✓ ${d.cfg_nodes_est ?? "?"} CFG nodes · ${d.elapsed_ms ?? "?"}ms`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Blackhole ── */
$("#btnBH")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تحليل ETW…");
    const d = await postFile("/api/blackhole");

    const sinks = d.forensic_sinks || [];
    const rows = sinks.map((s) => [
      esc(s.path || ""),
      `${s.size_mb ?? "?"} MB`,
    ]);
    const sessEl = $("#bhSessions");
    if (sessEl)
      sessEl.innerHTML =
        `<p class="muted">${d.etw_sessions_visible ?? 0} ETW sessions · blindness=${d.blindness_effectiveness ?? "?"}%</p>` +
        tbl(["sink", "size"], rows);

    const playEl = $("#bhPlaybook");
    if (playEl)
      playEl.textContent = (d.playbook || []).join("\n");

    toast(`✓ Blindness ${d.blindness_effectiveness ?? "?"}%`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Speculative ── */
$("#btnSpec")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تحليل Spectre…");
    $("#quantumBlur")?.classList.add("on");
    const d = await postFile("/api/speculative");

    const gadgets = d.top_gadgets || [];
    const rows = gadgets.map((g) => [
      hexOff(g.offset),
      esc(g.desc || ""),
      g.secret_proximity ? "⚠" : "",
      g.trainable ? "✓" : "",
    ]);
    const gadEl = $("#specGadgets");
    if (gadEl)
      gadEl.innerHTML = tbl(["offset", "gadget", "secret", "train"], rows);

    const planEl = $("#specPlan");
    if (planEl)
      planEl.textContent = (d.training_plan || []).join("\n");

    setTimeout(() => $("#quantumBlur")?.classList.remove("on"), 1500);
    toast(
      `✓ ${d.gadgets_total ?? "?"} gadgets · injectability=${d.injectability_score ?? "?"}`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
    $("#quantumBlur")?.classList.remove("on");
  }
});

/* ── Compiler Flip ── */
$("#btnFlip")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تحليل JIT…");
    const d = await postFile("/api/compiler-flip");

    const sinks = d.sinks || [];
    const rows = sinks.map((s) => [
      esc(s.sink || ""),
      s.offset ?? "",
      esc((s.context || "").slice(0, 60)),
    ]);
    const sinksEl = $("#flipSinks");
    if (sinksEl)
      sinksEl.innerHTML = tbl(["sink", "offset", "context"], rows);

    const stratEl = $("#flipStrat");
    if (stratEl)
      stratEl.textContent = (d.strategy || []).join("\n");

    toast(
      `✓ ${d.sink_count ?? sinks.length} sinks · ${d.runtime_format || "?"}`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Weighted Future ── */
$("#btnFuture")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("توقع المستقبل…");
    const d = await postFile("/api/weighted-future");

    const regs = d.future_registers || [];
    const rows = regs.map((r) => [
      esc(r.register || ""),
      esc(r.current_est || ""),
      `<span class="badge psychic">${esc(r.predicted_5c || "")}</span>`,
      `${r.confidence ?? "?"}%`,
    ]);
    const regsEl = $("#futRegs");
    if (regsEl)
      regsEl.innerHTML = tbl(
        ["register", "now", "predicted +5c", "conf"],
        rows
      );

    const scoreEl = $("#futScore");
    if (scoreEl)
      scoreEl.textContent = `ثقة ${d.confidence_pct ?? "?"}% · MAE=${d.mae ?? "?"} · ${d.predictor || ""}`;

    const predsEl = $("#futPreds");
    if (predsEl)
      predsEl.textContent = formatJSON((d.predictions || []).slice(0, 12));

    toast(`✓ ثقة ${d.confidence_pct ?? "?"}%`, "ok");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Register Puzzle ── */
$("#btnRegPuz")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("حل أحجية XMM…");
    const d = await postFile("/api/register-puzzle");

    const simd = d.simd_instructions || d.simd_regions || [];
    const rows = simd.map((r) => [
      hexOff(r.offset),
      esc(r.desc || ""),
    ]);
    const simdEl = $("#regSimd");
    if (simdEl)
      simdEl.innerHTML = tbl(["offset", "instruction"], rows);

    const k = d.key_reconstruction || {};
    const keyEl = $("#regKey");
    if (keyEl)
      keyEl.textContent = `🔑 ${k.key_hex || "—"}  (len=${k.key_len_est ?? "?"} · accuracy=${k.accuracy_pct ?? "?"}%)`;

    const accEl = $("#regAcc");
    if (accEl) accEl.textContent = `Accuracy ${k.accuracy_pct ?? "?"}%`;

    toast(
      `✓ ${d.simd_regions_found ?? simd.length} SIMD regions`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ── Silent Plague ── */
$("#btnPlague")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("💀 تحليل الثبات…");
    $("#quantumBlur")?.classList.add("on");
    const d = await postFile("/api/silent-plague");

    const arts = d.uefi_artifacts || [];
    const rows = arts.map((a) => [
      hexOff(a.offset),
      esc(a.label || a.sig || ""),
    ]);
    const artsEl = $("#plagueArtifacts");
    if (artsEl)
      artsEl.innerHTML = tbl(["offset", "artifact"], rows);

    const planEl = $("#plaguePlan");
    if (planEl)
      planEl.textContent = (d.persistence_playbook || []).join("\n");

    setTimeout(() => $("#quantumBlur")?.classList.remove("on"), 1500);
    toast(
      `✓ Persistence ${d.persistence_score ?? "?"}% · ${d.artifact_count ?? arts.length} artifacts`,
      "ok"
    );
  } catch (e) {
    toast(e.message, "err");
    $("#quantumBlur")?.classList.remove("on");
  }
});

/* ── Full Run ── */
$("#btnFull")?.addEventListener("click", async () => {
  try {
    const files = await pickFile();
    if (!files[0]) return;
    currentFile = files[0];
    toast("تشغيل المحركات الأساسية…");
    const d = await postFile("/api/full");

    if (d.shell_ripper?.tree) {
      const treeEl = $("#shellTree");
      if (treeEl) treeEl.innerHTML = renderTree(d.shell_ripper.tree);
      const coresEl = $("#shellCores");
      if (coresEl)
        coresEl.textContent = formatJSON(d.shell_ripper.cores || []);
      const chainsEl = $("#shellChains");
      if (chainsEl)
        chainsEl.textContent = (d.shell_ripper.method_chains || [])
          .map((c) => (Array.isArray(c) ? c.join(" → ") : String(c)))
          .join("\n");
    }

    if (d.sovereignty) {
      const s = d.sovereignty;
      const scoreEl = $("#sovScore");
      if (scoreEl)
        scoreEl.textContent = `Risk ${s.risk_score ?? "?"}/100 · ${s.count ?? 0} hits`;
      const findEl = $("#sovFindings");
      if (findEl)
        findEl.innerHTML = tbl(
          ["sev", "id", "kind", "desc"],
          (s.findings || []).map((f) => [
            `<span class="sev-${esc(f.severity || "low")}">${esc(f.severity || "")}</span>`,
            esc(f.id || ""),
            esc(f.kind || ""),
            esc(f.desc || ""),
          ])
        );
      const planEl = $("#sovPlan");
      if (planEl)
        planEl.textContent = (s.bypass_plan || [])
          .map((x, i) => `${i + 1}. ${x}`)
          .join("\n");
    }

    if (d.reverse_timestamp) {
      const b = d.reverse_timestamp.best_toolchain;
      const bestEl = $("#revBest");
      if (bestEl)
        bestEl.innerHTML = b
          ? `${esc(b.era || b.id)} <span class="badge psychic">${b.match_pct ?? "?"}%</span>`
          : "—";
      const planEl = $("#revPlan");
      if (planEl)
        planEl.textContent = formatJSON(
          d.reverse_timestamp.exploit_plan || []
        );
    }

    if (d.memory?.hits) renderMemHits(d.memory);

    if (d.tetra_cube) {
      lastGraph = d.tetra_cube;
      const statsEl = $("#tetraStats");
      if (statsEl)
        statsEl.textContent = `${d.tetra_cube.stats?.nodes ?? 0} nodes`;
    }

    toast("✓ اكتمل التحليل الشامل", "ok");
    setTab("shell-ripper");
  } catch (e) {
    toast(e.message, "err");
  }
});

/* ═══════════════════════════════════════════════════════════
   HEALTH + METRICS
   ═══════════════════════════════════════════════════════════ */

let healthBase = null;

function fmtUptime(sec) {
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h > 0 ? `${h}h ${m}m ${r}s` : m > 0 ? `${m}m ${r}s` : `${r}s`;
}

function renderSideStats() {
  const el = $("#sideStats");
  if (!el || !healthBase) return;
  const up = fmtUptime(healthBase.uptime + (Date.now() - healthBase.at) / 1000);
  const req = healthBase.requests_total != null ? ` · 📡 ${healthBase.requests_total} req` : "";
  el.textContent = `⏱️ ${up}${req}`;
  el.hidden = false;
  const pill = $("#healthPill");
  if (pill) pill.title = el.textContent;
}

fetch("/api/health")
  .then((r) => r.json())
  .then((d) => {
    const p = $("#healthPill");
    if (!p) return;
    p.textContent = d.ok
      ? `◉ Online · ${d.features ?? "?"} engines`
      : "◉ Offline";
    if (!d.ok) {
      p.classList.add("bad");
      return;
    }
    if (typeof d.uptime_sec === "number") {
      healthBase = {
        uptime: d.uptime_sec,
        at: Date.now(),
        requests_total: d.requests_total ?? null
      };
      renderSideStats();
      setInterval(renderSideStats, 5000);
    }
  })
  .catch(() => {
    const p = $("#healthPill");
    if (p) {
      p.textContent = "◉ Offline";
      p.classList.add("bad");
    }
  });

setInterval(async () => {
  try {
    const r = await fetch("/api/metrics");
    const d = await r.json();
    // reserved for flame strip
  } catch (_) {}
}, 4000);

/* ═══════════════════════════════════════════════════════════
   ELITE LIVE PANEL — لوحة ELITE الحية
   ═══════════════════════════════════════════════════════════ */
titles["elite-panel"] = [
  "📡 لوحة ELITE الحية",
  "9 محركات مباشرة · بث الشبكة · 29 محركاً في نظرة واحدة — تجميع الطلبات في /api/dash/status",
];

async function getJSON(url) {
  const r = await fetch(url);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || j.message || `HTTP ${r.status}`);
  return j;
}

async function postForm(url, fd) {
  const r = await fetch(url, { method: "POST", body: fd });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || j.message || `HTTP ${r.status}`);
  return j;
}

const ENGINES_29 = [
  { id: "shell_ripper", n: "🧅 تمزيق الأصداف", tab: "shell-ripper" },
  { id: "sovereignty", n: "⚔️ محطم السيادة", tab: "sovereignty" },
  { id: "reverse_timestamp", n: "⏳ البصمة الزمنية المعكوسة", tab: "reverse-timestamp" },
  { id: "tetra_cube", n: "🧊 المكعب الرباعي", tab: "tetra-cube" },
  { id: "memory_keys", n: "🎣 مصيدة المفاتيح", tab: "memory" },
  { id: "ghost_spectrum", n: "👻 الطيف الخفي", tab: "ghost-spectrum" },
  { id: "ant_colony", n: "🐜 مستعمرة النمل", tab: "ant-colony" },
  { id: "brain_link", n: "🧠 الوصلة الدماغية", tab: "brain-link" },
  { id: "kamikaze", n: "💀 المحرك الانتحاري", tab: "kamikaze" },
  { id: "shattered_mind", n: "🧠 العقل المتشظي", tab: "shattered-mind" },
  { id: "blackhole", n: "🕳️ ثقب الهندسة الأسود", tab: "blackhole" },
  { id: "speculative_injector", n: "⚡ الحاقن التخميني", tab: "speculative" },
  { id: "compiler_flip", n: "🌀 مقلب المترجم", tab: "compiler-flip" },
  { id: "weighted_future", n: "🔮 المستقبل الموزون", tab: "weighted-future" },
  { id: "register_puzzle", n: "🧩 أحجية السجل", tab: "register-puzzle" },
  { id: "silent_plague", n: "💀 الطاعون الصامت", tab: "silent-plague" },
  { id: "network_analyzer", n: "🌐 محلل الشبكة", tab: "network" },
  { id: "author", n: "✍️ المحرك المؤلف", tab: "elite" },
  { id: "spectral", n: "🔬 الماسح الطيفي", tab: "elite" },
  { id: "combi_scan", n: "🧪 مسح كومبي", tab: "elite-panel" },
  { id: "digital_fingerprint", n: "🧬 البصمة الرقمية", tab: "elite-panel" },
  { id: "port_scanner", n: "🔌 ماسح المنافذ", tab: "elite-panel" },
  { id: "process_monitor", n: "🖥️ مراقب العمليات", tab: "elite-panel" },
  { id: "file_encryptor", n: "🔐 مشفر الملفات", tab: "elite-panel" },
  { id: "stealth_tasks", n: "🗂️ مدير المهام الخفي", tab: "elite-panel" },
  { id: "event_log", n: "📜 سجل الأحداث", tab: "elite-panel" },
  { id: "speculative_brute", n: "⚡ الاختراق التخميني", tab: "elite-panel" },
  { id: "accelerator", n: "🚀 مسرع الأداء", tab: "elite-panel" },
  { id: "secret_browser", n: "📂 المستعرض السري", tab: "elite-panel" },
];

let eliteLiveOn = false;
let eliteTimers = [];

function renderEngines29() {
  const g = $("#enginesGrid");
  if (!g || g.dataset.rendered) return;
  g.dataset.rendered = "1";
  g.innerHTML = ENGINES_29.map(
    (e, i) =>
      `<div class="elite-card" style="cursor:pointer" data-nav="${e.tab}" data-idx="${i}">
        <h3>${e.n}</h3>
        <p class="elite-desc"><span class="mono" style="color:var(--accent)">#${String(i + 1).padStart(2, "0")}</span> · ${e.id}</p>
        <div class="elite-actions"><button class="mini-btn">فتح</button></div>
      </div>`
  ).join("");
  g.querySelectorAll(".elite-card").forEach((c) =>
    c.addEventListener("click", () => {
      const t = c.dataset.nav;
      if (t === "elite-panel") {
        const first = $("#dashGrid");
        if (first) first.scrollIntoView({ behavior: "smooth", block: "start" });
      } else {
        setTab(t);
      }
    })
  );
}

async function refreshEliteStatus() {
  try {
    const d = await getJSON("/api/dash/status");
    const fp = $("#eliteFp");
    const mt = $("#eliteMetrics");
    const up = $("#eliteUptime");
    if (fp) fp.textContent = formatJSON(d.fingerprint_short || {});
    if (mt) mt.textContent = formatJSON(d.metrics || {});
    if (up && d.metrics) up.textContent = "⏱️ تشغيل " + (d.metrics.uptime ?? "—");
  } catch (_) {}
}

async function refreshNetLive() {
  try {
    const d = await getJSON("/api/net-live");
    const st = $("#netLiveStamp");
    if (st) st.textContent = "· " + new Date().toLocaleTimeString("ar-EG");
    const box = $("#netLiveTable");
    if (!box) return;
    const conns = (d.connections || []).slice(0, 18);
    const rows = conns.map((c) => [c.pid ?? "—", c.status ?? "—", c.local ?? "—", c.remote ?? "—"]);
    const ifaces = (d.interfaces || [])
      .filter((i) => i.up)
      .map((i) => i.name)
      .join("، ");
    box.innerHTML =
      tbl(["PID", "الحالة", "محلي", "بعيد"], rows) +
      `<p class="muted" style="margin-top:8px">واجهات نشطة: ${esc(ifaces || "—")}</p>`;
  } catch (_) {}
}

function eliteLiveStart() {
  if (eliteLiveOn) return;
  eliteLiveOn = true;
  const pill = $("#eliteLivePill");
  const btn = $("#btnEliteLive");
  if (pill) pill.textContent = "يعمل — كل 5 ثوانٍ";
  if (btn) btn.textContent = "⏹️ إيقاف البث";
  renderEngines29();
  refreshEliteStatus();
  refreshNetLive();
  eliteTimers.push(setInterval(refreshEliteStatus, 5000));
  eliteTimers.push(setInterval(refreshNetLive, 4000));
}

function eliteLiveStop() {
  eliteLiveOn = false;
  eliteTimers.forEach(clearInterval);
  eliteTimers = [];
  const pill = $("#eliteLivePill");
  const btn = $("#btnEliteLive");
  if (pill) pill.textContent = "متوقف";
  if (btn) btn.textContent = "🔴 بث مباشر";
}

let dashBound = false;

function bindDashCards() {
  if (dashBound) return;
  dashBound = true;

  $("#btnEliteLive")?.addEventListener("click", () =>
    eliteLiveOn ? eliteLiveStop() : eliteLiveStart()
  );

  $("#btnFp")?.addEventListener("click", async () => {
    try {
      showResult("dashFp", await getJSON("/api/dash/fingerprint"));
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnPorts")?.addEventListener("click", async () => {
    try {
      const ports = $("#portsFld").value.trim();
      const url = "/api/dash/ports" + (ports ? `?ports=${encodeURIComponent(ports)}` : "");
      showResult("dashPorts", await getJSON(url));
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnProcs")?.addEventListener("click", async () => {
    try {
      showResult("dashProcs", await getJSON("/api/dash/processes?limit=25"));
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnKill")?.addEventListener("click", async () => {
    try {
      const pid = parseInt($("#killPid").value, 10);
      if (!pid) throw new Error("أدخل PID");
      showResult("dashProcs", await postJSON("/api/dash/kill", { pid }));
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnDashEnc")?.addEventListener("click", async () => {
    try {
      const f = $("#dashEncFile").files[0];
      if (!f) throw new Error("اختر ملفاً");
      const pass = $("#dashEncPass").value;
      if (!pass) throw new Error("كلمة المرور مطلوبة");
      const fd = new FormData();
      fd.append("file", f);
      fd.append("password", pass);
      const d = await postForm("/api/dash/encrypt", fd);
      showResult("dashEncRes", d);
      if (d.download) window.open(d.download, "_blank");
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnDashDec")?.addEventListener("click", async () => {
    try {
      const f = $("#dashDecFile").files[0];
      if (!f) throw new Error("اختر ملفاً");
      const pass = $("#dashDecPass").value;
      if (!pass) throw new Error("كلمة المرور مطلوبة");
      const fd = new FormData();
      fd.append("file", f);
      fd.append("password", pass);
      const d = await postForm("/api/dash/decrypt", fd);
      showResult("dashDecRes", d);
      if (d.download) window.open(d.download, "_blank");
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnTasks")?.addEventListener("click", async () => {
    try {
      showResult("dashTasks", await getJSON("/api/dash/tasks?limit=15"));
    } catch (e) {
      toast(e.message, "err");
    }
  });

  $("#btnEvents")?.addEventListener("click", async () => {
    try {
      showResult("dashEvents", await getJSON("/api/dash/events?limit=30"));
    } catch (e) {
      toast(e.message, "err");
    }
  });
}
