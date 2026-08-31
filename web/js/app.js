/* ==========================================================================
   Nuclei GUI — 前端逻辑
   ========================================================================== */
"use strict";

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

const PROTOCOLS = ["dns", "file", "http", "headless", "network", "tcp", "ssl",
  "websocket", "whois", "code", "javascript", "workflow"];

const State = {
  scans: [],
  runningScanId: null,     // 正在轮询实时输出的扫描
  currentDetail: null,     // 当前详情扫描
  detailResults: [],
  templates: [],
  templatesLoaded: false,  // 平铺列表是否已从本机加载过模板
  tags: [],
};

/* ---------------- 工具 ---------------- */
let toastTimer = null;
function toast(msg, isErr) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g,
    c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function sevClass(sev) {
  return "sev-" + (String(sev || "info").toLowerCase());
}

function escapeHtmlForConsole(s) { return esc(s); }

/* ---------------- 主题 ---------------- */
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  $("#iconSun").style.display = theme === "light" ? "block" : "none";
  $("#iconMoon").style.display = theme === "dark" ? "block" : "none";
}
$("#themeToggle").addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme") || "dark";
  const next = cur === "dark" ? "light" : "dark";
  applyTheme(next);
  api("/api/config", { method: "POST", body: JSON.stringify({ theme: next }) }).catch(() => {});
});

/* ---------------- 导航 ---------------- */
$$(".nav-item").forEach(item => {
  item.addEventListener("click", () => switchPage(item.dataset.page));
});

function switchPage(page) {
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page === page));
  $$(".page").forEach(p => p.classList.toggle("active", p.id === "page-" + page));
  if (page === "history") refreshHistory();
  if (page === "templates") loadMyTemplates($("#myTplList"), "manage");
  if (page === "settings") loadSettings();
}

/* ---------------- 引擎状态 ---------------- */
async function refreshEngineStatus() {
  try {
    const st = await api("/api/status");
    const chip = $("#engineStatus");
    if (st.ok) {
      chip.className = "status-chip ok";
      $("#engineStatusText").textContent = `nuclei v${st.version || "?"}`;
      $("#footEngine").textContent = st.version ? "v" + st.version : "就绪";
      $("#footTemplates").textContent = st.templates ? "v" + st.templates : "—";
      if (location.hash === "#settings") {
        $("#engineBox").className = "engine-box ok";
        $("#engineBox").textContent =
          `路径: ${st.path}\n版本: v${st.version || "未知"}\n模板: v${st.templates || "未知"}`;
      }
    } else {
      chip.className = "status-chip err";
      $("#engineStatusText").textContent = "nuclei 未找到";
      $("#footEngine").textContent = "未找到";
      $("#footTemplates").textContent = "—";
      if (location.hash === "#settings") {
        $("#engineBox").className = "engine-box err";
        $("#engineBox").textContent = st.error || "未找到 nuclei";
      }
    }
  } catch (e) {
    $("#engineStatusText").textContent = "无法连接";
  }
}

/* ==========================================================================
   扫描页
   ========================================================================== */

function getScanParams() {
  const mode = $("#targetMode .seg-btn.active").dataset.mode;
  const targets = mode === "single"
    ? [$("#targetSingle").value.trim()]
    : $("#targetMulti").value.split("\n").map(s => s.trim()).filter(Boolean);
  const params = {
    targets,
    severity: [],
    exclude_severity: [],
    tags: "",
    exclude_tags: "",
    templates: selectedTemplate ? [selectedTemplate] : [],
    types: [],
    rate_limit: parseInt($("#rl").value || "0", 10) || 0,
    concurrency: parseInt($("#cc").value || "0", 10) || 0,
    bulk_size: parseInt($("#bs").value || "0", 10) || 0,
    timeout: parseInt($("#to").value || "0", 10) || 0,
    retries: $("#rt").value === "" ? 0 : (parseInt($("#rt").value, 10) || 0),
    follow_redirects: $("#optFollow").checked,
    headless: $("#optHeadless").checked,
    silent: $("#optSilent").checked,
    verbose: $("#optVerbose").checked,
    store_resp: $("#optStoreResp").checked,
    proxy: $("#scanProxy").value.trim(),
    headers: $("#scanHeaders").value.trim(),
    extra_args: $("#scanExtra").value.trim(),
  };
  return params;
}

function fillScanFromDefaults(defs) {
  if (!defs) return;
  if (defs.rate_limit) $("#rl").value = defs.rate_limit;
  if (defs.concurrency) $("#cc").value = defs.concurrency;
  if (defs.bulk_size) $("#bs").value = defs.bulk_size;
  if (defs.timeout) $("#to").value = defs.timeout;
  if (defs.retries !== undefined) $("#rt").value = defs.retries;
  if (defs.silent !== undefined) $("#optSilent").checked = !!defs.silent;
  if (defs.verbose) $("#optVerbose").checked = true;
  if (defs.follow_redirects) $("#optFollow").checked = true;
  if (defs.headless) $("#optHeadless").checked = true;
  if (defs.store_resp) $("#optStoreResp").checked = true;
  if (defs.check_update === false) { /* 由后端 -duc 处理 */ }
}

async function startScan() {
  const params = getScanParams();
  if (!params.targets.length) {
    toast("请先填写扫描目标", true);
    return;
  }
  const btn = $("#btnStart");
  btn.disabled = true;
  try {
    const res = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify(params),
    });
    toast("扫描已提交：" + res.id);
    $("#liveCard").style.display = "block";
    $("#liveConsole").textContent = "";
    $("#liveFindings").textContent = "0 条结果";
    $("#scanProgress").classList.remove("done");
    State.runningScanId = res.id;
    $("#btnStop").disabled = false;
    $("#liveState").textContent = "运行中";
    $("#scanMsg").textContent = "扫描运行中…";
    beginLivePoll(res.id, 0);
  } catch (e) {
    toast("启动失败: " + e.message, true);
    btn.disabled = false;
  }
}

async function stopScan() {
  if (!State.runningScanId) return;
  try {
    await api("/api/scans/" + State.runningScanId + "/stop", { method: "POST" });
    $("#scanMsg").textContent = "正在停止…";
  } catch (e) { /* ignore */ }
}

/* 实时输出轮询 */
let liveTimer = null;
function beginLivePoll(scanId, offset) {
  clearInterval(liveTimer);
  liveTimer = setInterval(async () => {
    try {
      const data = await api(`/api/scans/${scanId}/output?offset=${offset}`);
      const consoleEl = $("#liveConsole");
      if (data.lines.length) {
        consoleEl.textContent += data.lines.join("\n") + "\n";
        consoleEl.scrollTop = consoleEl.scrollHeight;
        offset = data.offset;
      }
      // 实时结果计数（后端扫描过程中实时统计 -jle 文件行数）
      if (typeof data.result_count === "number") {
        $("#liveFindings").textContent = data.result_count + " 条结果";
      }
      if (!data.running) {
        clearInterval(liveTimer);
        State.runningScanId = null;
        $("#btnStop").disabled = true;
        $("#btnStart").disabled = false;
        $("#liveState").textContent = "已结束";
        $("#scanProgress").classList.add("done");
        $("#scanMsg").textContent = "";
        toast("扫描结束");
        setTimeout(() => { $("#liveCard").style.display = "none"; }, 8000);
        // 若当前在历史页则刷新
        if ($("#page-history").classList.contains("active")) refreshHistory();
      }
    } catch (e) {
      // 连接失败时停止轮询
      clearInterval(liveTimer);
    }
  }, 1500);
}

/* 目标模式切换 */
$$("#targetMode .seg-btn").forEach(b => {
  b.addEventListener("click", () => {
    $$("#targetMode .seg-btn").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    const single = b.dataset.mode === "single";
    $("#targetSingleWrap").style.display = single ? "" : "none";
    $("#targetMultiWrap").style.display = single ? "none" : "";
  });
});

/* 从文件导入目标（每行一个 IP / URL / CIDR） */
$("#btnImportTargets").addEventListener("click", () => $("#targetFileInput").click());
$("#targetFileInput").addEventListener("change", (e) => {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    const lines = String(reader.result || "").split(/\r?\n/).map(s => s.trim())
      .filter(s => s && !s.startsWith("#") && !s.startsWith("//"));
    const uniq = [...new Set(lines)];
    // 切换到多目标模式并填充
    const multiBtn = document.querySelector('#targetMode .seg-btn[data-mode="multi"]');
    if (multiBtn) multiBtn.click();
    $("#targetMulti").value = uniq.join("\n");
    toast(`已导入 ${uniq.length} 个目标（去重后）`);
  };
  reader.readAsText(f);
  e.target.value = "";
});

$("#btnToggleExtra").addEventListener("click", (e) => {
  const w = $("#extraWrap");
  const show = w.style.display !== "block";
  w.style.display = show ? "block" : "none";
  e.target.textContent = show ? "收起" : "展开";
});

/* 速率与优化：展开/收缩 */
$("#btnToggleOpt").addEventListener("click", (e) => {
  const w = $("#optWrap");
  const hidden = w.style.display === "none";
  w.style.display = hidden ? "" : "none";
  e.target.textContent = hidden ? "收起" : "展开";
});

$("#btnStart").addEventListener("click", startScan);
$("#btnStop").addEventListener("click", stopScan);

/* ==========================================================================
   历史记录
   ========================================================================== */
function statusTag(s) {
  const cls = "st-" + (s || "queued");
  const label = { queued: "排队中", running: "运行中", stopping: "停止中",
    completed: "已完成", stopped: "已停止", failed: "失败", error: "错误" }[s] || s;
  return `<span class="st-tag ${cls}"><span class="sdot"></span>${label}</span>`;
}

function filterText(f) {
  if (!f) return "—";
  const parts = [];
  if (f.severity && f.severity.length) parts.push(f.severity.join(","));
  if (f.tags) parts.push("tags:" + f.tags);
  if (f.types && f.types.length) parts.push(f.types.join(","));
  return parts.join(" · ") || "—";
}

async function refreshHistory() {
  try {
    const data = await api("/api/scans");
    State.scans = data.scans || [];
    const body = $("#historyBody");
    body.innerHTML = "";
    const empty = $("#historyEmpty");
    empty.hidden = State.scans.length > 0;
    $("#navHistoryBadge").hidden = State.scans.length === 0;
    $("#navHistoryBadge").textContent = State.scans.length;
    State.scans.forEach(s => {
      const tr = document.createElement("tr");
      const targets = (s.targets || []).join("; ") || "—";
      tr.innerHTML = `
        <td>${statusTag(s.status)}</td>
        <td class="target-cell" title="${esc(targets)}">${esc(targets)}</td>
        <td>${esc(filterText(s.filters))}</td>
        <td><span class="badge ${s.result_count > 0 ? "accent" : ""}">${s.result_count || 0}</span></td>
        <td style="white-space:nowrap;color:var(--text-2);font-size:12px">${esc(s.created_at || "")}</td>
        <td>
          <div class="row-actions">
            <button class="mini-btn" data-act="view" data-id="${s.id}">详情</button>
            <button class="mini-btn danger" data-act="del" data-id="${s.id}">删除</button>
          </div>
        </td>`;
      body.appendChild(tr);
    });
    $$("#historyBody .mini-btn").forEach(b => {
      b.addEventListener("click", async () => {
        const id = b.dataset.id;
        if (b.dataset.act === "view") await openDetail(id);
        else {
          try {
            await api("/api/scans/" + id, { method: "DELETE" });
            toast("已删除记录");
            refreshHistory();
          } catch (e) { toast("删除失败", true); }
        }
      });
    });
  } catch (e) {
    toast("加载历史失败: " + e.message, true);
  }
}

/* 详情弹窗 */
async function openDetail(id) {
  const s = State.scans.find(x => x.id === id);
  if (!s) return;
  State.currentDetail = s;
  $("#detailModal").hidden = false;
  $("#detailTitle").textContent = "扫描详情";
  $("#detailSub").textContent = `${esc((s.targets || []).join("; "))}  ·  ${esc(s.created_at || "")}`;
  // 结果
  State.detailDeduped = false;
  const data = await api(`/api/scans/${id}/results`);
  State.detailResults = data.results || [];
  State.detailStats = data.stats || {};
  renderResults();
  // 日志
  try {
    const log = await api(`/api/scans/${id}/output?offset=0`);
    $("#detailLog").textContent = (log.lines || []).join("\n") || "（无日志）";
  } catch (e) { $("#detailLog").textContent = "（读取失败）"; }
  // 命令
  $("#detailCmd").textContent = s.command || "（无命令记录）";
  // 刷新按钮激活
  const running = s.status === "running" || s.status === "stopping" || s.status === "queued";
  // 导出链接
  $("#btnExport").onclick = () => { window.open(`/api/scans/${id}/report?format=jsonl`); };
  $("#btnExportTxt").onclick = () => { window.open(`/api/scans/${id}/report?format=txt`); };
  $("#btnExportMd").onclick = () => { window.open(`/api/scans/${id}/report?format=md`); };
  $("#btnDedupe").onclick = async () => {
    State.detailDeduped = !State.detailDeduped;
    const q = State.detailDeduped ? "?dedupe=1" : "";
    try {
      const data = await api(`/api/scans/${id}/results${q}`);
      State.detailResults = data.results || [];
      State.detailStats = data.stats || {};
      renderResults();
      toast(State.detailDeduped ? "已按漏洞去重（保留最高严重度）" : "已显示全部原始结果");
    } catch (e) {
      toast("切换去重失败: " + e.message, true);
    }
  };
  $("#btnRescan").onclick = async () => {
    const btn = $("#btnRescan");
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "重扫中…";
    try {
      const r = await api(`/api/scans/${id}/rescan`, { method: "POST", body: "{}" });
      if (r.ok) {
        toast("已用相同目标与参数发起新扫描");
        refreshHistory();
        setTimeout(() => { $("#detailModal").hidden = true; switchPage("history"); }, 600);
      } else {
        toast("重扫失败: " + (r.error || ""), true);
      }
    } catch (e) {
      toast("重扫失败: " + e.message, true);
    }
    btn.disabled = false;
    btn.textContent = original;
  };
}

function renderResults() {
  const rows = State.detailResults;
  const active = $$("#resultSevFilter .pill.active").map(p => p.querySelector("input").value);
  const showAll = active.includes("all") || active.length === 0;
  const filtered = showAll ? rows : rows.filter(r => active.includes(r.severity));
  const body = $("#resultsBody");
  body.innerHTML = "";
  $("#resultsEmpty").hidden = filtered.length > 0;
  $("#tabResultCount").textContent = rows.length;
  // 严重程度统计徽章
  const stats = State.detailStats || {};
  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const statsEl = $("#resultStats");
  if (statsEl) {
    statsEl.innerHTML = (State.detailDeduped ? "（已去重）" : "（原始）") + " 总计 " +
      (stats.total != null ? stats.total : rows.length) +
      " 条：" + sevOrder.map(s =>
        `<span class="sev-tag ${sevClass(s)}" style="margin-left:4px">${s} ${stats[s] || 0}</span>`
      ).join("");
  }
  // 去重按钮状态
  const dd = $("#btnDedupe");
  if (dd) dd.classList.toggle("active", !!State.detailDeduped);
  filtered.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="sev-tag ${sevClass(r.severity)}">${esc(r.severity)}</span></td>
      <td>
        <div style="font-weight:600">${esc(r.name)}</div>
        <div style="font-size:11.5px;color:var(--text-3);font-family:monospace">${esc(r.template_id)}</div>
      </td>
      <td class="target-cell" title="${esc(r.matched_at || r.host)}">${esc(r.host || r.matched_at || "")}</td>
      <td>${esc(r.type || "")}</td>
      <td style="font-size:12px;color:var(--text-2)">${esc(r.matcher || "")}</td>
      <td><div class="row-actions">
        <button class="mini-btn" data-act="yaml" title="生成 YAML 模板">YAML</button>
        <button class="mini-btn" data-act="raw" title="查看原始 JSON">JSON</button>
      </div></td>`;
    body.appendChild(tr);
    tr.querySelector("[data-act=yaml]").addEventListener("click", () => openYamlEditor(null, r));
    tr.querySelector("[data-act=raw]").addEventListener("click", () => {
      toast(r.raw.length > 400 ? r.raw.slice(0, 400) + " …" : r.raw);
    });
  });
}

$$("#resultSevFilter .pill").forEach(p => {
  p.addEventListener("click", () => {
    // 单选风格：点击全部则清空其它，点击其它则取消全部
    const inp = p.querySelector("input");
    const val = inp.value;
    if (val === "all") {
      $$("#resultSevFilter .pill").forEach(x => x.classList.remove("active"));
      p.classList.add("active");
      inp.checked = true;
    } else {
      $$("#resultSevFilter .pill").forEach(x => {
        const v = x.querySelector("input").value;
        if (v !== "all") x.classList.remove("active");
      });
      $$("#resultSevFilter .pill").forEach(x => {
        if (x.querySelector("input").value === "all") x.classList.remove("active");
      });
      p.classList.toggle("active");
      inp.checked = p.classList.contains("active");
    }
    renderResults();
  });
});

$("#detailClose").addEventListener("click", () => { $("#detailModal").hidden = true; });
$("#detailModal").addEventListener("click", (e) => {
  if (e.target === $("#detailModal")) $("#detailModal").hidden = true;
});
$$(".mtab").forEach(t => {
  t.addEventListener("click", () => {
    $$(".mtab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    const tab = t.dataset.tab;
    $$(".mtab-panel").forEach(p => p.classList.remove("active"));
    $("#panel-" + tab).classList.add("active");
  });
});

/* ==========================================================================
   模板库
   ========================================================================== */

/* ==========================================================================
   模板目录树（参数化：mode=pick 填入扫描 / mode=manage 文件管理）
   ========================================================================== */
function treeArrowSvg() {
  return '<svg viewBox="0 0 24 24" width="12" height="12"><path d="M9 5l7 7-7 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}
function treeFolderSvg() {
  return '<svg viewBox="0 0 24 24" width="15" height="15"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="currentColor" opacity=".8"/></svg>';
}
function treeFileSvg() {
  return '<svg viewBox="0 0 24 24" width="15" height="15"><path d="M6 2h8l4 4v16a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z" fill="currentColor" opacity=".35"/></svg>';
}

/* ---- 模板文件管理操作（删除 / 重命名 / 移动） ---- */
function treeMiniBtn(label, fn, danger) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "mini-btn" + (danger ? " danger" : "");
  b.textContent = label;
  b.addEventListener("click", (e) => { e.stopPropagation(); fn(); });
  return b;
}

function reloadTplTree(st) {
  const expandList = Array.from(st.expanded);  // 记住展开路径
  st.expanded.clear();
  st.loaded.clear();
  loadTreeDir("", st.treeEl, st).then(() => {
    // 逐层重新展开之前展开过的路径
    (async () => {
      let cur = "";
      const parts = [];
      expandList.forEach(p => { if (p) parts.push(p); });
      for (const p of parts) {
        const rows = st.treeEl.querySelectorAll(".tree-dir");
        let row = null;
        rows.forEach(r => { if (r.dataset.path === p) row = r; });
        if (row) {
          if (!st.expanded.has(p)) row.click();
          await new Promise(res => setTimeout(res, 250));
        }
      }
    })();
  });
}

function deleteTplPath(path, st) {
  if (!confirm("确定删除模板文件？\n" + path + "\n\n此操作不可恢复。")) return;
  api("/api/templates/file/delete", { method: "POST", body: JSON.stringify({ path }) })
    .then(d => { toast(d.message || "已删除"); reloadTplTree(st); })
    .catch(e => toast("删除失败: " + e.message, true));
}

function renameTplPath(path, st) {
  const cur = path.split("/").pop();
  const name = prompt("重命名模板文件（可省略 .yaml 后缀）：", cur);
  if (!name) return;
  api("/api/templates/file/rename",
      { method: "POST", body: JSON.stringify({ path, new_name: name }) })
    .then(d => { toast(d.message || "已重命名"); reloadTplTree(st); })
    .catch(e => toast("重命名失败: " + e.message, true));
}

function moveTplPath(path, st) {
  const dest = prompt("移动到目标目录（相对模板根，留空 = 根目录）：\n例如 http/cves", "");
  if (dest === null) return;
  api("/api/templates/file/move",
      { method: "POST", body: JSON.stringify({ path, dest_dir: dest }) })
    .then(d => { toast(d.message || "已移动"); reloadTplTree(st); })
    .catch(e => toast("移动失败: " + e.message, true));
}

/* ---- 树渲染 ---- */
function treeActionsFor(st, item) {
  const box = document.createElement("span");
  box.className = "tree-actions";
  if (st.mode === "pick") {
    const a = document.createElement("span");
    a.className = "tree-add";
    a.textContent = "填入扫描";
    a.title = item.type === "dir" ? "精确扫描该目录" : "精确扫描该模板";
    a.addEventListener("click", (e) => { e.stopPropagation(); st.onPick(item.path); });
    box.appendChild(a);
  } else {
    if (item.type === "file") box.appendChild(treeMiniBtn("改名", () => renameTplPath(item.path, st)));
    box.appendChild(treeMiniBtn("移动", () => moveTplPath(item.path, st)));
    box.appendChild(treeMiniBtn("删除", () => deleteTplPath(item.path, st), true));
  }
  return box;
}

async function loadTreeDir(rel, containerEl, st) {
  containerEl.innerHTML = '<div class="empty"><p>加载中…</p></div>';
  try {
    const q = new URLSearchParams();
    if (rel) q.set("dir", rel);
    const data = await api("/api/templates/tree?" + q.toString());
    if (data.error) throw new Error(data.error);
    st.root = data.root;
    st.loaded.add(rel);
    renderTreeChildren(rel, data.items || [], containerEl, st);
  } catch (e) {
    containerEl.innerHTML = '<div class="empty"><p>加载失败: ' + esc(e.message) + '</p></div>';
  }
}

function renderTreeChildren(rel, items, containerEl, st) {
  containerEl.innerHTML = "";
  if (!items.length) {
    containerEl.innerHTML = '<div class="empty"><p>该目录暂无模板</p></div>';
    return;
  }
  items.forEach(item => {
    const row = document.createElement("div");
    row.className = "tree-row " + (item.type === "dir" ? "tree-dir" : "tree-file");
    row.dataset.path = item.path;

    const arrow = document.createElement("span");
    arrow.className = "tree-arrow" + (item.type === "file" ? " leaf"
      : (st.expanded.has(item.path) ? " open" : ""));
    arrow.innerHTML = treeArrowSvg();

    const icon = document.createElement("span");
    icon.className = "tree-icon";
    icon.innerHTML = item.type === "dir" ? treeFolderSvg() : treeFileSvg();

    const name = document.createElement("span");
    name.className = "tree-name";
    name.textContent = item.name;
    name.title = item.path;

    const actions = treeActionsFor(st, item);

    row.appendChild(arrow); row.appendChild(icon); row.appendChild(name); row.appendChild(actions);
    containerEl.appendChild(row);

    if (item.type === "dir") {
      const kids = document.createElement("div");
      kids.className = "tree-children";
      kids.style.display = st.expanded.has(item.path) ? "" : "none";
      kids.innerHTML = '<div class="empty"><p>…</p></div>';
      row.addEventListener("click", () => toggleTreeDir(item, row, arrow, kids, st));
      containerEl.appendChild(kids);
    } else if (st.mode === "pick") {
      row.addEventListener("click", () => st.onPick(item.path));
    }
  });
}

async function toggleTreeDir(item, row, arrow, kids, st) {
  if (st.expanded.has(item.path)) {
    st.expanded.delete(item.path);
    arrow.classList.remove("open");
    kids.style.display = "none";
  } else {
    st.expanded.add(item.path);
    arrow.classList.add("open");
    kids.style.display = "";
    // 若子容器尚无实际内容（根重载后可能只剩占位），则重新加载
    if (!st.loaded.has(item.path) || !kids.querySelector(".tree-row")) {
      st.loaded.add(item.path);
      await loadTreeDir(item.path, kids, st);
    }
  }
}

/* ---- 模板树实例（模板库 manage / 扫描页 pick，均仅目录树） ---- */
function initTplPicker(st, ids) {
  st.treeEl = $(ids.tree);
  loadTreeDir("", st.treeEl, st);
}

/* 模板库页：管理模式（文件管理，仅目录树） */
const TplLibState = { root: "", expanded: new Set(), loaded: new Set(), mode: "manage",
  templates: [], templatesLoaded: false, onPick: null };
initTplPicker(TplLibState, {
  tree: "#tplTree",
});

/* 扫描页：选择模式（点选即指定扫描模板） */
const ScanTplState = { root: "", expanded: new Set(), loaded: new Set(), mode: "pick",
  templates: [], templatesLoaded: false, mineLoaded: false,
  onPick: (p) => setSelectedTemplate(p) };
initTplPicker(ScanTplState, { tree: "#scanTplTree" });

/* 扫描页模板树：内置/我的 tab 切换 */
$("#scanTplTabSeg").addEventListener("click", (e) => {
  const btn = e.target.closest(".seg-btn");
  if (!btn) return;
  $$("#scanTplTabSeg .seg-btn").forEach(b => b.classList.toggle("active", b === btn));
  const tab = btn.dataset.tab;
  $("#scanTplBuiltin").style.display = tab === "builtin" ? "" : "none";
  $("#scanTplMine").style.display = tab === "mine" ? "" : "none";
  if (tab === "mine" && !ScanTplState.mineLoaded) {
    ScanTplState.mineLoaded = true;
    loadMyTemplates($("#scanMyTplList"), "pick");
  }
});

/* 扫描页模板树内搜索（搜索模板或目录） */
let scanAllItems = null;
let scanTplSearchTimer = null;
$("#scanTplSearch").addEventListener("input", (e) => {
  clearTimeout(scanTplSearchTimer);
  scanTplSearchTimer = setTimeout(() => scanTplSearch(e.target.value.trim()), 220);
});

async function scanTplSearch(kw) {
  const treeEl = $("#scanTplTree");
  const resEl = $("#scanTplResults");
  if (!kw) {
    resEl.style.display = "none";
    treeEl.style.display = "";
    return;
  }
  if (!scanAllItems) {
    try {
      const d = await api("/api/templates/all");
      scanAllItems = d.items || [];
    } catch (err) {
      resEl.innerHTML = '<div class="empty"><p>加载模板列表失败</p></div>';
      resEl.style.display = "";
      treeEl.style.display = "none";
      return;
    }
  }
  const q = kw.toLowerCase();
  const dirs = scanAllItems.filter(i => i.type === "dir" && i.path.toLowerCase().includes(q));
  const files = scanAllItems.filter(i => i.type === "file" && i.path.toLowerCase().includes(q));
  resEl.innerHTML = "";
  if (!dirs.length && !files.length) {
    resEl.innerHTML = '<div class="empty"><p>无匹配模板或目录</p></div>';
  } else {
    const mkRow = (item) => {
      const row = document.createElement("div");
      row.className = "tpl-item";
      const icon = item.type === "dir"
        ? '<span class="tpl-icon"><svg viewBox="0 0 24 24" width="14" height="14"><path d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="currentColor" opacity=".8"/></svg></span>'
        : '<span class="tpl-icon"><svg viewBox="0 0 24 24" width="14" height="14"><path d="M4 5a1 1 0 0 1 1-1h6l2 2h6a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></span>';
      row.innerHTML = icon +
        `<span class="tpl-name" title="${esc(item.path)}">${esc(item.path)}</span>` +
        `<span class="tpl-add">填入扫描</span>`;
      row.addEventListener("click", () => ScanTplState.onPick(item.path));
      return row;
    };
    files.slice(0, 200).forEach(f => resEl.appendChild(mkRow(f)));
    dirs.slice(0, 100).forEach(d => resEl.appendChild(mkRow(d)));
  }
  treeEl.style.display = "none";
  resEl.style.display = "";
}

/* 当前选中的扫描模板（目录或单文件；空 = 扫描全部模板） */
let selectedTemplate = "";
function setSelectedTemplate(p) {
  selectedTemplate = p || "";
  const box = $("#scanSelectedTpl");
  if (box) {
    $("#scanSelectedTplPath").textContent = selectedTemplate;
    box.style.display = selectedTemplate ? "" : "none";
  }
  toast(selectedTemplate ? "已选择模板: " + selectedTemplate : "已清除，将扫描全部模板");
}
$("#btnClearSelectedTpl").addEventListener("click", () => setSelectedTemplate(""));

/* ==========================================================================
   设置
   ========================================================================== */
async function loadSettings() {
  try {
    const cfg = await api("/api/config");
    $("#setNucleiPath").value = cfg.nuclei_path || "";
    $("#setDataDir").value = cfg.data_dir || "";
    const st = await api("/api/status");
    $("#setTplDir").value = st.templates_dir || "";
    $("#setCustomTplDir").value = st.custom_templates_dir || "";
    const d = cfg.defaults || {};
    $("#defRate").value = d.rate_limit || "";
    $("#defConc").value = d.concurrency || "";
    $("#defBulk").value = d.bulk_size || "";
    $("#defTimeout").value = d.timeout || "";
    $("#defRetries").value = d.retries !== undefined ? d.retries : "";
    $("#defCheckUpdate").checked = d.check_update !== false;
    fillScanFromDefaults(d);
    refreshEngineStatus();
  } catch (e) { toast("加载设置失败", true); }
}

$("#btnSaveSettings").addEventListener("click", async () => {
  try {
    await api("/api/config", {
      method: "POST",
      body: JSON.stringify({
        nuclei_path: $("#setNucleiPath").value,
        defaults: {
          rate_limit: parseInt($("#defRate").value || "0", 10) || 0,
          concurrency: parseInt($("#defConc").value || "0", 10) || 0,
          bulk_size: parseInt($("#defBulk").value || "0", 10) || 0,
          timeout: parseInt($("#defTimeout").value || "0", 10) || 0,
          retries: parseInt($("#defRetries").value || "0", 10) || 0,
          check_update: $("#defCheckUpdate").checked,
        },
      }),
    });
    toast("设置已保存（保存在 data/config.json）");
    refreshEngineStatus();
  } catch (e) { toast("保存失败: " + e.message, true); }
});

$("#btnDetect").addEventListener("click", async () => {
  const st = await api("/api/status");
  if (st.ok) {
    $("#setNucleiPath").value = st.path;
    toast("已检测到 nuclei: " + st.path);
  } else toast(st.error || "未找到 nuclei", true);
  refreshEngineStatus();
});

async function doUpdate(target, forceMirror, btn) {
  const original = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "处理中…"; }
  const msgEl = $("#updateMsg");
  if (msgEl) msgEl.textContent = "正在处理，官方源不可达时将自动回退镜像，请稍候…";
  try {
    const res = await api("/api/update", {
      method: "POST",
      body: JSON.stringify({ target, force_mirror: !!forceMirror }),
    });
    const src = res.source === "mirror" ? "（镜像源）" : "（官方源）";
    if (res.ok) {
      toast("更新成功 " + src);
      if (msgEl) msgEl.textContent = "成功 " + src + "\n" + (res.output || "");
      setTimeout(refreshEngineStatus, 1500);
    } else {
      toast("更新失败 " + src, true);
      if (msgEl) msgEl.textContent = "失败 " + src + "\n" + (res.output || res.error || "");
    }
  } catch (e) {
    toast("更新失败: " + e.message, true);
    if (msgEl) msgEl.textContent = "更新失败: " + e.message;
  }
  if (btn) { btn.disabled = false; btn.textContent = original; }
}

$("#btnUpdateTemplates").addEventListener("click", () => doUpdate("templates", false, $("#btnUpdateTemplates")));
$("#btnMirrorTemplates").addEventListener("click", () => doUpdate("templates", true, $("#btnMirrorTemplates")));
$("#btnUpdateNuclei").addEventListener("click", () => doUpdate("nuclei", false, $("#btnUpdateNuclei")));
$("#btnMirrorNuclei").addEventListener("click", () => doUpdate("nuclei", true, $("#btnMirrorNuclei")));

$("#btnNetCheck").addEventListener("click", async () => {
  const box = $("#netBox");
  box.textContent = "检测中…";
  box.className = "engine-box";
  try {
    const r = await api("/api/netcheck");
    box.textContent = (r.detail || []).join("\n");
    box.className = "engine-box " + (r.mirror || r.github ? "ok" : "err");
  } catch (e) {
    box.textContent = "检测失败: " + e.message;
    box.className = "engine-box err";
  }
});

/* ---- 数据备份与恢复 ---- */
$("#btnBackup").addEventListener("click", async () => {
  const btn = $("#btnBackup");
  const msgEl = $("#backupMsg");
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = "打包中…";
  msgEl.textContent = "";
  try {
    const resp = await fetch("/api/backup", { cache: "no-store" });
    if (!resp.ok) throw new Error("备份失败 (HTTP " + resp.status + ")");
    const blob = await resp.blob();
    const cd = resp.headers.get("Content-Disposition") || "";
    const m = cd.match(/filename="([^"]+)"/);
    const fname = m ? m[1] : "nuclei-gui-backup.zip";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fname;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    msgEl.textContent = "备份已下载：" + fname + "（含配置、历史、结果与自定义模板）";
    toast("备份已下载");
  } catch (e) {
    msgEl.textContent = "备份失败: " + e.message;
    toast("备份失败: " + e.message, true);
  }
  btn.disabled = false;
  btn.textContent = original;
});

$("#btnRestore").addEventListener("click", () => {
  $("#restoreFile").click();
});

$("#restoreFile").addEventListener("change", async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  const msgEl = $("#backupMsg");
  msgEl.textContent = "正在读取 " + file.name + " …";
  try {
    const buf = await file.arrayBuffer();
    let binary = "";
    const bytes = new Uint8Array(buf);
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    const zipB64 = btoa(binary);
    const res = await api("/api/restore", {
      method: "POST",
      body: JSON.stringify({ zip_b64: zipB64 }),
    });
    if (res.ok) {
      msgEl.textContent = "恢复成功：" + file.name +
        (res.summary && res.summary.pre_backup
          ? "（恢复前已备份当前数据到 " + res.summary.pre_backup + "）"
          : "");
      toast("恢复成功");
      refreshEngineStatus();
      if (window.refreshHistory) refreshHistory();
      loadMyTemplates($("#myTplList"), "manage");
      loadMyTemplates($("#scanMyTplList"), "pick");
    } else {
      msgEl.textContent = "恢复失败: " + (res.error || "未知错误");
      toast("恢复失败: " + (res.error || ""), true);
    }
  } catch (e) {
    msgEl.textContent = "恢复失败: " + e.message;
    toast("恢复失败: " + e.message, true);
  } finally {
    ev.target.value = "";
  }
});

/* ==========================================================================
   YAML 模板：从漏洞结果生成 / 自定义模板管理
   ========================================================================== */
let yamlEditing = null;      // {name, useInScan}

function openYamlEditor(existingName, result, presetName, presetContent) {
  const modal = $("#yamlModal");
  modal.hidden = false;
  yamlEditing = { name: existingName || "", useInScan: false };
  $("#yamlName").value = "";
  $("#yamlContent").value = "";
  $("#yamlMsg").textContent = "";
  if (existingName) {
    // 编辑已保存的自定义模板
    $("#yamlSub").textContent = "编辑自定义模板：custom-templates/" + existingName;
    $("#yamlName").value = existingName;
    $("#yamlSave").textContent = "保存修改";
    $("#yamlUse").textContent = "保存并用于扫描";
    api("/api/templates/custom?name=" + encodeURIComponent(existingName)).then(d => {
      $("#yamlContent").value = d.content;
    }).catch(() => toast("读取模板失败", true));
  } else if (presetContent != null) {
    // 预设内容（如新建空白模板）
    $("#yamlName").value = presetName || "my-template";
    $("#yamlContent").value = presetContent;
    $("#yamlSave").textContent = "保存模板";
    $("#yamlUse").textContent = "保存并用于扫描";
  } else {
    // 从漏洞结果生成
    $("#yamlSub").textContent = "来源：历史漏洞结果 → YAML 模板（请核对内容后保存）";
    $("#yamlSave").textContent = "保存模板";
    $("#yamlUse").textContent = "保存并用于扫描";
    api("/api/templates/from-result", {
      method: "POST",
      body: JSON.stringify({ result }),
    }).then(d => {
      $("#yamlContent").value = d.content;
      $("#yamlName").value = d.name;
      $("#yamlSub").textContent = d.source === "builtin"
        ? `来源：已从本地内置模板库找到 ${d.name}，可直接修改另存`
        : "来源：自动生成骨架（请根据漏洞特征补全 matchers）";
    }).catch(() => toast("生成失败: 请先安装模板库", true));
  }
}

function saveYaml(useInScan) {
  const name = $("#yamlName").value.trim();
  const content = $("#yamlContent").value;
  if (!name) { toast("请填写模板文件名", true); return; }
  if (!/^[A-Za-z0-9_\-]+(\.ya?ml)?$/.test(name)) {
    toast("文件名只能包含字母、数字、下划线、中划线", true);
    return;
  }
  api("/api/templates/custom", {
    method: "POST",
    body: JSON.stringify({ name, content }),
  }).then(d => {
    toast("模板已保存：" + d.name);
    $("#yamlMsg").textContent = "已保存 → " + (d.path || d.name);
    loadMyTemplates($("#myTplList"), "manage");
    loadMyTemplates($("#scanMyTplList"), "pick");
    if (useInScan) {
      setSelectedTemplate(d.path || name);
      $("#yamlModal").hidden = true;
      switchPage("scan");
    }
  }).catch(e => {
    toast("保存失败: " + e.message, true);
    $("#yamlMsg").textContent = "保存失败: " + e.message;
  });
}

$("#yamlSave").addEventListener("click", () => saveYaml(false));
$("#yamlUse").addEventListener("click", () => saveYaml(true));
$("#yamlClose").addEventListener("click", () => { $("#yamlModal").hidden = true; });
$("#yamlCancel").addEventListener("click", () => { $("#yamlModal").hidden = true; });
$("#yamlModal").addEventListener("click", (e) => {
  if (e.target === $("#yamlModal")) $("#yamlModal").hidden = true;
});

/* 校验模板：调用 nuclei -validate */
$("#yamlValidate").addEventListener("click", async () => {
  const btn = $("#yamlValidate");
  const msgEl = $("#yamlValidateMsg");
  const content = $("#yamlContent").value;
  if (!content.trim()) { msgEl.textContent = "请先填写模板内容"; return; }
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = "校验中…";
  msgEl.textContent = "";
  try {
    const res = await api("/api/templates/validate", {
      method: "POST",
      body: JSON.stringify({ content }),
    });
    if (!res.ok) {
      msgEl.textContent = res.output || "校验失败（未找到 nuclei）";
    } else if (res.valid) {
      msgEl.textContent = "✅ 校验通过：" + (res.output || "模板语法正确");
      msgEl.style.color = "var(--ok, #3ddc84)";
    } else {
      msgEl.textContent = "❌ 校验失败：\n" + (res.output || "模板存在语法错误");
      msgEl.style.color = "var(--err, #f14c4c)";
    }
  } catch (e) {
    msgEl.textContent = "校验失败: " + e.message;
    msgEl.style.color = "var(--err, #f14c4c)";
  }
  btn.disabled = false;
  btn.textContent = original;
});

async function loadMyTemplates(listEl, mode) {
  mode = mode || "manage";
  try {
    const data = await api("/api/templates/custom");
    const list = data.templates || [];
    const empty = '<div class="empty"><p>暂无自定义模板</p></div>';
    listEl.innerHTML = list.length ? "" : empty;
    if (mode === "manage") $("#myTplCount").textContent = list.length + " 个";
    list.forEach(t => {
      const row = document.createElement("div");
      row.className = "tpl-item mytpl";
      row.innerHTML = `
        <span class="tpl-icon">
          <svg viewBox="0 0 24 24" width="14" height="14"><path d="M4 5a1 1 0 0 1 1-1h6l2 2h6a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>
        </span>
        <span class="tpl-name" title="${esc(t.path)}">${esc(t.name)}</span>
        <span style="font-size:11px;color:var(--text-3)">${esc(t.mtime || "")}</span>
        <span class="tpl-actions">${mode === "pick"
          ? '<button class="mini-btn" data-act="use">使用</button>'
          : '<button class="mini-btn" data-act="view">查看</button><button class="mini-btn" data-act="edit">编辑</button><button class="mini-btn" data-act="use">使用</button><button class="mini-btn danger" data-act="del">删除</button>'}</span>`;
      listEl.appendChild(row);
      const use = row.querySelector("[data-act=use]");
      if (use) use.addEventListener("click", () => {
        setSelectedTemplate(t.path);
        if (mode === "manage") switchPage("scan");
      });
      if (mode === "manage") {
        row.querySelector("[data-act=view]").addEventListener("click", () => {
          openYamlEditor(t.name);
          $("#yamlName").disabled = true;
          $("#yamlMsg").textContent = "只读查看（改名为保存为新模板需手动修改文件名）。";
        });
        row.querySelector("[data-act=edit]").addEventListener("click", () => {
          $("#yamlName").disabled = false;
          openYamlEditor(t.name);
        });
        row.querySelector("[data-act=del]").addEventListener("click", async () => {
          if (!confirm("确定删除模板 " + t.name + " ？")) return;
          try {
            await api("/api/templates/custom?name=" + encodeURIComponent(t.name), { method: "DELETE" });
            toast("已删除");
            loadMyTemplates($("#myTplList"), "manage");
            loadMyTemplates($("#scanMyTplList"), "pick");
          } catch (e) { toast("删除失败", true); }
        });
      }
    });
  } catch (e) {
    listEl.innerHTML = '<div class="empty"><p>加载失败</p></div>';
  }
}

$("#btnNewTemplate").addEventListener("click", () => {
  $("#yamlName").disabled = false;
  openYamlEditor(null, null, "my-custom-template", `id: my-custom-template

info:
  name: 我的自定义模板
  author: nuclei-gui
  severity: info
  description: |
    在此编写你的检测逻辑。
  tags: custom

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
`);
});

/* ==========================================================================
   初始化
   ========================================================================== */
async function init() {
  try {
    const cfg = await api("/api/config");
    applyTheme(cfg.theme || "dark");
    fillScanFromDefaults(cfg.defaults);
  } catch (e) { applyTheme("dark"); }
  refreshEngineStatus();
  refreshHistory();
  // 每 30 秒刷新一次引擎状态（用于发现刚安装的 nuclei）
  setInterval(refreshEngineStatus, 30000);
}

init();
