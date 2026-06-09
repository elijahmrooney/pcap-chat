// pcap-chat frontend
// Plain vanilla JS, no framework. Talks to /api/* on the same origin.
 
const $ = (sel) => document.querySelector(sel);
 
const state = {
sessionId: null,
filename: null,
selectedPacket: null,
busy: false,
// Per-streaming-turn DOM/state:
streamMsgEl: null,
streamBodyEl: null,
streamText: "",
activeTools: {}, // toolCallId -> trace DOM element
// Last filter result (so we can re-render selection state on row click)
currentTable: null,
};
 
const els = {
fileInput: $("#file-input"),
captureInfo: $("#capture-info"),
captureLabel: $("#capture-label"),
resetBtn: $("#reset-btn"),
provider: $("#provider"),
model: $("#model"),
chatLog: $("#chat-log"),
message: $("#message"),
composer: $("#composer"),
sendBtn: $("#send-btn"),
traceList: $("#trace-list"),
traceSub: $("#trace-sub"),
tableHost: $("#table-host"),
tableSub: $("#table-sub"),
detailHost: $("#detail-host"),
detailSub: $("#detail-sub"),
statusDot: $("#status-dot"),
statusText: $("#status-text"),
};
 
// --- helpers ---------------------------------------------------------------
 
function escapeHtml(s) {
return String(s)
.replaceAll('&', '&amp;')
.replaceAll('<', '<')
.replaceAll('>', '>')
.replaceAll('"', '"')
.replaceAll("'", '&#039;');
}
 
function fmtBytes(n) {
const units = ["B", "KB", "MB", "GB"];
let i = 0;
while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}
 
function setStatus(s, t) {
els.statusDot.dataset.state = s;
els.statusText.textContent = t;
}
 
function setBusy(busy) {
state.busy = busy;
els.sendBtn.disabled = busy || !state.sessionId;
els.message.disabled = busy || !state.sessionId;
}
 
// Replace "frame N", "packet N", "frame #N" with clickable spans.
function wrapFrameRefs(escapedText) {
return escapedText.replace(
/\b(frame|packet)\s*#?\s*(\d{1,8})\b/gi,
(match, _word, num) =>
`<span class="frame-ref" data-frame="${num}">${match}</span>`
);
}
 
// --- chat rendering --------------------------------------------------------
 
function clearHint() {
const hint = els.chatLog.querySelector(".hint");
if (hint) hint.remove();
}
 
function appendStaticMessage(role, text, opts = {}) {
clearHint();
const wrap = document.createElement("div");
wrap.className = "msg";
const head = document.createElement("div");
head.className = `msg-role ${role}`;
head.textContent = opts.label || role;
const body = document.createElement("div");
body.className = "msg-body";
body.innerHTML = wrapFrameRefs(escapeHtml(text));
wrap.append(head, body);
els.chatLog.appendChild(wrap);
scrollChatToBottom();
}
 
function startStreamingMessage() {
clearHint();
const wrap = document.createElement("div");
wrap.className = "msg";
const head = document.createElement("div");
head.className = "msg-role assistant";
head.textContent = "assistant";
const body = document.createElement("div");
body.className = "msg-body";
wrap.append(head, body);
els.chatLog.appendChild(wrap);
state.streamMsgEl = wrap;
state.streamBodyEl = body;
state.streamText = "";
renderStreamingBody();
scrollChatToBottom();
}
 
function appendStreamingChunk(chunk) {
if (!state.streamBodyEl) startStreamingMessage();
state.streamText += chunk;
renderStreamingBody();
scrollChatToBottom();
}
 
function renderStreamingBody() {
if (!state.streamBodyEl) return;
const escaped = escapeHtml(state.streamText);
state.streamBodyEl.innerHTML =
wrapFrameRefs(escaped) + '<span class="stream-cursor"></span>';
}
 
function finalizeStreamingMessage() {
if (!state.streamBodyEl) return;
// Drop the cursor; keep the wrapped refs.
state.streamBodyEl.innerHTML = wrapFrameRefs(escapeHtml(state.streamText));
state.streamMsgEl = null;
state.streamBodyEl = null;
state.streamText = "";
}
 
function scrollChatToBottom() {
els.chatLog.scrollTop = els.chatLog.scrollHeight;
}
 
// --- trace rendering -------------------------------------------------------
 
function clearTraceEmpty() {
const empty = els.traceList.querySelector(".empty");
if (empty) empty.remove();
}
 
function addTraceStart(id, name, input) {
clearTraceEmpty();
const item = document.createElement("div");
item.className = "trace-item";
item.dataset.toolId = id;
item.innerHTML = `
<div class="trace-item-head">
<span class="trace-item-name running">
<span class="trace-spinner"></span>${escapeHtml(name)}
</span>
<span class="trace-item-status running">running…</span>
</div>
<div class="trace-item-in">${escapeHtml(JSON.stringify(input))}</div>
`;
els.traceList.appendChild(item);
els.traceSub.textContent = "— running —";
els.traceSub.classList.add("live");
state.activeTools[id] = item;
els.traceList.scrollTop = els.traceList.scrollHeight;
}
 
function completeTraceEntry(id, name, success, text) {
const item = state.activeTools[id] || els.traceList.querySelector(`[data-tool-id="${id}"]`);
if (!item) return;
const cls = success ? "ok" : "error";
const status = success ? "✓ ok" : "✗ error";
item.innerHTML = `
<div class="trace-item-head">
<span class="trace-item-name ${cls}">${escapeHtml(name)}</span>
<span class="trace-item-status">${status}</span>
</div>
<div class="trace-item-in">${escapeHtml(item.querySelector(".trace-item-in")?.textContent || "")}</div>
<div class="trace-item-out">${escapeHtml(text || "")}</div>
`;
delete state.activeTools[id];
// If no more running, drop the "live" label.
if (Object.keys(state.activeTools).length === 0) {
els.traceSub.textContent = "— idle —";
els.traceSub.classList.remove("live");
}
}
 
// --- packet table rendering ------------------------------------------------
 
function renderTable(tableData) {
state.currentTable = tableData;
if (!tableData || !tableData.rows || tableData.rows.length === 0) {
els.tableHost.innerHTML = '<div class="empty">no rows.</div>';
els.tableSub.textContent = tableData ? `— ${tableData.title} —` : "— last filter result —";
return;
}
const cols = tableData.columns;
const tplCols = cols.map((c) => c.width || "1fr").join(" ");
 
let html = '<div class="pkt-table">';
html += `<div class="pkt-thead" style="grid-template-columns: ${tplCols};">`;
for (const c of cols) {
html += `<span class="cell">${escapeHtml(c.label)}</span>`;
}
html += "</div>";
 
for (const row of tableData.rows) {
const frame = row.frame || "";
const sel = (state.selectedPacket && String(state.selectedPacket) === String(frame))
? " selected" : "";
html += `<div class="pkt-row${sel}" data-frame="${escapeHtml(frame)}" style="grid-template-columns: ${tplCols};">`;
cols.forEach((c, i) => {
const cellClass = (c.key === "frame") ? "cell num"
: (c.key === "info") ? "cell info"
: "cell";
html += `<span class="${cellClass}">${escapeHtml(row[c.key] || "")}</span>`;
});
html += "</div>";
}
html += "</div>";
els.tableHost.innerHTML = html;
 
const subBits = [tableData.title];
if (tableData.total_matched != null) {
subBits.push(
`${tableData.rows.length}${tableData.truncated ? `/${tableData.total_matched}` : ""} row${tableData.rows.length === 1 ? "" : "s"}`
);
}
els.tableSub.textContent = `— ${subBits.join(" · ")} —`;
}
 
// --- packet detail tree rendering -----------------------------------------
 
function renderTree(treeNodes, packetNumber) {
if (!treeNodes || treeNodes.length === 0) {
els.detailHost.innerHTML = '<div class="empty">no detail available.</div>';
els.detailSub.textContent = "— click a frame to inspect —";
return;
}
els.detailHost.innerHTML = treeNodes.map((n) => renderTreeNode(n, 0)).join("");
els.detailSub.textContent = `— frame ${packetNumber} · ${treeNodes.length} layer${treeNodes.length === 1 ? "" : "s"} —`;
}
 
function renderTreeNode(node, depth) {
const leaf = !node.children || node.children.length === 0;
// Top-level nodes (Frame, Ethernet II, IPv4, TCP, etc.) start expanded.
// Deeper nodes start collapsed to keep things tidy.
const collapsed = !leaf && depth >= 1 ? "collapsed" : "";
const disclose = leaf ? "·" : (collapsed ? "▸" : "▾");
let html = `<div class="tree-node ${leaf ? "leaf" : ""} ${collapsed}">`;
html += `<div class="tree-node-row">`;
html += `<span class="tree-disclose">${disclose}</span>`;
html += `<span class="tree-text">${formatTreeLine(node.text)}</span>`;
html += `</div>`;
if (!leaf) {
html += `<div class="tree-children">`;
html += node.children.map((c) => renderTreeNode(c, depth + 1)).join("");
html += `</div>`;
}
html += `</div>`;
return html;
}
 
function formatTreeLine(text) {
// Highlight "key: value" lines with two-tone coloring.
const escaped = escapeHtml(text);
const m = escaped.match(/^([^:=]+?):\s*(.+)$/);
if (m) {
return `<span class="key">${m[1]}:</span> <span class="val">${m[2]}</span>`;
}
return escaped;
}
 
// --- selection (used by frame-ref clicks AND table row clicks) ------------
 
async function selectPacket(frameNumber) {
if (!state.sessionId || !frameNumber) return;
state.selectedPacket = frameNumber;
 
// Update selection state in the current table.
els.tableHost.querySelectorAll(".pkt-row").forEach((r) => {
r.classList.toggle("selected", r.dataset.frame === String(frameNumber));
});
 
// Update selection state in frame-refs throughout chat.
els.chatLog.querySelectorAll(".frame-ref").forEach((r) => {
r.classList.toggle("active", r.dataset.frame === String(frameNumber));
});
 
els.detailSub.textContent = `— loading frame ${frameNumber}… —`;
els.detailHost.innerHTML = '<div class="empty">fetching dissection…</div>';
 
try {
const resp = await fetch(`/api/packet/${state.sessionId}/${frameNumber}`);
if (!resp.ok) {
const j = await resp.json().catch(() => ({}));
throw new Error(j.detail || `HTTP ${resp.status}`);
}
const data = await resp.json();
renderTree(data.tree, data.packet_number);
} catch (err) {
els.detailHost.innerHTML = `<div class="empty">error: ${escapeHtml(err.message)}</div>`;
}
}
 
// --- event delegation -----------------------------------------------------
 
els.chatLog.addEventListener("click", (e) => {
const ref = e.target.closest(".frame-ref");
if (ref) {
const n = parseInt(ref.dataset.frame, 10);
if (n > 0) selectPacket(n);
}
});
 
els.tableHost.addEventListener("click", (e) => {
const row = e.target.closest(".pkt-row");
if (row) {
const n = parseInt(row.dataset.frame, 10);
if (n > 0) selectPacket(n);
}
});
 
els.detailHost.addEventListener("click", (e) => {
const row = e.target.closest(".tree-node-row");
if (row) {
const node = row.closest(".tree-node");
if (node && !node.classList.contains("leaf")) {
node.classList.toggle("collapsed");
// Update disclosure marker.
const disc = node.querySelector(":scope > .tree-node-row > .tree-disclose");
if (disc) disc.textContent = node.classList.contains("collapsed") ? "▸" : "▾";
}
}
});
 
// --- upload ---------------------------------------------------------------
 
els.fileInput.addEventListener("change", async (e) => {
const file = e.target.files[0];
if (!file) return;
setStatus("working", `uploading ${file.name}…`);
els.captureInfo.textContent = `uploading ${file.name}…`;
 
const fd = new FormData();
fd.append("file", file);
try {
const resp = await fetch("/api/upload", { method: "POST", body: fd });
if (!resp.ok) {
const j = await resp.json().catch(() => ({}));
throw new Error(j.detail || `HTTP ${resp.status}`);
}
const data = await resp.json();
state.sessionId = data.session_id;
state.filename = data.filename;
els.captureInfo.textContent = `${data.filename} · ${fmtBytes(data.size_bytes)}`;
els.captureInfo.classList.add("has-file");
els.captureLabel.textContent = `${data.filename} · ${fmtBytes(data.size_bytes)}`;
els.captureLabel.classList.add("has-file");
setStatus("ready", "capture loaded");
appendStaticMessage(
"system",
`Capture loaded: ${data.filename}\n\nInitial summary:\n${data.summary}`,
{ label: "system" }
);
setBusy(false);
els.message.focus();
} catch (err) {
setStatus("error", err.message);
els.captureInfo.textContent = "upload failed";
els.captureInfo.classList.remove("has-file");
appendStaticMessage("error", err.message, { label: "upload error" });
}
});
 
// --- reset ---------------------------------------------------------------
 
els.resetBtn.addEventListener("click", async () => {
if (state.sessionId) {
try { await fetch(`/api/session/${state.sessionId}`, { method: "DELETE" }); } catch {}
}
state.sessionId = null;
state.filename = null;
state.selectedPacket = null;
state.currentTable = null;
els.captureInfo.textContent = "no file";
els.captureInfo.classList.remove("has-file");
els.captureLabel.textContent = "/ packet forensics by conversation";
els.captureLabel.classList.remove("has-file");
els.chatLog.innerHTML = `
<div class="hint">
<p>upload a pcap, then ask things like:</p>
<ul>
<li>"give me an overview of this capture"</li>
<li>"list all dns queries and flag anything suspicious"</li>
<li>"are there any cleartext credentials in here?"</li>
<li>"who is the top talker and what protocols are they using?"</li>
</ul>
</div>`;
els.traceList.innerHTML = '<div class="empty">no activity yet.</div>';
els.tableHost.innerHTML = '<div class="empty">no filter run yet.</div>';
els.detailHost.innerHTML = '<div class="empty">no packet selected.</div>';
els.tableSub.textContent = "— last filter result —";
els.detailSub.textContent = "— click a frame to inspect —";
els.traceSub.textContent = "— live —";
els.traceSub.classList.remove("live");
setStatus("idle", "no capture loaded");
setBusy(false);
els.fileInput.value = "";
});
 
// --- SSE chat stream -----------------------------------------------------
 
async function* parseSSE(response) {
const reader = response.body.getReader();
const decoder = new TextDecoder();
let buffer = "";
while (true) {
const { value, done } = await reader.read();
if (done) {
if (buffer.trim()) {
const parsed = parseSSEBlock(buffer);
if (parsed) yield parsed;
}
break;
}
buffer += decoder.decode(value, { stream: true });
let idx;
while ((idx = buffer.indexOf("\n\n")) !== -1) {
const block = buffer.slice(0, idx);
buffer = buffer.slice(idx + 2);
const parsed = parseSSEBlock(block);
if (parsed) yield parsed;
}
}
}
 
function parseSSEBlock(block) {
let event = "message";
const dataLines = [];
for (const line of block.split("\n")) {
if (line.startsWith("event:")) event = line.slice(6).trim();
else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
}
if (!dataLines.length) return null;
let data;
try { data = JSON.parse(dataLines.join("\n")); }
catch { data = {}; }
return { event, data };
}
 
async function sendMessage(text) {
if (!state.sessionId || state.busy) return;
appendStaticMessage("user", text);
setBusy(true);
setStatus("working", "thinking…");
 
let response;
try {
response = await fetch("/api/chat-stream", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({
session_id: state.sessionId,
message: text,
provider: els.provider.value,
model: els.model.value || null,
}),
});
if (!response.ok) {
let detail = `HTTP ${response.status}`;
try { detail = (await response.json()).detail || detail; } catch {}
throw new Error(detail);
}
} catch (err) {
setStatus("error", err.message);
appendStaticMessage("error", err.message, { label: "error" });
setBusy(false);
return;
}
 
try {
for await (const { event, data } of parseSSE(response)) {
handleStreamEvent(event, data);
}
} catch (err) {
appendStaticMessage("error", err.message, { label: "stream error" });
setStatus("error", err.message);
} finally {
finalizeStreamingMessage();
setBusy(false);
if (els.statusDot.dataset.state !== "error") {
setStatus("ready", "ready");
}
}
}
 
function handleStreamEvent(event, data) {
switch (event) {
case "text":
appendStreamingChunk(data.chunk || "");
break;
case "tool_start":
addTraceStart(data.id, data.name, data.input);
break;
case "tool_end":
completeTraceEntry(data.id, data.name, data.success, data.text);
if (data.table) renderTable(data.table);
if (data.detail) {
state.selectedPacket = data.detail.packet_number;
renderTree(data.detail.tree, data.detail.packet_number);
}
break;
case "turn_end":
// Model finished a turn but more turns may follow. Close the current
// streaming bubble so the next text starts a new bubble.
finalizeStreamingMessage();
break;
case "truncated":
appendStaticMessage(
"system",
"Investigation truncated: hit the maximum number of agent turns.",
{ label: "system" }
);
break;
case "error":
appendStaticMessage("error", data.message || "stream error", { label: "error" });
setStatus("error", data.message || "error");
break;
case "done":
// Stream is closing cleanly.
break;
default:
// Unknown event — ignore.
break;
}
}
 
els.composer.addEventListener("submit", (e) => {
e.preventDefault();
const text = els.message.value.trim();
if (!text) return;
els.message.value = "";
sendMessage(text);
});
 
els.message.addEventListener("keydown", (e) => {
if (e.key === "Enter" && !e.shiftKey) {
e.preventDefault();
els.composer.requestSubmit();
}
});
 
// --- init ----------------------------------------------------------------
 
(async function init() {
try {
const resp = await fetch("/api/health");
const data = await resp.json();
const available = new Set(data.providers || []);
for (const opt of els.provider.options) {
if (!available.has(opt.value)) {
opt.disabled = true;
opt.text += " (not configured)";
}
}
const firstEnabled = [...els.provider.options].find((o) => !o.disabled);
if (firstEnabled) els.provider.value = firstEnabled.value;
setStatus("idle", "ready to upload");
} catch {
setStatus("error", "backend unreachable");
}
})();
 
