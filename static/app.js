const form = document.querySelector("#analyze-form");
const fileInput = document.querySelector("#files");
const statusText = document.querySelector("#status");
const resultsBody = document.querySelector("#results-body");
const submitButton = form.querySelector("button");
const selectedCount = document.querySelector("#selected-count");
const selectedFilesList = document.querySelector("#selected-files");
const clearFilesButton = document.querySelector("#clear-files");
const copyResultsButton = document.querySelector("#copy-results");
const downloadResultsButton = document.querySelector("#download-results");
let selectedFiles = [];
let latestResults = [];

function stringify(value) {
  if (value === null || value === undefined) {
    return "none";
  }
  if (Array.isArray(value)) {
    return value.length ? value.join("\n") : "none";
  }
  if (typeof value === "object") {
    return Object.keys(value).length ? JSON.stringify(value, null, 2) : "none";
  }
  return String(value);
}

function cell(text, usePre = false) {
  const td = document.createElement("td");
  if (usePre) {
    const pre = document.createElement("pre");
    pre.textContent = stringify(text);
    td.appendChild(pre);
  } else {
    td.textContent = stringify(text);
  }
  return td;
}

function fileKey(file) {
  return `${file.name}:${file.size}:${file.lastModified}`;
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderSelectedFiles() {
  selectedFilesList.textContent = "";
  selectedCount.textContent = selectedFiles.length
    ? `${selectedFiles.length} file${selectedFiles.length === 1 ? "" : "s"} selected`
    : "No files selected";
  clearFilesButton.hidden = selectedFiles.length === 0;

  for (const [index, file] of selectedFiles.entries()) {
    const item = document.createElement("li");

    const details = document.createElement("span");
    details.className = "selected-file-name";
    details.textContent = `${file.name} (${formatBytes(file.size)})`;

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-file";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      selectedFiles.splice(index, 1);
      renderSelectedFiles();
    });

    item.appendChild(details);
    item.appendChild(remove);
    selectedFilesList.appendChild(item);
  }
}

function typeColorClass(result) {
  const detected = result.detected_type || "unknown";
  const family = result.detected_family || detected;
  if (detected.startsWith("corrupt_")) {
    return "type-corrupt";
  }
  if (["pdf", "ps", "eps"].includes(detected)) {
    return "type-document";
  }
  if (["doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "ppsx", "ole", "rtf", "pub"].includes(detected)) {
    return "type-office";
  }
  if (["zip", "rar", "7z", "tar", "gz", "bz2", "jar", "apk", "app"].includes(detected) || family === "zip") {
    return "type-archive";
  }
  if (["exe", "dll", "scr", "pe", "lnk", "msi", "msp"].includes(detected) || family === "pe") {
    return "type-executable";
  }
  if (["js", "vbs", "vb", "bat", "ps1", "py", "sh", "rb", "java", "php", "sql", "sct", "wsf", "wsh", "hkcu"].includes(detected)) {
    return "type-script";
  }
  if (["html", "xml", "mhtml", "eml", "svg"].includes(detected)) {
    return "type-markup";
  }
  if (detected === "text") {
    return "type-text";
  }
  if (["gif", "png", "jpg", "jpeg", "bmp"].includes(detected)) {
    return "type-image";
  }
  if (["mp3", "wav", "mp4", "avi", "mov", "swf"].includes(detected)) {
    return "type-media";
  }
  if (["db", "class", "iso", "chm"].includes(detected)) {
    return "type-data";
  }
  return "type-unknown";
}

function renderResults(results) {
  latestResults = results;
  copyResultsButton.disabled = results.length === 0;
  downloadResultsButton.disabled = results.length === 0;
  resultsBody.textContent = "";
  if (!results.length) {
    const row = document.createElement("tr");
    const empty = cell("No results returned.");
    empty.colSpan = 9;
    empty.className = "empty";
    row.appendChild(empty);
    resultsBody.appendChild(row);
    return;
  }

  for (const result of results) {
    const row = document.createElement("tr");
    row.appendChild(cell(result.uploaded_filename || result.path));

    const typeCell = document.createElement("td");
    typeCell.className = "type-cell";
    const type = document.createElement("span");
    type.className = `type ${typeColorClass(result)}`;
    type.textContent = result.detected_type || "unknown";
    typeCell.appendChild(type);
    row.appendChild(typeCell);

    row.appendChild(cell(result.description));
    row.appendChild(cell(result.size === null || result.size === undefined ? "none" : `${result.size} bytes`));
    row.appendChild(cell(result.extension ? `.${result.extension}` : "none"));
    row.appendChild(cell(`exact: ${result.extension_matches}\ncompatible: ${result.extension_compatible}`, true));
    row.appendChild(cell(result.notes, true));
    row.appendChild(cell(result.indicators, true));
    row.appendChild(cell(result.errors, true));
    resultsBody.appendChild(row);
  }
}

function resultsAsJson() {
  return JSON.stringify({ results: latestResults }, null, 2);
}

copyResultsButton.addEventListener("click", async () => {
  if (!latestResults.length) {
    return;
  }
  try {
    await navigator.clipboard.writeText(resultsAsJson());
    statusText.textContent = "Results JSON copied.";
  } catch (error) {
    statusText.textContent = `Copy failed: ${error}`;
  }
});

downloadResultsButton.addEventListener("click", () => {
  if (!latestResults.length) {
    return;
  }
  const blob = new Blob([resultsAsJson()], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  link.href = url;
  link.download = `file-analysis-results-${timestamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  statusText.textContent = "Results JSON downloaded.";
});

fileInput.addEventListener("change", () => {
  const existing = new Set(selectedFiles.map(fileKey));
  for (const file of fileInput.files) {
    const key = fileKey(file);
    if (!existing.has(key)) {
      selectedFiles.push(file);
      existing.add(key);
    }
  }
  fileInput.value = "";
  renderSelectedFiles();
});

clearFilesButton.addEventListener("click", () => {
  selectedFiles = [];
  fileInput.value = "";
  renderSelectedFiles();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedFiles.length) {
    statusText.textContent = "Choose at least one file.";
    return;
  }

  const data = new FormData();
  for (const file of selectedFiles) {
    data.append("files", file);
  }

  submitButton.disabled = true;
  statusText.textContent = "Analyzing files...";

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      body: data,
    });
    const payload = await response.json();
    renderResults(payload.results || []);
    statusText.textContent = response.ok ? "Analysis complete." : payload.error || "Analysis completed with errors.";
  } catch (error) {
    statusText.textContent = `Request failed: ${error}`;
  } finally {
    submitButton.disabled = false;
  }
});

renderSelectedFiles();
