const form = document.querySelector("#analyze-form");
const fileInput = document.querySelector("#files");
const statusText = document.querySelector("#status");
const resultsBody = document.querySelector("#results-body");
const submitButton = form.querySelector("button");

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

function typeColorClass(result) {
  const detected = result.detected_type || "unknown";
  const family = result.detected_family || detected;
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!fileInput.files.length) {
    statusText.textContent = "Choose at least one file.";
    return;
  }

  const data = new FormData();
  for (const file of fileInput.files) {
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
