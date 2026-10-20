const API_BASE = import.meta.env.VITE_API_BASE || "";

function formatDetail(detail) {
  if (Array.isArray(detail)) {
    return detail
      .map((item) => item.detail || item.msg || JSON.stringify(item))
      .join("; ");
  }
  if (detail && typeof detail === "object") {
    return detail.detail || JSON.stringify(detail);
  }
  return detail || "";
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    const message =
      formatDetail(payload?.detail) || `Request failed with status ${response.status}`;
    throw new Error(message);
  }

  return payload;
}

export function getHealth() {
  return request("/api/health");
}

export function listAnalyses() {
  return request("/api/analyses");
}

export function getAnalysis(id) {
  return request(`/api/analyses/${id}`);
}

export async function analyzeFiles(files) {
  const form = new FormData();
  for (const file of files) {
    form.append("files", file);
  }
  return request("/api/analyses", { method: "POST", body: form });
}
