import { useRef, useState } from "react";
import { analyzeFiles } from "../api";

const MAX_FILES = 20;

function mergeFiles(current, incoming) {
  const seen = new Set(current.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
  const merged = [...current];
  for (const file of incoming) {
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(file);
    }
  }
  return merged.slice(0, MAX_FILES);
}

export default function UploadPanel({ onUploaded }) {
  const inputRef = useRef(null);
  const [files, setFiles] = useState([]);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  function addFiles(incoming) {
    const emlFiles = Array.from(incoming).filter((file) =>
      file.name.toLowerCase().endsWith(".eml")
    );
    if (emlFiles.length === 0) {
      setError("Select one or more .eml files.");
      return;
    }
    setError("");
    setNotice("");
    setFiles((current) => mergeFiles(current, emlFiles));
  }

  function handleDrop(event) {
    event.preventDefault();
    setDragging(false);
    addFiles(event.dataTransfer.files);
  }

  function removeFile(file) {
    setFiles((current) => current.filter((item) => item !== file));
  }

  async function handleAnalyze() {
    if (files.length === 0 || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const payload = await analyzeFiles(files);
      if (payload.errors?.length) {
        setError(
          payload.errors.map((item) => `${item.filename}: ${item.detail}`).join(" · ")
        );
      }
      if (payload.results?.length) {
        setNotice(
          `${payload.results.length} email${payload.results.length === 1 ? "" : "s"} analyzed.`
        );
        setFiles([]);
        onUploaded?.(payload.results);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel upload-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Evidence intake</p>
          <h2>Analyze email files</h2>
        </div>
        <span className="muted small">.eml · max {MAX_FILES} per batch</span>
      </div>

      <div
        className={`upload-zone ${dragging ? "is-dragging" : ""}`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") inputRef.current?.click();
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".eml"
          multiple
          hidden
          onChange={(event) => addFiles(event.target.files)}
        />
        <span className="upload-icon">EML</span>
        <strong>Drop email files here</strong>
        <span className="muted">or click to browse your device</span>
      </div>

      {files.length > 0 && (
        <ul className="file-list">
          {files.map((file) => (
            <li key={`${file.name}:${file.size}:${file.lastModified}`}>
              <span className="file-name">{file.name}</span>
              <span className="muted small">{(file.size / 1024).toFixed(1)} KB</span>
              <button
                type="button"
                className="icon-button"
                onClick={() => removeFile(file)}
                aria-label={`Remove ${file.name}`}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      {error && <p className="alert alert-error">{error}</p>}
      {notice && <p className="alert alert-ok">{notice}</p>}

      <div className="upload-actions">
        <p className="muted small">
          Files stay on this machine. The original bytes are hashed, never modified.
        </p>
        <button
          type="button"
          className="button"
          onClick={handleAnalyze}
          disabled={files.length === 0 || busy}
        >
          {busy ? "Analyzing..." : `Analyze ${files.length || ""} email${files.length === 1 ? "" : "s"}`}
        </button>
      </div>
    </section>
  );
}
