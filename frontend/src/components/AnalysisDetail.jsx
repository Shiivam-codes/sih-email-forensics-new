import Badge from "./Badge";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDelay(value) {
  if (value === null || value === undefined) return "—";
  if (value < 0) return `${value}s`;
  if (value < 60) return `${value}s`;
  return `${Math.round(value / 60)}m ${value % 60}s`;
}

function resultTone(result) {
  const value = (result || "").toLowerCase();
  if (value === "pass") return "is-pass";
  if (["fail", "softfail", "permerror"].includes(value)) return "is-fail";
  if (["none", "neutral", "temperror"].includes(value)) return "is-unknown";
  return "is-partial";
}

function addressLine(value) {
  if (!value?.address) return "—";
  return value.name ? `${value.name} <${value.address}>` : value.address;
}

function alignmentLabel(value) {
  if (value === true) return "aligned";
  if (value === false) return "misaligned";
  return "unknown";
}

function Stat({ label, value, hint, tone }) {
  return (
    <div className={`stat-card ${tone || ""}`}>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
      {hint && <span className="muted small">{hint}</span>}
    </div>
  );
}

function Section({ eyebrow, title, children, actions }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export default function AnalysisDetail({ analysis, onBack }) {
  if (!analysis) return null;

  const { email, auth, routing, evidence, iocs, warnings } = analysis;
  const authRows = [
    { mechanism: "SPF", ...auth.spf },
    ...auth.dkim.map((row, index) => ({
      mechanism: auth.dkim.length > 1 ? `DKIM #${index + 1}` : "DKIM",
      ...row,
    })),
    { mechanism: "DMARC", ...auth.dmarc },
  ];

  return (
    <div className="detail">
      <button type="button" className="back-button" onClick={onBack}>
        ← Back to case queue
      </button>

      <header className="detail-header">
        <div>
          <p className="eyebrow">Forensic analysis</p>
          <h1>{email.subject || "(no subject)"}</h1>
          <p className="muted mono small">
            {evidence.filename} · SHA-256 {evidence.sha256.slice(0, 16)}…
          </p>
        </div>
        <div className="detail-header-badges">
          <Badge value={auth.verdict} label={`Auth: ${auth.verdict}`} />
          <Badge
            value={routing.origin_ip ? "partial" : "unknown"}
            label={routing.origin_ip ? "Origin located" : "Origin undetermined"}
          />
        </div>
      </header>

      <div className="stat-grid">
        <Stat
          label="Sender domain"
          value={email.sender.domain || "unknown"}
          hint={email.sender.address || "no From address"}
          tone={auth.verdict === "fail" ? "is-risk" : ""}
        />
        <Stat
          label="Probable origin"
          value={routing.origin_ip || "undetermined"}
          hint={`${Math.round(routing.origin_confidence * 100)}% confidence · ${routing.origin_method}`}
        />
        <Stat
          label="Relay hops"
          value={routing.hops.length}
          hint={`${routing.public_ip_count} public IP${routing.public_ip_count === 1 ? "" : "s"}`}
        />
        <Stat
          label="Indicators"
          value={iocs.length}
          hint={`${email.attachments.length} attachment${email.attachments.length === 1 ? "" : "s"}`}
        />
      </div>

      {warnings.length > 0 && (
        <div className="alert alert-warn">
          <strong>Analysis warnings:</strong> {warnings.join(" · ")}
        </div>
      )}

      <Section eyebrow="Identity" title="Sender and message metadata">
        <div className="kv-grid">
          <div>
            <span className="kv-label">From</span>
            <span>{addressLine(email.sender)}</span>
          </div>
          <div>
            <span className="kv-label">Reply-To</span>
            <span>{addressLine(email.reply_to)}</span>
          </div>
          <div>
            <span className="kv-label">Return-Path</span>
            <span>{addressLine(email.return_path)}</span>
          </div>
          <div>
            <span className="kv-label">Date</span>
            <span>{formatDate(email.date)}</span>
          </div>
          <div>
            <span className="kv-label">Message-ID</span>
            <span className="mono small">{email.message_id || "—"}</span>
          </div>
          <div>
            <span className="kv-label">Recipients</span>
            <span className="small">
              {email.to.length ? email.to.map((item) => item.address).join(", ") : "—"}
            </span>
          </div>
        </div>
      </Section>

      <Section
        eyebrow="Authentication"
        title="SPF, DKIM, and DMARC evidence"
        actions={<Badge value={auth.verdict} />}
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Mechanism</th>
                <th>Result</th>
                <th>Domain</th>
                <th>Source</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {authRows.map((row, index) => (
                <tr key={`${row.mechanism}-${index}`}>
                  <td className="strong">{row.mechanism}</td>
                  <td>
                    <Badge
                      value={row.result}
                      label={row.result}
                      tone={resultTone(row.result)}
                    />
                  </td>
                  <td className="mono small">{row.domain || "—"}</td>
                  <td className="small">{row.source || "—"}</td>
                  <td className="small muted">
                    {row.client_ip ? `client-ip ${row.client_ip} · ` : ""}
                    {row.detail || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="alignment-grid">
          <div>
            <span className="kv-label">From domain</span>
            <span className="mono small">{auth.alignment.from_domain || "—"}</span>
          </div>
          <div>
            <span className="kv-label">SPF alignment</span>
            <Badge
              value={alignmentLabel(auth.alignment.spf_aligned)}
              tone={auth.alignment.spf_aligned ? "is-pass" : "is-partial"}
            />
          </div>
          <div>
            <span className="kv-label">DKIM alignment</span>
            <Badge
              value={alignmentLabel(auth.alignment.dkim_aligned)}
              tone={auth.alignment.dkim_aligned ? "is-pass" : "is-partial"}
            />
          </div>
          <div>
            <span className="kv-label">Reply-To mismatch</span>
            <Badge
              value={auth.alignment.reply_to_mismatch ? "flagged" : "none"}
              tone={auth.alignment.reply_to_mismatch ? "is-partial" : "is-pass"}
            />
          </div>
        </div>

        {auth.notes?.length > 0 && (
          <ul className="note-list">
            {auth.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        eyebrow="Transmission"
        title="Reconstructed relay path"
        actions={
          <span className="muted small">Earliest hop first · {routing.origin_method}</span>
        }
      >
        {routing.anomalies.length > 0 && (
          <div className="chips">
            {routing.anomalies.map((anomaly) => (
              <span className="chip" key={anomaly}>
                {anomaly.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        )}

        {routing.hops.length === 0 ? (
          <p className="empty-state">No Received headers were available to reconstruct a path.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="numeric">Hop</th>
                  <th>From</th>
                  <th>By</th>
                  <th>IP</th>
                  <th>Timestamp</th>
                  <th>Delay</th>
                </tr>
              </thead>
              <tbody>
                {routing.hops.map((hop, index) => (
                  <tr
                    key={`${hop.index}-${hop.raw.slice(0, 24)}`}
                    className={hop.ip === routing.origin_ip ? "origin-row" : ""}
                  >
                    <td className="numeric">{index + 1}</td>
                    <td className="mono small">{hop.from_host || "—"}</td>
                    <td className="mono small">{hop.by_host || "—"}</td>
                    <td className="mono small">
                      {hop.ip || "—"}
                      {hop.ip === routing.origin_ip && (
                        <span className="inline-tag">origin</span>
                      )}
                    </td>
                    <td className="small">{formatDate(hop.timestamp)}</td>
                    <td className="numeric small">{formatDelay(hop.delay_seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section eyebrow="Indicators" title="Extracted indicators of compromise">
        {iocs.length === 0 ? (
          <p className="empty-state">No indicators were extracted.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Context</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={`${ioc.type}-${ioc.value}`}>
                    <td>
                      <span className="type-tag">{ioc.type}</span>
                    </td>
                    <td className="mono small break-all">{ioc.value}</td>
                    <td className="small muted">{ioc.context}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section eyebrow="Content" title="Body excerpt">
        {email.body_excerpt ? (
          <pre className="body-preview">{email.body_excerpt}</pre>
        ) : (
          <p className="empty-state">No plain-text body could be extracted.</p>
        )}
        {email.attachments.length > 0 && (
          <div className="attachments">
            <h3>Attachments</h3>
            <ul>
              {email.attachments.map((attachment) => (
                <li key={attachment.sha256}>
                  <span className="strong">{attachment.filename}</span>
                  <span className="muted small">
                    {attachment.content_type} · {formatBytes(attachment.size_bytes)}
                  </span>
                  <span className="mono tiny break-all">{attachment.sha256}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Section>

      <Section eyebrow="Evidence" title="Raw headers">
        <details className="raw-headers">
          <summary>Show original header block</summary>
          <pre>{email.headers_excerpt}</pre>
        </details>
        <div className="evidence-grid">
          <div>
            <span className="kv-label">SHA-256</span>
            <span className="mono tiny break-all">{evidence.sha256}</span>
          </div>
          <div>
            <span className="kv-label">File size</span>
            <span>{formatBytes(evidence.size_bytes)}</span>
          </div>
          <div>
            <span className="kv-label">Analyzed at</span>
            <span>{formatDate(evidence.analyzed_at)}</span>
          </div>
          <div>
            <span className="kv-label">Tool version</span>
            <span className="mono small">{evidence.tool_version}</span>
          </div>
        </div>
      </Section>
    </div>
  );
}
