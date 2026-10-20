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

function formatAge(days) {
  if (days === null || days === undefined) return "—";
  if (days < 1) return "today";
  if (days < 30) return `${days}d`;
  if (days < 365) return `${Math.round(days / 30)}mo`;
  const years = (days / 365).toFixed(1);
  return `${years}y`;
}

function formatLocation(intel) {
  if (!intel || intel.scope !== "public") {
    return `${intel?.scope || "unknown"} · lookup skipped`;
  }
  return [intel.city, intel.region, intel.country].filter(Boolean).join(", ") || "—";
}

const SIGNAL_LABELS = {
  auth: "Authentication",
  domain: "Domain",
  ip: "IP reputation",
  content: "Content",
  header: "Header",
};

function scoreLabel(value) {
  return (value || "unscored").replaceAll("_", " ");
}

function scoreTone(value) {
  if (value === "malicious") return "is-fail";
  if (value === "suspicious") return "is-partial";
  if (value === "likely_legitimate") return "is-pass";
  return "is-neutral";
}

const SOURCE_LABELS = {
  geoip: "GeoIP",
  internetdb: "InternetDB",
  tor_exit_list: "Tor exits",
  dns: "DNS",
  rdap: "RDAP",
  lookalike: "Lookalike",
  url_passive: "URL heuristics",
};

function sourceTone(status) {
  if (status === "ok" || status === "complete") return "is-pass";
  if (status === "partial") return "is-partial";
  if (["unavailable", "budget_exceeded"].includes(status)) return "is-fail";
  return "is-neutral";
}

function IpFlags({ intel }) {
  const flags = [
    intel.tor && ["Tor exit", "is-risk"],
    intel.hosting && ["Hosting", "is-watch"],
    intel.vpn && ["VPN", "is-watch"],
    intel.cloud && ["Cloud", "is-info"],
  ].filter(Boolean);
  if (flags.length === 0) return <span className="muted small">—</span>;
  return (
    <span className="flag-list">
      {flags.map(([label, tone]) => (
        <span className={`flag-tag ${tone}`} key={label}>
          {label}
        </span>
      ))}
    </span>
  );
}

function DnsFlags({ intel }) {
  const flags = [
    intel.spf && ["SPF", "is-pass"],
    !intel.spf && intel.sources.includes("dns") && ["No SPF", "is-watch"],
    intel.dmarc && ["DMARC", "is-pass"],
    !intel.dmarc && intel.sources.includes("dns") && ["No DMARC", "is-watch"],
    intel.lookalike_of && [`Lookalike · ${intel.lookalike_of}`, "is-risk"],
  ].filter(Boolean);
  if (flags.length === 0) return <span className="muted small">—</span>;
  return (
    <span className="flag-list">
      {flags.map(([label, tone]) => (
        <span className={`flag-tag ${tone}`} key={label}>
          {label}
        </span>
      ))}
    </span>
  );
}

function UrlFlags({ intel }) {
  const flags = [
    intel.ip_literal && ["IP literal", "is-risk"],
    intel.punycode && ["Punycode", "is-watch"],
    intel.userinfo && ["Userinfo", "is-risk"],
    intel.shortened && ["Shortener", "is-watch"],
    intel.suspicious_tld && ["High-risk TLD", "is-watch"],
    intel.lookalike_of && [`Lookalike · ${intel.lookalike_of}`, "is-risk"],
    !intel.https && ["No HTTPS", "is-watch"],
  ].filter(Boolean);
  if (flags.length === 0) return <span className="muted small">—</span>;
  return (
    <span className="flag-list">
      {flags.map(([label, tone]) => (
        <span className={`flag-tag ${tone}`} key={label}>
          {label}
        </span>
      ))}
    </span>
  );
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

  const { email, auth, routing, evidence, enrichment, score, iocs, warnings } = analysis;
  const ipRows = Object.values(enrichment?.ip || {});
  const domainRows = Object.values(enrichment?.domain || {});
  const urlRows = Object.values(enrichment?.url || {});
  const sourceRows = Object.values(enrichment?.sources || {});
  const originIntel = enrichment?.ip?.[routing.origin_ip];
  const originHint =
    originIntel?.scope === "public" && (originIntel.city || originIntel.country)
      ? `${[originIntel.city, originIntel.country].filter(Boolean).join(", ")} · ${
          Math.round(routing.origin_confidence * 100)
        }% confidence`
      : `${Math.round(routing.origin_confidence * 100)}% confidence · ${routing.origin_method}`;
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
          <Badge
            value={score?.label}
            label={`Risk: ${scoreLabel(score?.label)}`}
          />
          <Badge value={auth.verdict} label={`Auth: ${auth.verdict}`} />
          <Badge
            value={routing.origin_ip ? "partial" : "unknown"}
            label={routing.origin_ip ? "Origin located" : "Origin undetermined"}
          />
          {enrichment?.offline_mode && (
            <Badge value="offline" label="Offline enrichment" tone="is-neutral" />
          )}
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
          hint={originHint}
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

      <Section
        eyebrow="Risk"
        title="Weighted threat assessment"
        actions={
          <Badge
            value={score?.label}
            label={`${score?.total ?? 0}/100 · ${scoreLabel(score?.label)}`}
          />
        }
      >
        {!score?.available ? (
          <p className="empty-state">
            {score?.notes?.[0] || "Scoring evidence is not available for this analysis."}
          </p>
        ) : (
          <>
            <div className="score-layout">
              <div className={`score-hero ${scoreTone(score.label)}`}>
                <span className="stat-label">Composite risk</span>
                <strong className="score-total">
                  {score.total}
                  <span>/100</span>
                </strong>
                <strong className="score-verdict">{scoreLabel(score.label)}</strong>
                <span className="muted small">
                  {Math.round(score.confidence * 100)}% confidence ·{" "}
                  {score.families_above_threshold} signal families ·{" "}
                  {Math.round(score.coverage * 100)}% coverage
                </span>
              </div>
              <div className="score-families">
                {Object.entries(score.signals).map(([family, points]) => {
                  const maximum = score.max_signals[family] || 0;
                  const percent = maximum ? Math.min(100, (points / maximum) * 100) : 0;
                  return (
                    <div className="score-row" key={family}>
                      <span className="score-row-label">
                        {SIGNAL_LABELS[family] || family}
                      </span>
                      <span className="score-bar">
                        <span
                          className={`score-fill ${
                            percent >= 70 ? "is-fail" : percent >= 30 ? "is-partial" : "is-pass"
                          }`}
                          style={{ width: `${percent}%` }}
                        />
                      </span>
                      <span className="numeric small">
                        {points}/{maximum}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
            {score.top_reasons.length > 0 && (
              <div className="score-reasons">
                <h3>Top reasons</h3>
                <ul className="note-list">
                  {score.top_reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </div>
            )}
            {score.notes?.length > 0 && (
              <ul className="note-list">
                {score.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            )}
            <p className="muted tiny">Scoring version: {score.version}</p>
          </>
        )}
      </Section>

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

      <Section
        eyebrow="Enrichment"
        title="External context and provenance"
        actions={
          <div className="section-actions">
            <span className="muted small">
              {enrichment?.cache_hits ?? 0} cache hits · {enrichment?.cache_misses ?? 0} misses
            </span>
            <Badge
              value={enrichment?.status || "not_queried"}
              label={(enrichment?.status || "not queried").replaceAll("_", " ")}
              tone={
                enrichment?.offline_mode
                  ? "is-neutral"
                  : sourceTone(enrichment?.status || "not_queried")
              }
            />
          </div>
        }
      >
        {sourceRows.length > 0 && (
          <div className="source-grid">
            {sourceRows.map((source) => (
              <div className="source-card" key={source.source}>
                <span className="source-name">
                  {SOURCE_LABELS[source.source] || source.source}
                </span>
                <Badge
                  value={source.status}
                  label={source.status.replaceAll("_", " ")}
                  tone={sourceTone(source.status)}
                />
                {source.detail && <span className="muted tiny">{source.detail}</span>}
              </div>
            ))}
          </div>
        )}

        {ipRows.length > 0 && (
          <div className="enrichment-block">
            <h3>IP intelligence</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Address</th>
                    <th>Location</th>
                    <th>ASN / network</th>
                    <th>Flags</th>
                    <th className="numeric">Ports</th>
                  </tr>
                </thead>
                <tbody>
                  {ipRows.map((row) => (
                    <tr key={row.ip} className={row.ip === routing.origin_ip ? "origin-row" : ""}>
                      <td className="mono small">
                        {row.ip}
                        {row.ip === routing.origin_ip && (
                          <span className="inline-tag">origin</span>
                        )}
                      </td>
                      <td className="small">{formatLocation(row)}</td>
                      <td className="small">
                        <span className="stacked">
                          <span>{row.asn ? `AS${row.asn}` : "—"}</span>
                          {row.as_org && <span className="muted tiny">{row.as_org}</span>}
                        </span>
                      </td>
                      <td>
                        <IpFlags intel={row} />
                      </td>
                      <td className="numeric small">
                        {row.ports.length > 0 ? row.ports.join(", ") : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {domainRows.length > 0 && (
          <div className="enrichment-block">
            <h3>Domain intelligence</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Age</th>
                    <th>Registrar</th>
                    <th>MX</th>
                    <th>Signals</th>
                  </tr>
                </thead>
                <tbody>
                  {domainRows.map((row) => (
                    <tr key={row.domain}>
                      <td className="mono small break-all">{row.domain}</td>
                      <td className="small" title={row.created_at || "registration date unavailable"}>
                        {formatAge(row.age_days)}
                      </td>
                      <td className="small">{row.registrar || "—"}</td>
                      <td className="small break-all">
                        {row.mx.length > 0 ? row.mx.join(", ") : "—"}
                      </td>
                      <td>
                        <DnsFlags intel={row} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {urlRows.length > 0 && (
          <div className="enrichment-block">
            <h3>URL intelligence</h3>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Host</th>
                    <th>Flags</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {urlRows.map((row) => (
                    <tr key={row.url}>
                      <td className="mono small break-all">{row.url}</td>
                      <td className="mono small break-all">{row.host || "—"}</td>
                      <td>
                        <UrlFlags intel={row} />
                      </td>
                      <td className="small muted">
                        {row.notes.length > 0 ? row.notes[0] : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {ipRows.length + domainRows.length + urlRows.length === 0 && (
          <p className="empty-state">No enrichment candidates were found in this message.</p>
        )}

        {enrichment?.notes?.length > 0 && (
          <ul className="note-list">
            {enrichment.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
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
