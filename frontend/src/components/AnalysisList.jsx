import Badge from "./Badge";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AnalysisList({ analyses, loading, onSelect, onRefresh }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Case queue</p>
          <h2>Analyzed emails</h2>
        </div>
        <button type="button" className="button button-ghost" onClick={onRefresh}>
          Refresh
        </button>
      </div>

      {loading ? (
        <p className="empty-state">Loading analyses...</p>
      ) : analyses.length === 0 ? (
        <div className="empty-state">
          <strong>No emails analyzed yet.</strong>
          <span>Upload one or more .eml files to start a case.</span>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Auth</th>
                <th>Risk</th>
                <th className="numeric">Hops</th>
                <th className="numeric">IOCs</th>
                <th>Origin</th>
                <th>Analyzed</th>
              </tr>
            </thead>
            <tbody>
              {analyses.map((analysis) => (
                <tr key={analysis.id}>
                  <td>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => onSelect(analysis.id)}
                    >
                      {analysis.filename}
                    </button>
                  </td>
                  <td className="mono small">{analysis.sender || "—"}</td>
                  <td className="subject-cell">{analysis.subject || "—"}</td>
                  <td>
                    <Badge value={analysis.verdict} />
                  </td>
                  <td>
                    {analysis.label ? (
                      <Badge
                        value={analysis.label}
                        label={`${analysis.score ?? "—"} · ${analysis.label.replaceAll("_", " ")}`}
                      />
                    ) : (
                      <span className="muted small">—</span>
                    )}
                  </td>
                  <td className="numeric">{analysis.hop_count}</td>
                  <td className="numeric">{analysis.ioc_count}</td>
                  <td className="mono small">{analysis.origin_ip || "undetermined"}</td>
                  <td className="small">{formatDate(analysis.analyzed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
