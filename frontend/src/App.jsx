import { useCallback, useEffect, useState } from "react";
import { getAnalysis, getHealth, listAnalyses } from "./api";
import AnalysisDetail from "./components/AnalysisDetail";
import AnalysisList from "./components/AnalysisList";
import UploadPanel from "./components/UploadPanel";

export default function App() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [selected, setSelected] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [health, setHealth] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setListError("");
    try {
      setAnalyses(await listAnalyses());
    } catch (err) {
      setListError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: "offline" }));
  }, [refresh]);

  async function openAnalysis(id) {
    setDetailLoading(true);
    setDetailError("");
    try {
      setSelected(await getAnalysis(id));
    } catch (err) {
      setDetailError(err.message);
    } finally {
      setDetailLoading(false);
    }
  }

  function handleUploaded(results) {
    refresh();
    if (results.length > 0) {
      setSelected(results[0]);
    }
  }

  const highRisk = analyses.filter((item) => item.verdict === "fail").length;
  const unresolved = analyses.filter((item) => !item.origin_ip).length;
  const online = health?.status === "ok";

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">EF</span>
          <div>
            <strong>Email Forensics</strong>
            <span className="brand-sub">Threat detection · origin tracing</span>
          </div>
        </div>
        <div className="header-status">
          <span className={`status-dot ${online ? "is-online" : "is-offline"}`} />
          <span className="small">{online ? "Backend connected" : "Backend offline"}</span>
          {health?.version && <span className="version-tag">v{health.version}</span>}
        </div>
      </header>

      <main className="container">
        {selected ? (
          <>
            {detailLoading && <p className="empty-state">Loading analysis...</p>}
            {detailError && <p className="alert alert-error">{detailError}</p>}
            <AnalysisDetail analysis={selected} onBack={() => setSelected(null)} />
          </>
        ) : (
          <>
            <section className="hero">
              <div>
                <p className="eyebrow">Forensic workspace</p>
                <h1>Trace the email. Verify the sender. Preserve the evidence.</h1>
                <p className="hero-copy">
                  Upload raw email files to reconstruct the relay path, validate SPF, DKIM, and
                  DMARC, extract indicators, and estimate probable origin. Every result keeps a
                  hash of the original evidence.
                </p>
              </div>
              <div className="hero-stats">
                <div>
                  <strong>{analyses.length}</strong>
                  <span>emails analyzed</span>
                </div>
                <div>
                  <strong>{highRisk}</strong>
                  <span>auth failures</span>
                </div>
                <div>
                  <strong>{unresolved}</strong>
                  <span>origin undetermined</span>
                </div>
              </div>
            </section>

            <UploadPanel onUploaded={handleUploaded} />

            {listError && <p className="alert alert-error">{listError}</p>}

            <AnalysisList
              analyses={analyses}
              loading={loading}
              onSelect={openAnalysis}
              onRefresh={refresh}
            />

            <footer className="footer">
              <span>Phase 1 · Parsing, authentication evidence, relay tracing, IOC extraction</span>
              <span className="muted">Geolocation and scoring arrive in the next phase</span>
            </footer>
          </>
        )}
      </main>
    </div>
  );
}
