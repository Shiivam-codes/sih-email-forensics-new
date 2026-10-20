const TONES = {
  pass: "is-pass",
  partial: "is-partial",
  fail: "is-fail",
  unknown: "is-unknown",
  neutral: "is-neutral",
};

export default function Badge({ value, label, tone }) {
  const resolvedTone = tone || TONES[value] || "is-neutral";
  return <span className={`badge ${resolvedTone}`}>{label || value || "unknown"}</span>;
}
