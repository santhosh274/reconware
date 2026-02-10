export default function RiskBar({ results }) {
  if (!results.length) return null;

  const ransomwareCount = results.filter(
    (r) => r.status === "Ransomware"
  ).length;

  const score = Math.min(100, ransomwareCount * 25);

  return (
    <div style={{ margin: "20px 0" }}>
      <strong>System Risk Score: {score}%</strong>
      <div
        style={{
          width: "300px",
          height: "20px",
          border: "1px solid black",
          marginTop: "5px",
        }}
      >
        <div
          style={{
            width: `${score}%`,
            height: "100%",
            backgroundColor: score > 50 ? "red" : "orange",
          }}
        />
      </div>
    </div>
  );
}
