export default function ResultsTable({ data }) {
  if (!data.length) return <p>No scan results yet.</p>;

  return (
    <table border="1">
      <thead>
        <tr>
          <th>File Name</th>
          <th>Entropy</th>
          <th>Status</th>
          <th>Action Taken</th>
        </tr>
      </thead>
      <tbody>
        {data.map((item, idx) => (
          <tr key={idx}>
            <td>{item.file}</td>
            <td>{item.entropy}</td>
            <td>{item.status}</td>
            <td>{item.action}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
