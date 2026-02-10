import { useState } from "react";
import { scanFolder } from "../api/scanApi";

export default function ScanForm({ setResults }) {
  const [path, setPath] = useState("");

  const handleScan = async () => {
    if (!path) {
      alert("Please enter a folder path");
      return;
    }
    const data = await scanFolder(path);
    setResults(data);
  };

  return (
    <div style={{ marginBottom: "15px" }}>
      <input
        type="text"
        placeholder="Enter folder path (e.g., D:\\test)"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        size="50"
      />
      <button onClick={handleScan}>Scan</button>
    </div>
  );
}
