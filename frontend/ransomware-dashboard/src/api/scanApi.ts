import axios from "axios";

const API = "http://localhost:8000";

export const startScan = () =>
  axios.post(`${API}/scan`);

export const scanFolder = async (path: string) =>
  axios.post(`http://localhost:8000/scan?path=${encodeURIComponent(path)}`);


export const fetchResults = async () => {
  const res = await axios.get(`${API}/results`);

  // Normalize backend shape into ScannedFile-based ScanResult
  const raw = res.data;
  const files = Array.isArray(raw?.files) ? raw.files : [];
  const normalizedFiles = files.map((f: any) => {
    const isRansomware =
      String(f.prediction).toLowerCase() === "ransomware" ||
      (typeof f.filename === "string" &&
        (f.filename.toLowerCase().endsWith(".rec") ||
          f.filename.toLowerCase().endsWith(".enc")));

    const entropy = typeof f.entropy === "number" ? f.entropy : 0;

    // Simple score: scale entropy to [0,1] and boost suspicious files
    let score = Math.min(1, entropy / 8);
    if (isRansomware) {
      score = Math.max(score, 0.8);
    }

    return {
      path: f.full_path ?? f.path ?? "",
      entropy,
      score,
      prediction: isRansomware ? "ransomware" : "benign",
      blocked: Boolean(f.blocked),
    };
  });

  const normalized = {
    timestamp: raw?.timestamp ?? null,
    files: normalizedFiles,
  };

  return normalized;
};
