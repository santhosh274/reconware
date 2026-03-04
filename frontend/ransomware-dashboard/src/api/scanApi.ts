import axios from "axios";

const API = "http://localhost:8000";

export const startScan = () =>
  axios.post(`${API}/scan`);

export const scanFolder = async (path: string) => {
  console.log("[Frontend] Starting scan of:", path);
  try {
    const response = await axios.post(`http://localhost:8000/scan?path=${encodeURIComponent(path)}`);
    console.log("[Frontend] Scan response:", response.data);
    return response;
  } catch (error) {
    console.error("[Frontend] Scan error:", error);
    throw error;
  }
};

export async function fetchQuarantinedFiles(): Promise<QuarantinedFile[]> {
  const response = await fetch('/api/quarantine');
  if (!response.ok) throw new Error('Failed to fetch quarantined files');
  return response.json();
}

export async function restoreFromQuarantine(fileId: string): Promise<void> {
  const response = await fetch(`/api/quarantine/${fileId}/restore`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('Failed to restore file');
}

export async function deleteFromQuarantine(fileId: string): Promise<void> {
  const response = await fetch(`/api/quarantine/${fileId}`, {
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Failed to delete file');
}

export const fetchResults = async () => {
  console.log("[Frontend] Fetching scan results...");
  const res = await axios.get(`${API}/results`);

  console.log("[Frontend] Raw API response:", res.data);

  // Return the raw response - let components handle the new fields
  const raw = res.data;
  const files = Array.isArray(raw?.files) ? raw.files : [];
  
  console.log(`[Frontend] Processing ${files.length} files`);
  
  // Log critical/high risk files
  const criticalFiles = files.filter((f: any) => f.risk_level === 'CRITICAL');
  const highFiles = files.filter((f: any) => f.risk_level === 'HIGH');
  console.log(`[Frontend] CRITICAL: ${criticalFiles.length}, HIGH: ${highFiles.length}`);
  
  for (const file of criticalFiles) {
    console.log(`[Frontend] CRITICAL FILE: ${file.filename} - Risk Score: ${file.risk_score}%`);
    if (file.findings?.length > 0) {
      console.log(`[Frontend]   Findings: ${file.findings[0].description}`);
    }
  }

  const normalized = {
    timestamp: raw?.timestamp ?? null,
    files: files,  // Pass through the raw files with all new fields
  };

  console.log("[Frontend] Normalized result:", normalized);
  return normalized;
};
