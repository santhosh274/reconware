import axios from "axios";
import { QuarantinedFile } from "../types/scan";

const API = "http://localhost:8000";

export const startScan = () =>
  axios.post(`${API}/scan`);

export const scanFolder = async (path: string) => {
  console.log("[Frontend] Starting scan of:", path);
  try {
    const response = await axios.post(`${API}/scan?path=${encodeURIComponent(path)}`);
    console.log("[Frontend] Scan response:", response.data);
    return response;
  } catch (error) {
    console.error("[Frontend] Scan error:", error);
    throw error;
  }
};

export async function fetchQuarantinedFiles(): Promise<QuarantinedFile[]> {
  try {
    const response = await axios.get(`${API}/quarantine`);
    const data = response.data;
    return data.files || [];
  } catch (error) {
    console.error("[Frontend] Error fetching quarantined files:", error);
    return [];
  }
}

export async function restoreFromQuarantine(quarantineName: string, destination: string): Promise<void> {
  try {
    await axios.post(
      `${API}/quarantine/restore?quarantine_name=${encodeURIComponent(quarantineName)}&destination=${encodeURIComponent(destination)}`
    );
  } catch (error) {
    console.error("[Frontend] Restore error:", error);
    throw error;
  }
}

export async function deleteFromQuarantine(quarantineName: string): Promise<void> {
  try {
    await axios.delete(`${API}/quarantine/${encodeURIComponent(quarantineName)}`);
  } catch (error) {
    console.error("[Frontend] Delete error:", error);
    throw error;
  }
}

export async function quarantineFile(filePath: string): Promise<void> {
  try {
    await axios.post(`${API}/block`, { file_path: filePath });
  } catch (error) {
    console.error("[Frontend] Quarantine error:", error);
    throw error;
  }
}

export async function getThreatIntel(): Promise<any> {
  try {
    const response = await axios.get(`${API}/threat-intel`);
    return response.data;
  } catch (error) {
    console.error("[Frontend] Threat Intel error:", error);
    throw error;
  }
}

export async function getReports(): Promise<any> {
  try {
    const response = await axios.get(`${API}/reports`);
    return response.data;
  } catch (error) {
    console.error("[Frontend] Reports error:", error);
    throw error;
  }
}

export const fetchResults = async () => {
  console.log("[Frontend] Fetching scan results...");
  try {
    const res = await axios.get(`${API}/results`);
    const raw = res.data;
    const files = Array.isArray(raw?.files) ? raw.files : [];
    return {
      timestamp: raw?.timestamp ?? null,
      files: files,
    };
  } catch (error) {
    console.error("[Frontend] Fetch results error:", error);
    return { timestamp: null, files: [] };
  }
};
