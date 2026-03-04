export interface ScanFile {
  filename: string;
  entropy: number;
  score: number;
  label: string;
}

export interface ScanResult {
  timestamp: string | null;
  files: ScanFile[];
}

export interface QuarantinedFile {
  id: string;
  original_path: string;
  quarantine_path: string;
  filename: string;
  size: number;
  threat_name: string;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  quarantine_date: string;
  hash?: string;
  status: "quarantined" | "restored" | "deleted";
}