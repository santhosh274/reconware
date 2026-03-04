export interface Finding {
  line?: number;
  code?: string;
  description: string;
  severity: number;
}

export interface ScannedFile {
  // Old format fields (for backward compatibility)
  filename: string;
  full_path: string;
  entropy: number;
  prediction: number; // 0 or 1
  blocked: boolean;
  
  // New format fields (for enhanced display)
  ml_prediction?: "Ransomware" | "Benign";
  ml_confidence?: number;
  risk_score?: number;
  risk_level?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEARED" | "UNKNOWN";
  file_type?: string;
  analysis_type?: string;
  content_risk_score?: number;
  findings?: Finding[];
}
