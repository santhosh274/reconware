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
