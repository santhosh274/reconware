import type { ScannedFile } from "./ScannedFile";

export interface ScanResult {
  timestamp: string | null;
  files: ScannedFile[];
}
