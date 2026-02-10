export interface ScannedFile {
  path: string;
  entropy: number;
  score: number;
  prediction: "benign" | "ransomware";
  blocked: boolean;
}
