import { z } from "zod";

export const FindingSchema = z.object({
    line: z.number().optional(),
    code: z.string().optional(),
    description: z.string(),
    severity: z.number()
});

export const ScannedFileSchema = z.object({
    filename: z.string(),
    full_path: z.string(),
    entropy: z.number(),
    prediction: z.number(), // 0 or 1
    blocked: z.boolean(),
    risk_score: z.number().optional(),
    risk_level: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEARED", "UNKNOWN"]).optional(),
    findings: z.array(FindingSchema).optional()
});

export const QuarantinedFileSchema = z.object({
    filename: z.string(),
    original_path: z.string(),
    quarantine_path: z.string(),
    threat_name: z.string().optional(),
    quarantine_date: z.string(),
    restored: z.boolean().optional()
});

export const ScanResultSchema = z.object({
    timestamp: z.string().nullable(),
    files: z.array(ScannedFileSchema),
});

// Infer types
export type Finding = z.infer<typeof FindingSchema>;
export type ScannedFile = z.infer<typeof ScannedFileSchema>;
export type QuarantinedFile = z.infer<typeof QuarantinedFileSchema>;
export type ScanResult = z.infer<typeof ScanResultSchema>;