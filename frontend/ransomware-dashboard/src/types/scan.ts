import { z } from "zod";

export const ScannedFileSchema = z.object({
    path: z.string(),
    entropy: z.number(),
    score: z.number(),
    prediction: z.enum(["benign", "ransomware"]),
    blocked: z.boolean(),
});

export const ScanResultSchema = z.object({
    timestamp: z.string().nullable(),
    files: z.array(ScannedFileSchema),
});
