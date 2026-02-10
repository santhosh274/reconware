import { motion } from "framer-motion";
import type { ScannedFile } from "../types/scan";

export default function RiskChart({ files }: { files: ScannedFile[] }) {
  const avg =
    files.length === 0
      ? 0
      : files.reduce((a, b) => a + b.score, 0) / files.length;

  const percentage = avg * 100;
  const severity =
    percentage >= 80 ? "high" : percentage >= 50 ? "medium" : "low";

  const ringColor =
    severity === "high"
      ? "from-red-500 via-rose-500 to-orange-500"
      : severity === "medium"
        ? "from-orange-500 via-amber-400 to-yellow-300"
        : "from-emerald-500 via-teal-400 to-cyan-300";

  const glowColor =
    severity === "high"
      ? "rgba(239, 68, 68, 0.2)"
      : severity === "medium"
        ? "rgba(249, 115, 22, 0.2)"
        : "rgba(16, 185, 129, 0.2)";

  return (
    <div className="relative flex items-center justify-center p-12">
      {/* Outer Rotating Ring */}
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 rounded-full border border-dashed border-white/5"
      />

      {/* Main Orb Container */}
      <div className="relative h-64 w-64 md:h-72 md:w-72 flex items-center justify-center">
        {/* Ambient Glow */}
        <motion.div
          animate={{ scale: [1, 1.1, 1], opacity: [0.3, 0.5, 0.3] }}
          transition={{ duration: 4, repeat: Infinity }}
          style={{ backgroundColor: glowColor }}
          className="absolute inset-0 rounded-full blur-[60px]"
        />

        {/* The Spherical Orb */}
        <div className="relative h-full w-full rounded-full bg-gradient-to-br from-white/10 via-black/40 to-black/80 border border-white/10 shadow-[0_0_50px_rgba(0,0,0,0.8)] backdrop-blur-3xl overflow-hidden flex items-center justify-center">
          {/* Internal Pulse Ring */}
          <motion.div
            className={`absolute inset-[15%] rounded-full bg-gradient-to-tr ${ringColor} opacity-40`}
            style={{
              maskImage: "radial-gradient(circle at center, transparent 55%, black 60%)",
              WebkitMaskImage: "radial-gradient(circle at center, transparent 55%, black 60%)",
            }}
          />

          {/* Dynamic Scan Sweep */}
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
            className="absolute inset-0 bg-[conic-gradient(from_0deg,rgba(255,255,255,0.2),transparent_60%)] mix-blend-screen"
          />

          {/* Data Center */}
          <div className="relative z-10 flex flex-col items-center gap-1">
            <span className="text-[10px] font-mono uppercase tracking-[0.4em] text-zinc-500">
              Risk Index
            </span>
            <motion.div
              key={percentage}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-5xl font-bold tracking-tighter text-white"
            >
              {percentage.toFixed(1)}<span className="text-xl text-white/40 ml-1">%</span>
            </motion.div>
            <span className={`text-[9px] font-mono px-3 py-1 rounded-full border border-white/10 uppercase tracking-[0.2em] bg-white/5 ${severity === "high" ? "text-red-400" : severity === "medium" ? "text-orange-400" : "text-emerald-400"
              }`}>
              {severity === "high" ? "CRITICAL" : severity === "medium" ? "ELEVATED" : "OPTIMAL"}
            </span>
          </div>

          {/* Bottom Label Overlay */}
          <div className="absolute bottom-6 w-full text-center px-8">
            <p className="text-[9px] font-mono text-zinc-500 uppercase tracking-[0.2em] leading-relaxed">
              Neural Heuristic <br /> Vector Analysis
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
