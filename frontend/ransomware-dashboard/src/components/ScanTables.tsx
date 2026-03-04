import React from "react";
import type { ScannedFile } from "../types/scan";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, ShieldAlert, Cpu, Hash, BarChart3 } from "lucide-react";

interface ScanTableProps {
  files: ScannedFile[];
}

const ScanTable: React.FC<ScanTableProps> = ({ files }) => {
  if (!files || files.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card rounded-3xl p-20 text-center border-dashed border-white/10"
      >
        <div className="flex flex-col items-center gap-4">
          <ShieldCheck className="w-12 h-12 text-zinc-700" />
          <p className="text-zinc-500 font-mono text-xs tracking-[0.3em] uppercase">
            No Active Threats in Local Sector
          </p>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-3xl border border-white/5 overflow-hidden"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-white/[0.02] border-b border-white/5">
              <th className="px-8 py-5 text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-500 font-medium">Source Path</th>
              <th className="px-8 py-5 text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-500 font-medium">
                <div className="flex items-center gap-2"><Hash className="w-3 h-3" /> Entropy</div>
              </th>
              <th className="px-8 py-5 text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-500 font-medium">
                <div className="flex items-center gap-2"><BarChart3 className="w-3 h-3" /> Heuristic Confidence</div>
              </th>
              <th className="px-8 py-5 text-[10px] font-mono uppercase tracking-[0.2em] text-zinc-500 font-medium text-right">Protection Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.02]">
            <AnimatePresence>
              {files.map((file, index) => (
                <motion.tr
                  layout
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  key={file.full_path}
                  className="group hover:bg-white/[0.02] transition-colors"
                >
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-4">
                      <div className={`p-2 rounded-lg ${file.prediction === 0 ? 'bg-red-500/10' : 'bg-emerald-500/10'}`}>
                        {file.prediction === 0 ? (
                          <ShieldAlert className="w-4 h-4 text-red-500" />
                        ) : (
                          <ShieldCheck className="w-4 h-4 text-emerald-500" />
                        )}
                      </div>
                      <div className="flex flex-col min-w-0">
                        <span className="text-sm font-medium text-zinc-200 group-hover:text-white truncate">
                          {file.full_path.split(/[\\/]/).pop()}
                        </span>
                        <span className="text-[9px] font-mono text-zinc-600 uppercase tracking-tight truncate max-w-[300px]">
                          {file.full_path}
                        </span>
                      </div>
                    </div>
                  </td>

                  <td className="px-8 py-5">
                    <span className="font-mono text-xs text-zinc-400 tabular-nums">
                      {file.entropy.toFixed(4)}
                    </span>
                  </td>

                  <td className="px-4 py-3">
    {file.risk_score !== undefined ? (
        <>
            <div className="flex items-center gap-2">
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    file.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                    file.risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                    file.risk_level === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                    file.risk_level === 'LOW' ? 'bg-blue-500/20 text-blue-400' :
                    'bg-green-500/20 text-green-400'
                }`}>
                    {file.risk_level || 'UNKNOWN'} ({file.risk_score}%)
                </span>
            </div>
            {file.findings && file.findings.length > 0 && (
                <div className="mt-1 text-xs text-gray-400">
                    {file.findings[0].description}
                </div>
            )}
        </>
    ) : (
        // Fallback to old scoring
        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
            file.prediction === 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
        }`}>
            {file.prediction === 0 ? 'MALICIOUS' : 'BENIGN'}
        </span>
    )}
</td>

                  <td className="px-8 py-5 text-right">
                    <div className="flex items-center justify-end gap-3">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${file.blocked
                          ? "bg-red-500/10 border-red-500/20 text-red-400"
                          : "bg-zinc-800 border-white/5 text-zinc-500"
                        }`}>
                        {file.blocked ? "QUARANTINED" : "CLEARED"}
                      </span>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
      </div>
    </motion.div>
  );
};

export default ScanTable;