import { useEffect, useState } from "react";
import { fetchResults } from "../api/scanApi";
import { ScanResult } from "../types/scan";
import { ShieldAlert, Activity, RefreshCw, Zap, Cpu, Terminal } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import ScanControls from "../components/ScanControls";
import ScanTables from "../components/ScanTables";
import RiskChart from "../components/RiskChart";
import StatusBadge from "../components/StatusBadge";

export default function Dashboard() {
  const [data, setData] = useState<ScanResult>({
    timestamp: null,
    files: [],
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetchResults();
        setData(res);
        setError(null);
      } catch (err) {
        setError("Neural link severed. Retrying connection...");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 font-sans selection:bg-orange-500/30 overflow-x-hidden">
      {/* Cinematic Background Elements */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute top-[-10%] right-[-5%] w-[80%] h-[70%] bg-orange-600/10 blur-[150px] rounded-full rotate-12 opacity-50" />
        <div className="absolute bottom-[10%] left-[-5%] w-[50%] h-[50%] bg-rose-600/5 blur-[120px] rounded-full opacity-30" />
        <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-[0.03] brightness-50 contrast-150" />
        <div className="scanline" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6 pb-24">

        {/* Navigation / Header */}
        <header className="flex items-center justify-between py-10">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex items-center gap-4"
          >
            <div className="h-12 w-12 flex items-center justify-center rounded-2xl bg-orange-500/10 ring-1 ring-orange-500/30 shadow-[0_0_20px_rgba(249,115,22,0.1)] backdrop-blur-md">
              <ShieldAlert className="w-6 h-6 text-orange-500" />
            </div>
            <div>
              <h1 className="text-2xl font-serif text-white tracking-tight leading-none mb-1">Security Sentinel</h1>
              <div className="flex items-center gap-2">
                <span className="h-1 w-1 rounded-full bg-orange-500/50" />
                <p className="text-[9px] font-mono text-white/30 uppercase tracking-[0.3em]">Neural Interface v2.4.0</p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="flex items-center gap-6"
          >
            <div className="hidden lg:flex items-center gap-6 mr-4">
              <div className="flex flex-col items-end">
                <span className="text-[9px] font-mono text-white/20 uppercase tracking-widest">System Load</span>
                <span className="text-xs font-mono text-emerald-500/80 italic">Optimized</span>
              </div>
              <div className="h-8 w-px bg-white/5" />
            </div>
            <StatusBadge filesCount={data.files.length} />
          </motion.div>
        </header>

        {/* Main Workspace */}
        <main className="pt-8 md:pt-16">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-16 items-center">

            {/* Left: Tactical Overview */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="lg:col-span-7 space-y-10"
            >
              <div className="space-y-6">
                <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-orange-500/5 border border-orange-500/10">
                  <Cpu className="w-3 h-3 text-orange-400" />
                  <span className="text-[9px] font-bold text-orange-200/60 uppercase tracking-[0.3em]">Protocol Alpha Active</span>
                </div>

                <h2 className="text-6xl md:text-7xl lg:text-8xl text-zinc-100 font-serif leading-[0.9] tracking-tighter">
                  Proactive <br />
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-orange-400 via-rose-400 to-orange-500">Threat Shield</span>
                </h2>

                <p className="text-white/40 text-lg max-w-xl font-sans leading-relaxed">
                  Advanced entropy analytics and heuristic pattern matching deployed
                  at the edge. Monitor ransomware vectors in real-time with zero-latency
                  inference.
                </p>
              </div>

              <ScanControls />
            </motion.div>

            {/* Right: Risk Analysis Visualization */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2, type: "spring", stiffness: 50 }}
              className="lg:col-span-5 flex justify-center lg:justify-end"
            >
              <RiskChart files={data.files} />
            </motion.div>
          </div>

          {/* Threat Ledger Section */}
          <div className="mt-40 space-y-10">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="flex items-center justify-between border-b border-white/5 pb-6"
            >
              <div className="flex items-center gap-4">
                <div className="p-2 rounded-lg bg-white/5 border border-white/5">
                  <Terminal className="w-4 h-4 text-orange-500" />
                </div>
                <div>
                  <h3 className="text-xs font-mono text-white/50 uppercase tracking-[0.4em]">Anomaly Ledger</h3>
                  <p className="text-[9px] font-mono text-white/20 uppercase tracking-widest mt-1">Real-time vector tracking</p>
                </div>
              </div>

              <div className="flex items-center gap-6 text-[10px] font-mono uppercase">
                {error && (
                  <motion.span
                    animate={{ opacity: [0.5, 1, 0.5] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="text-rose-500 font-bold"
                  >
                    {error}
                  </motion.span>
                )}
                <div className="flex items-center gap-3 bg-white/5 px-4 py-2 rounded-xl border border-white/5">
                  <RefreshCw className="w-3 h-3 text-zinc-600" />
                  <span className="text-zinc-500 tracking-widest">
                    Last Sync: {data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : "PENDING"}
                  </span>
                </div>
              </div>
            </motion.div>

            <AnimatePresence mode="wait">
              {loading ? (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="h-80 flex flex-col items-center justify-center glass-card rounded-3xl border-dashed border-white/10"
                >
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    className="w-10 h-10 border-2 border-orange-500/20 border-t-orange-500 rounded-full mb-6"
                  />
                  <span className="text-[10px] font-mono text-white/20 uppercase tracking-[0.5em]">Syncing Neural Net...</span>
                </motion.div>
              ) : (
                <ScanTables files={data.files} />
              )}
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}